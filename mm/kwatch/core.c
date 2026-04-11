// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kwatch.h"

static atomic_t dbgfs_config_busy = ATOMIC_INIT(0);
static struct kwatch_config *kwatch_config;
static struct dentry *dbgfs_config;
static struct dentry *dbgfs_dir;
static bool watching_active;

static int kwatch_start_watching(void)
{
	int ret;

	/*
	 * Watch init will preallocate the HWBP,
	 * so it must happen before stack init
	 */
	ret = kwatch_hwbp_prealloc();
	if (ret) {
		pr_err("kwatch_hwbp_prealloc ret: %d\n", ret);
		return ret;
	}

	ret = kwatch_probe_start();
	if (ret) {
		pr_err("kwatch_probe_start ret: %d\n", ret);
		kwatch_hwbp_free();
		return ret;
	}

	watching_active = true;
	return 0;
}

static void kwatch_stop_watching(void)
{
	kwatch_probe_stop();
	kwatch_hwbp_free();
	watching_active = false;
}

static void kwatch_cfg_free(struct kwatch_config *cfg)
{
	if (!cfg)
		return;

	kfree(cfg->func_name);
	kfree(cfg);
}

static int kwatch_config_parse_kv(struct kwatch_config *cfg, const char *key,
				  const char *val)
{
	int ret = 0;

	if (!strcmp(key, "func_name")) {
		kfree(cfg->func_name);
		cfg->func_name = kstrdup(val, GFP_KERNEL);
		if (!cfg->func_name)
			return -ENOMEM;
	} else if (!strcmp(key, "func_offset")) {
		ret = kstrtou16(val, 0, &cfg->func_offset);
	} else if (!strcmp(key, "mode")) {
		if (!strcmp(val, "stack")) {
			cfg->mode_type = KWATCH_MODE_STACK;
			cfg->mode_ops = kwatch_mode_lookup(KWATCH_MODE_STACK);
			cfg->mode_config = cfg->mode_ops->mode_config_alloc();
		}
	} else if (cfg->mode_ops && cfg->mode_ops->mode_config_parse) {
		ret = cfg->mode_ops->mode_config_parse(cfg, key, val);
	} else {
		pr_err("KWatch: Unknown parameter '%s'\n", key);
		ret = -EINVAL;
	}

	return ret;
}

static int kwatch_config_parse(char *buf, struct kwatch_config *cfg)
{
	char *token, *key, *val;
	int ret = 0;

	/* * Boundary Safety: Reset global config state.
	 * kwatch_stop_watching() halts execution, but we must clear old
	 * parameters and free old plugin memory before accepting new ones.
	 */
	kfree(cfg->func_name);
	cfg->func_name = NULL;
	cfg->func_offset = 0;

	if (cfg->mode_ops && cfg->mode_ops->mode_config_free)
		cfg->mode_ops->mode_config_free(cfg->mode_config);
	cfg->mode_ops = NULL;

	/* Tokenize and route */
	while ((token = strsep(&buf, " \t\n")) != NULL) {
		if (!*token)
			continue;

		key = strsep(&token, "=");
		val = token;

		if (!key || !val) {
			pr_err("KWatch: Malformed key=value pair\n");
			return -EINVAL;
		}

		ret = kwatch_config_parse_kv(cfg, key, val);
		if (ret)
			return ret;
	}

	/* Two-Phase Commit: Validation Phase */
	if (!cfg->func_name) {
		pr_err("KWatch: Missing required target function (fn=)\n");
		return -EINVAL;
	}

	if (!cfg->mode_ops) {
		pr_err("KWatch: No execution mode specified (mode=)\n");
		return -EINVAL;
	}

	if (cfg->mode_ops->mode_config_validate) {
		ret = cfg->mode_ops->mode_config_validate(cfg);
		if (ret) {
			pr_err("KWatch: Plugin validation failed: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static int kwatch_dbgfs_open(struct inode *inode, struct file *file)
{
	if (atomic_cmpxchg(&dbgfs_config_busy, 0, 1))
		return -EBUSY;
	return 0;
}

static int kwatch_dbgfs_release(struct inode *inode, struct file *file)
{
	atomic_set(&dbgfs_config_busy, 0);
	return 0;
}

static ssize_t kwatch_dbgfs_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	char out_buf[512];
	size_t len = 0;

	if (watching_active) {
		/* Print Global Plane Parameters */
		len += snprintf(out_buf + len, sizeof(out_buf) - len,
				"func_name=%s\n"
				"func_offset=%u\n"
				"depth=%u\n"
				"sp_offset=%u\n"
				"max_watch=%u\n"
				"access_type=%d\n",
				kwatch_config->func_name ?: "(none)",
				kwatch_config->func_offset,
				kwatch_config->depth,
				kwatch_config->sp_offset,
				kwatch_config->max_watch,
				kwatch_config->mode_type);

		/* Delegate to Plugin Plane to print mode_config variables */
		if (kwatch_config->mode_ops && kwatch_config->mode_ops->mode_config_show) {
			len += kwatch_config->mode_ops->mode_config_show(kwatch_config,
								    out_buf + len,
								    sizeof(out_buf) - len);
		}
	} else {
		len = snprintf(out_buf, sizeof(out_buf), "not watching\n");
	}

	return simple_read_from_buffer(user_buf, count, ppos, out_buf, len);
}

static ssize_t kwatch_dbgfs_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *ppos)
{
	char input[MAX_CONFIG_STR_LEN];
	int ret;

	if (count == 0 || count >= sizeof(input))
		return -EINVAL;

	if (copy_from_user(input, buffer, count))
		return -EFAULT;

	if (watching_active)
		kwatch_stop_watching();

	input[count] = '\0';
	strim(input);

	if (!strlen(input)) {
		pr_info("config cleared\n");
		return count;
	}

	ret = kwatch_config_parse(input, kwatch_config);
	if (ret) {
		pr_err("Failed to parse config %d\n", ret);
		return ret;
	}

	ret = kwatch_start_watching();
	if (ret) {
		pr_err("Failed to start watching with %d\n", ret);
		return ret;
	}

	return count;
}

static const struct file_operations kwatch_fops = {
	.owner = THIS_MODULE,
	.open = kwatch_dbgfs_open,
	.release = kwatch_dbgfs_release,
	.read = kwatch_dbgfs_read,
	.write = kwatch_dbgfs_write,
	.llseek = default_llseek,
};

static int __init kwatch_init(void)
{
	int ret = 0;

	kwatch_config = kzalloc_obj(*kwatch_config);
	if (!kwatch_config) {
		ret = -ENOMEM;
		goto err_alloc;
	}

	dbgfs_dir = debugfs_create_dir("kwatch", NULL);
	if (!dbgfs_dir) {
		ret = -ENOMEM;
		goto err_dir;
	}

	dbgfs_config = debugfs_create_file("config", 0600, dbgfs_dir, NULL,
					   &kwatch_fops);
	if (!dbgfs_config) {
		ret = -ENOMEM;
		goto err_file;
	}

	pr_info("module loaded\n");
	return 0;

err_file:
	debugfs_remove_recursive(dbgfs_dir);
	dbgfs_dir = NULL;
err_dir:
	kfree(kwatch_config);
	kwatch_config = NULL;
err_alloc:
	return ret;
}

static void __exit kwatch_exit(void)
{
	debugfs_remove_recursive(dbgfs_dir);
	if (kwatch_config)
		kwatch_cfg_free(kwatch_config);
	pr_info("module unloaded\n");
}

const struct kwatch_config *kwatch_get_config(void)
{
	return kwatch_config;
}

module_init(kwatch_init);
module_exit(kwatch_exit);

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel watchpoint");
MODULE_LICENSE("GPL");
