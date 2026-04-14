// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kwatch.h"
#include "mode/mode.h"

static atomic_t dbgfs_config_busy = ATOMIC_INIT(0);
static struct kwatch_config kwatch_config;
static struct dentry *dbgfs_config;
static struct dentry *dbgfs_dir;
static bool watching_active;

static int kwatch_start_watching(void)
{
	int ret;

	ret = kwatch_hwbp_prealloc(kwatch_config.max_watch);
	if (ret) {
		pr_err("kwatch_hwbp_prealloc ret: %d\n", ret);
		return ret;
	}

	ret = kwatch_probe_start(&kwatch_config);
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
	kwatch_mode_uninit();

	watching_active = false;
}

static int kwatch_config_parse_kv(struct kwatch_config *cfg, const char *key,
				  const char *val)
{
	int ret = 0;

	if (!strcmp(key, "func_name"))
		strscpy(kwatch_config.func_name, val);
	else if (!strcmp(key, "func_offset"))
		ret = kstrtou16(val, 0, &kwatch_config.func_offset);
	else if (!strcmp(key, "mode"))
		ret = kwatch_mode_init(val);
	else
		ret = kwatch_mode_config_parse(key, val);

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
	memset(cfg, 0, sizeof(*cfg));
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
	if (strlen(kwatch_config.func_name)) {
		pr_err("KWatch: Missing required target function (fn=)\n");
		return -EINVAL;
	}

	if (kwatch_mode_config_validate()) {
		pr_err("KWatch: Plugin validation failed: %d\n", ret);
		return ret;
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
	char *out_buf;
	size_t len = 0;
	ssize_t ret;

	out_buf = kzalloc(MAX_CONFIG_STR_LEN, GFP_KERNEL);
	if (!out_buf)
		return -ENOMEM;

	if (watching_active) {
		len += scnprintf(out_buf + len, MAX_CONFIG_STR_LEN - len,
				 "func_name=%s\n"
				 "func_offset=%u\n"
				 "depth=%u\n"
				 "max_watch=%u\n"
				 "access_type=%d\n",
				 kwatch_config.func_name,
				 kwatch_config.func_offset, kwatch_config.depth,
				 kwatch_config.max_watch,
				 kwatch_config.access_type);

		len += kwatch_mode_config_show(out_buf + len,
					       MAX_CONFIG_STR_LEN - len);
	} else {
		len = scnprintf(out_buf, MAX_CONFIG_STR_LEN, "not watching\n");
	}

	ret = simple_read_from_buffer(user_buf, count, ppos, out_buf, len);

	kfree(out_buf);
	return ret;
}

static ssize_t kwatch_dbgfs_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *ppos)
{
	char *input_alloc;
	char *parse_str;
	int ret;

	if (count == 0 || count >= MAX_CONFIG_STR_LEN)
		return -EINVAL;

	input_alloc = memdup_user_nul(buffer, count);
	if (IS_ERR(input_alloc))
		return PTR_ERR(input_alloc);

	if (watching_active)
		kwatch_stop_watching();

	parse_str = strim(input_alloc);

	if (!strlen(parse_str)) {
		ret = EINVAL;
		goto out;
	}

	ret = kwatch_config_parse(parse_str, &kwatch_config);
	if (ret) {
		pr_err("Failed to parse config %d\n", ret);
		goto out;
	}

	ret = kwatch_start_watching();
	if (ret) {
		pr_err("Failed to start watching with %d\n", ret);
		goto out;
	}

	ret = count;

out:
	kfree(input_alloc);
	return ret;
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

	memset(&kwatch_config, 0, sizeof(kwatch_config));

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
	return ret;
}

static void __exit kwatch_exit(void)
{
	kwatch_stop_watching();
	debugfs_remove_recursive(dbgfs_dir);
	pr_info("module unloaded\n");
}

module_init(kwatch_init);
module_exit(kwatch_exit);

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel watchpoint");
MODULE_LICENSE("GPL");
