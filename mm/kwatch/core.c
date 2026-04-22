// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/kallsyms.h>
#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "kwatch.h"

static atomic_t dbgfs_config_busy = ATOMIC_INIT(0);
static DEFINE_MUTEX(kwatch_dbgfs_mutex);
static struct kwatch_config kwatch_config;
static struct dentry *dbgfs_config;
static struct dentry *dbgfs_dir;
static bool watching_active;

static int kwatch_start_watching(void)
{
	unsigned long addr, size;
	int ret;

	/* 1. Resolve the entry point address */
	addr = kallsyms_lookup_name(kwatch_config.func_name);
	if (!addr)
		return -ENOENT;

	/* * 2. Retrieve symbol size.
	 * Modern kallsyms APIs allow passing NULL for the offset pointer
	 * if the caller only requires the symbol size.
	 */
	if (!kallsyms_lookup_size_offset(addr, &size, NULL))
		return -ENOENT;

	ret = kwatch_hwbp_prealloc(kwatch_config.max_watch,
				   addr,
				   addr + size);
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
	watching_active = false;
	kwatch_probe_stop();
	synchronize_rcu();
	kwatch_hwbp_free();
}

static int parse_deref_chain(struct kwatch_config *cfg, char *val)
{
	char *p = val;
	char *base_str = p;
	char *offset_str = NULL;
	bool has_arrow = false;

	/* 1. Find the boundary of the base string */
	while (*p) {
		if (*p == ':') {
			*p = '\0';
			offset_str = p + 1;
			break;
		} else if (!strncmp(p, "->", 2)) {
			*p = '\0';
			offset_str = p + 2;
			has_arrow = true;
			break;
		}
		p++;
	}

	/* 2. Parse the Base Anchor (Unified Logic) */
	if (!strcmp(base_str, "stack")) {
		cfg->base = KWATCH_BASE_STACK;
	} else if (!strncmp(base_str, "arg", 3) && strlen(base_str) == 4) {
		int arg_num;

		if (kstrtoint(base_str + 3, 10, &arg_num) || arg_num < 1 ||
		    arg_num > 6)
			return -EINVAL;
		cfg->base = KWATCH_BASE_ARG1 + (arg_num - 1);
	} else {
		/* Fallback: Treat as a global symbol */
		cfg->base = KWATCH_BASE_GLOBAL_SYM;

		strscpy(cfg->sym_name, base_str, sizeof(cfg->sym_name));

		cfg->sym_addr = kallsyms_lookup_name(base_str);
		if (!cfg->sym_addr) {
			pr_err("KWatch: Base anchor '%s' is not stack, argN, or a valid symbol\n",
			       base_str);
			return -EINVAL;
		}
	}

	/* 3. Parse the bound :offset (handling implicit 0) */
	if (has_arrow) {
		/* Syntax: base->... (implicitly includes :0) */
		cfg->offsets[cfg->offset_count++] = 0;
		p = offset_str;
	} else if (offset_str) {
		/* Syntax: base:offset... */
		p = offset_str;
		char *next_arrow = strstr(p, "->");

		if (next_arrow)
			*next_arrow = '\0';

		if (*p == '\0')
			cfg->offsets[cfg->offset_count++] = 0;
		else if (kstrtol(p, 0, &cfg->offsets[cfg->offset_count++]))
			return -EINVAL;

		p = next_arrow ? next_arrow + 2 : NULL;
	} else {
		/* Syntax: base (no offsets, no dereferences) */
		cfg->offsets[cfg->offset_count++] = 0;
		return 0;
	}

	/* 4. Parse all subsequent ->offset dereferences */
	while (p) {
		char *next_arrow = strstr(p, "->");

		if (cfg->offset_count >= MAX_DEREF_CHAIN)
			return -E2BIG;

		if (next_arrow)
			*next_arrow = '\0';

		if (*p == '\0')
			cfg->offsets[cfg->offset_count++] = 0;
		else if (kstrtol(p, 0, &cfg->offsets[cfg->offset_count++]))
			return -EINVAL;

		p = next_arrow ? next_arrow + 2 : NULL;
	}

	return 0;
}

static int kwatch_config_parse(char *buf, struct kwatch_config *cfg)
{
	char *token, *key, *val;
	int ret = 0;

	memset(cfg, 0, sizeof(*cfg));

	while ((token = strsep(&buf, " \t\n")) != NULL) {
		if (!*token)
			continue;
		key = strsep(&token, "=");
		val = token;
		if (!key || !val)
			return -EINVAL;

		if (!strcmp(key, "func_name"))
			strscpy(cfg->func_name, val, sizeof(cfg->func_name));
		else if (!strcmp(key, "func_offset"))
			ret = kstrtou16(val, 0, &cfg->func_offset);
		else if (!strcmp(key, "depth"))
			ret = kstrtou16(val, 0, &cfg->depth);
		else if (!strcmp(key, "watch_len"))
			ret = kstrtou16(val, 0, &cfg->watch_len);
		else if (!strcmp(key, "target"))
			ret = parse_deref_chain(cfg, val);

		if (ret)
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
	int i;
	const char *base_str;
	static const char *const arg_strs[] = { "arg1", "arg2", "arg3",
						"arg4", "arg5", "arg6" };

	out_buf = kzalloc(MAX_CONFIG_STR_LEN, GFP_KERNEL);
	if (!out_buf)
		return -ENOMEM;

	if (watching_active) {
		/* 1. Resolve Base Anchor String */
		if (kwatch_config.base == KWATCH_BASE_STACK)
			base_str = "stack";
		else if (kwatch_config.base >= KWATCH_BASE_ARG1 &&
			 kwatch_config.base <= KWATCH_BASE_ARG6)
			base_str =
				arg_strs[kwatch_config.base - KWATCH_BASE_ARG1];
		else if (kwatch_config.base == KWATCH_BASE_GLOBAL_SYM)
			base_str =
				kwatch_config.sym_name; /* NEW: Use saved name */
		else
			base_str = "unknown";

		/* 2. Print Core Configuration */
		len += scnprintf(out_buf + len, MAX_CONFIG_STR_LEN - len,
				 "func_name=%s\n"
				 "func_offset=%u\n"
				 "depth=%u\n"
				 "max_watch=%u\n"
				 "access_type=%d\n"
				 "watch_len=%u\n",
				 kwatch_config.func_name,
				 kwatch_config.func_offset, kwatch_config.depth,
				 kwatch_config.max_watch,
				 kwatch_config.access_type,
				 kwatch_config.watch_len);

		/* NEW: Print the resolved address only if it is a global symbol */
		if (kwatch_config.base == KWATCH_BASE_GLOBAL_SYM) {
			len += scnprintf(out_buf + len,
					 MAX_CONFIG_STR_LEN - len,
					 "sym_name=%s\n",
					 kwatch_config.sym_name);
		}

		/* 3. Reconstruct the Unified Dereference Chain */
		len += scnprintf(out_buf + len, MAX_CONFIG_STR_LEN - len,
				 "target=%s", base_str);

		for (i = 0; i < kwatch_config.offset_count; i++) {
			if (i == 0)
				len += scnprintf(out_buf + len,
						 MAX_CONFIG_STR_LEN - len,
						 ":%ld",
						 kwatch_config.offsets[i]);
			else
				len += scnprintf(out_buf + len,
						 MAX_CONFIG_STR_LEN - len,
						 "->%ld",
						 kwatch_config.offsets[i]);
		}
		len += scnprintf(out_buf + len, MAX_CONFIG_STR_LEN - len, "\n");

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

	/* VFS Boundary Lock: Serialize concurrent configuration writes */
	mutex_lock(&kwatch_dbgfs_mutex);

	if (watching_active)
		kwatch_stop_watching();

	parse_str = strim(input_alloc);

	if (!strlen(parse_str)) {
		ret = -EINVAL; /* Corrected from EINVAL */
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
	mutex_unlock(&kwatch_dbgfs_mutex);
	kfree(input_alloc);
	return ret;
}

static const struct file_operations kwatch_fops = {
	.owner = THIS_MODULE,
	.open = kwatch_dbgfs_open,
	.release = kwatch_dbgfs_release,
	.read = kwatch_dbgfs_read,
	.write = kwatch_dbgfs_write,
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
