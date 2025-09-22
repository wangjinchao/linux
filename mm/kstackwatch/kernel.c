// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kstackwatch.h"

static struct ksw_config *ksw_config;
static atomic_t config_file_busy = ATOMIC_INIT(0);

static bool watching_active;

static int ksw_start_watching(void)
{
	int ret;

	/*
	 * Watch init will preallocate the HWBP,
	 * so it must happen before stack init
	 */
	ret = ksw_watch_init();
	if (ret) {
		pr_err("ksw_watch_init ret: %d\n", ret);
		return ret;
	}

	ret = ksw_stack_init();
	if (ret) {
		pr_err("ksw_stack_init ret: %d\n", ret);
		ksw_watch_exit();
		return ret;
	}
	watching_active = true;

	pr_info("start watching: %s\n", ksw_config->user_input);
	return 0;
}

static void ksw_stop_watching(void)
{
	ksw_stack_exit();
	ksw_watch_exit();
	watching_active = false;

	pr_info("stop watching: %s\n", ksw_config->user_input);
}

struct param_map {
	const char *name;       /* long name */
	const char *short_name; /* short name (2 letters) */
	size_t offset;          /* offsetof(struct ksw_config, field) */
	bool is_string;         /* true for string */
};

/* macro generates both long and short name automatically */
#define PMAP(field, short, is_str) \
	{ #field, #short, offsetof(struct ksw_config, field), is_str }

static const struct param_map ksw_params[] = {
	PMAP(func_name,   fn, true),
	PMAP(func_offset, fo, false),
	PMAP(depth,       dp, false),
	PMAP(max_watch,   mw, false),
	PMAP(sp_offset,   so, false),
	PMAP(watch_len,   wl, false),
};

static int ksw_parse_param(struct ksw_config *config, const char *key,
			   const char *val)
{
	const struct param_map *pm = NULL;
	int ret;

	for (int i = 0; i < ARRAY_SIZE(ksw_params); i++) {
		if (strcmp(key, ksw_params[i].name) == 0 ||
		    strcmp(key, ksw_params[i].short_name) == 0) {
			pm = &ksw_params[i];
			break;
		}
	}

	if (!pm)
		return -EINVAL;

	if (pm->is_string) {
		char **dst = (char **)((char *)config + pm->offset);
		*dst = kstrdup(val, GFP_KERNEL);
		if (!*dst)
			return -ENOMEM;
	} else {
		ret = kstrtou16(val, 0, (u16 *)((char *)config + pm->offset));
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Configuration string format:
 *    param_name=<value> [param_name=<value> ...]
 *
 * Required parameters:
 * - func_name  |fn (str) : target function name
 * - func_offset|fo (u16) : instruction pointer offset
 *
 * Optional parameters:
 * - depth      |dp (u16) : recursion depth
 * - max_watch  |mw (u16) : maximum number of watchpoints
 * - sp_offset  |so (u16) : offset from stack pointer at func_offset
 * - watch_len  |wl (u16) : watch length (1,2,4,8)
 */
static int ksw_parse_config(char *buf, struct ksw_config *config)
{
	char *part, *key, *val;
	int ret;

	kfree(config->func_name);
	kfree(config->user_input);
	memset(ksw_config, 0, sizeof(*ksw_config));

	buf = strim(buf);
	config->user_input = kstrdup(buf, GFP_KERNEL);
	if (!config->user_input)
		return -ENOMEM;

	while ((part = strsep(&buf, " \t\n")) != NULL) {
		if (*part == '\0')
			continue;

		key = strsep(&part, "=");
		val = part;
		if (!key || !val)
			continue;
		ret = ksw_parse_param(config, key, val);
		if (ret)
			pr_warn("unsupported param %s=%s", key, val);
	}

	if (!config->func_name || !config->func_offset) {
		pr_err("Missing required parameters: function or func_offset\n");
		return -EINVAL;
	}

	return 0;
}

static ssize_t kstackwatch_proc_write(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *pos)
{
	char input[MAX_CONFIG_STR_LEN];
	int ret;

	if (count == 0 || count >= sizeof(input))
		return -EINVAL;

	if (copy_from_user(input, buffer, count))
		return -EFAULT;

	if (watching_active)
		ksw_stop_watching();

	input[count] = '\0';
	strim(input);

	if (!strlen(input)) {
		pr_info("config cleared\n");
		return count;
	}

	ret = ksw_parse_config(input, ksw_config);
	if (ret) {
		pr_err("Failed to parse config %d\n", ret);
		return ret;
	}

	ret = ksw_start_watching();
	if (ret) {
		pr_err("Failed to start watching with %d\n", ret);
		return ret;
	}

	return count;
}

static int kstackwatch_proc_show(struct seq_file *m, void *v)
{
	if (watching_active)
		seq_printf(m, "%s\n", ksw_config->user_input);
	else
		seq_puts(m, "not watching\n");

	return 0;
}

static int kstackwatch_proc_open(struct inode *inode, struct file *file)
{
	if (atomic_cmpxchg(&config_file_busy, 0, 1))
		return -EBUSY;

	return single_open(file, kstackwatch_proc_show, NULL);
}

static int kstackwatch_proc_release(struct inode *inode, struct file *file)
{
	atomic_set(&config_file_busy, 0);
	return single_release(inode, file);
}

static const struct proc_ops kstackwatch_proc_ops = {
	.proc_open = kstackwatch_proc_open,
	.proc_read = seq_read,
	.proc_write = kstackwatch_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = kstackwatch_proc_release,
};

const struct ksw_config *ksw_get_config(void)
{
	return ksw_config;
}
static int __init kstackwatch_init(void)
{
	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
	if (!ksw_config)
		return -ENOMEM;

	if (!proc_create("kstackwatch", 0600, NULL, &kstackwatch_proc_ops)) {
		pr_err("create proc kstackwatch fail");
		kfree(ksw_config);
		return -ENOMEM;
	}

	pr_info("module loaded\n");
	return 0;
}

static void __exit kstackwatch_exit(void)
{
	if (watching_active)
		ksw_stop_watching();

	remove_proc_entry("kstackwatch", NULL);
	kfree(ksw_config->func_name);
	kfree(ksw_config->user_input);
	kfree(ksw_config);

	pr_info("module unloaded\n");
}

module_init(kstackwatch_init);
module_exit(kstackwatch_exit);

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel Stack Watch");
MODULE_LICENSE("GPL");
