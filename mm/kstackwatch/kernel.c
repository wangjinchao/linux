// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel Stack Watch");
MODULE_LICENSE("GPL");

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

	pr_info("start watching: %s\n", ksw_config->config_str);
	return 0;
}

static void ksw_stop_watching(void)
{
	ksw_stack_exit();
	ksw_watch_exit();
	watching_active = false;

	pr_info("stop watching: %s\n", ksw_config->config_str);
}

/*
 * Format of the configuration string:
 *    function+ip_offset[+depth] [local_var_offset:local_var_len]
 *
 * - function         : name of the target function
 * - ip_offset        : instruction pointer offset within the function
 * - depth            : recursion depth to watch
 * - local_var_offset : offset from the stack pointer at function+ip_offset
 * - local_var_len    : length of the local variable(1,2,4,8)
 */
static int ksw_parse_config(char *buf, struct ksw_config *config)
{
	char *func_part, *local_var_part = NULL;
	char *token;
	u16 local_var_len;

	memset(ksw_config, 0, sizeof(*ksw_config));

	/* set the watch type to the default canary-based watching */
	config->type = WATCH_CANARY;

	func_part = strim(buf);
	strscpy(config->config_str, func_part, MAX_CONFIG_STR_LEN);

	local_var_part = strchr(func_part, ' ');
	if (local_var_part) {
		*local_var_part = '\0'; // terminate the function part
		local_var_part = strim(local_var_part + 1);
	}

	/* parse the function part: function+ip_offset[+depth] */
	token = strsep(&func_part, "+");
	if (!token)
		goto fail;

	strscpy(config->function, token, MAX_FUNC_NAME_LEN - 1);

	token = strsep(&func_part, "+");
	if (!token || kstrtou16(token, 0, &config->ip_offset)) {
		pr_err("failed to parse instruction offset\n");
		goto fail;
	}

	token = strsep(&func_part, "+");
	if (token && kstrtou16(token, 0, &config->depth)) {
		pr_err("failed to parse depth\n");
		goto fail;
	}
	if (!local_var_part || !(*local_var_part))
		return 0;

	/* parse the optional local var offset:len */
	config->type = WATCH_LOCAL_VAR;
	token = strsep(&local_var_part, ":");
	if (!token || kstrtou16(token, 0, &config->local_var_offset)) {
		pr_err("failed to parse local var offset\n");
		goto fail;
	}

	if (!local_var_part || kstrtou16(local_var_part, 0, &local_var_len)) {
		pr_err("failed to parse local var len\n");
		goto fail;
	}

	if (local_var_len != 1 && local_var_len != 2 &&
	    local_var_len != 4 && local_var_len != 8) {
		pr_err("invalid local var len %u (must be 1,2,4,8)\n",
		       local_var_len);
		goto fail;
	}
	config->local_var_len = local_var_len;

	return 0;
fail:
	pr_err("invalid input: %s\n", config->config_str);
	config->config_str[0] = '\0';
	return -EINVAL;
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
		seq_printf(m, "%s\n", ksw_config->config_str);
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
	kfree(ksw_config);

	pr_info("module unloaded\n");
}

module_init(kstackwatch_init);
module_exit(kstackwatch_exit);
