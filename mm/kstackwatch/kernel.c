#include "linux/kern_levels.h"
#include "linux/kstrtox.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel Stack Watch");
MODULE_LICENSE("GPL");

/* Global state */
struct ksw_config global_config;
bool watching_active;

/* Module parameters */
bool panic_on_catch;
module_param(panic_on_catch, bool, 0644);
MODULE_PARM_DESC(panic_on_catch,
		 "Trigger a kernel panic immediately on corruption catch");

void ksw_show_config(const char *lvl)
{
	struct ksw_config *config = &global_config;
	printk("%sKSW: watch config %s\n", lvl, config->config_str);
}

static int start_watching(struct ksw_config *config)
{
	int ret;

	if (strlen(config->function) == 0) {
		pr_err("KSW: No target function specified\n");
		return -EINVAL;
	}

	/*
	 * watch init will prealloc HWBP
	 * so it must be before stack init
	 */
	ret = ksw_watch_init();
	if (ret) {
		pr_err("KSW: ksw_watch_init ret: %d\n", ret);
		return ret;
	}

	ret = ksw_stack_init(config);
	if (ret) {
		pr_err("KSW: ksw_stack_init ret: %d\n", ret);
		ksw_watch_exit();
		return ret;
	}
	watching_active = true;

	pr_info("KSW: start watching:\n");
	ksw_show_config(KERN_INFO);

	return 0;
}

static void stop_watching(struct ksw_config *config)
{
	ksw_stack_exit();
	ksw_watch_exit();
	watching_active = false;

	pr_info("KSW: stop watching:\n");
	ksw_show_config(KERN_INFO);
}

/* Parse watch configuration: 
*    function+ip_offset[+depth] [local_var_offset:local_var_len]
*/
static int parse_config(char *buf, struct ksw_config *config)
{
	char *func_part, *stack_part = NULL;
	char *token;

	/* Initialize with default values */
	memset(config, 0, sizeof(*config));
	config->type = WATCH_CANARY;

	/* strim() removes leading/trailing whitespace */
	func_part = strim(buf);
	strscpy(config->config_str, func_part, MAX_CONFIG_STR_LEN);

	stack_part = strchr(func_part, ' ');
	if (stack_part) {
		*stack_part = '\0'; // Terminate the function part
		stack_part = strim(stack_part + 1);
	}

	/* 1. Parse the function part: function+ip_offset[+depth] */
	token = strsep(&func_part, "+");
	if (!token)
		return -EINVAL;

	strncpy(config->function, token, MAX_FUNC_NAME_LEN - 1);

	token = strsep(&func_part, "+");
	if (!token || kstrtou16(token, 0, &config->ip_offset)) {
		pr_err("KSW: Failed to parse instruction offset\n");
		return -EINVAL;
	}

	token = strsep(&func_part, "+");
	if (token && kstrtou16(token, 0, &config->depth)) {
		pr_err("KSW: Failed to parse depth\n");
		return -EINVAL;
	}
	if (!stack_part || !(*stack_part))
		return 0;

	/* 2. Parse the optional stack part: offset:len */
	config->type = WATCH_LOCAL_VAR;
	token = strsep(&stack_part, ":");
	if (!token || kstrtou16(token, 0, &config->local_var_offset)) {
		pr_err("KSW: Failed to parse stack variable offset\n");
		return -EINVAL;
	}

	if (!stack_part || kstrtou16(stack_part, 0, &config->local_var_len)) {
		pr_err("KSW: Failed to parse stack variable length\n");
		return -EINVAL;
	}

	return 0;
}

/* Proc interface for configuration */
static ssize_t kstackwatch_proc_write(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *pos)
{
	char input[256];
	int ret;
	struct ksw_config *config = &global_config;

	if (count == 0 || count >= sizeof(input))
		return -EINVAL;

	if (copy_from_user(input, buffer, count))
		return -EFAULT;

	input[count] = '\0';
	strim(input);

	/* Stop current watching */
	if (watching_active)
		stop_watching(config);

	ret = parse_config(input, config);
	if (ret)
		return ret;

	/* Start watching */
	ret = start_watching(config);
	if (ret < 0) {
		pr_err("KSW: Failed to start watching with %d\n", ret);
		return ret;
	}

	return count;
}

static int kstackwatch_proc_show(struct seq_file *m, void *v)
{
	struct ksw_config *config = &global_config;

	if (watching_active) {
		seq_printf(m, "KSW: watch config %s\n", config->config_str);
	} else {
		seq_printf(m, "Not watching\n");
		seq_printf(m, "\nUsage:\n");
		seq_printf(
			m,
			"  echo 'function+ip_offset[+depth] [local_var_offset:local_var_len]' > /proc/kstackwatch\n");
		seq_printf(m, "  if ignore the stack part, watch the canary");
	}

	return 0;
}

static int kstackwatch_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, kstackwatch_proc_show, NULL);
}

static const struct proc_ops kstackwatch_proc_ops = {
	.proc_open = kstackwatch_proc_open,
	.proc_read = seq_read,
	.proc_write = kstackwatch_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int is_ksw_supported(void)
{
	static const char *supported_archs[] = { "x86_64", NULL };

	const char *current_arch = utsname()->machine;
	int i;

	for (i = 0; supported_archs[i] != NULL; i++) {
		if (strcmp(current_arch, supported_archs[i]) == 0) {
			pr_info("KSW: Architecture %s supports hardware breakpoints\n",
				current_arch);
			return 1;
		}
	}

	pr_warn("KSW: Architecture %s may not support hardware breakpoints\n",
		current_arch);
	return 1; /* Allow for testing */
}

static int __init kstackwatch_init(void)
{
	if (!is_ksw_supported()) {
		return -EOPNOTSUPP;
	}

	/* Create proc interface */
	if (!proc_create("kstackwatch", 0644, NULL, &kstackwatch_proc_ops)) {
		return -ENOMEM;
	}

	pr_info("KSW: Module loaded\n");
	pr_info("KSW: Usage:\n");
	pr_info("KSW: echo 'function+ip_offset[+depth] [local_var_offset:local_var_len]' > /proc/kstackwatch\n");

	return 0;
}

static void __exit kstackwatch_exit(void)
{
	struct ksw_config *config = &global_config;

	/* Cleanup active watching */
	if (watching_active)
		stop_watching(config);

	/* Remove proc interface */
	remove_proc_entry("kstackwatch", NULL);

	pr_info("KSW: Module unloaded\n");
}

module_init(kstackwatch_init);
module_exit(kstackwatch_exit);
