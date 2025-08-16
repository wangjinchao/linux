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
struct kstackwatch_config global_config;
bool watching_active;

/* Module parameters */
bool panic_on_catch;
module_param(panic_on_catch, bool, 0644);
MODULE_PARM_DESC(panic_on_catch,
		 "Trigger kernel panic when corruption detected");

void ksw_show_config(void)
{
	struct kstackwatch_config *config = &global_config;
	printk("KStackWatch: watch config %s\n", config->config_str);
}

static int start_watching(struct kstackwatch_config *config)
{
	int ret;

	if (strlen(config->function) == 0) {
		pr_err("KStackWatch: No target function specified\n");
		return -EINVAL;
	}

	/* Initialize HWBP  */
	ret = ksw_watch_init();
	if (ret) {
		pr_err("KStackWatch: Failed to initialize HWBP : %d\n", ret);
		return ret;
	}

	ret = ksw_stack_init(config);
	if (ret) {
		pr_err("KStackWatch: Failed to setup probes: %d\n", ret);
		ksw_watch_exit();
		return ret;
	}
	watching_active = true;

	pr_info("KStackWatch: start watching:\n");
	ksw_show_config();

	return 0;
}

static void stop_watching(struct kstackwatch_config *config)
{
	ksw_stack_exit();
	ksw_watch_exit();
	watching_active = false;

	pr_info("KStackWatch: stop watching:\n");
	ksw_show_config();
}

/* Parse watch configuration: 
*    function+instruction_off[+depth] [local_var_offset:local_var_len]
*/
static int parse_config(char *buf, struct kstackwatch_config *config)
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

	/* 1. Parse the function part: function+instruction_offset[+depth] */
	token = strsep(&func_part, "+");
	if (!token)
		return -EINVAL;

	strncpy(config->function, token, MAX_FUNC_NAME_LEN - 1);

	token = strsep(&func_part, "+");
	if (!token || kstrtou16(token, 0, &config->instruction_offset)) {
		pr_err("KStackWatch: Failed to parse instruction offset\n");
		return -EINVAL;
	}

	token = strsep(&func_part, "+");
	if (token && kstrtou16(token, 0, &config->depth)) {
		pr_err("KStackWatch: Failed to parse depth\n");
		return -EINVAL;
	}
	if (!stack_part || !(*stack_part))
		return 0;

	/* 2. Parse the optional stack part: offset:len */
	config->type = WATCH_LOCAL_VAR;
	token = strsep(&stack_part, ":");
	if (!token || kstrtou16(token, 0, &config->local_var_offset)) {
		pr_err("KStackWatch: Failed to parse stack variable offset\n");
		return -EINVAL;
	}

	if (!stack_part || kstrtou16(stack_part, 0, &config->local_var_len)) {
		pr_err("KStackWatch: Failed to parse stack variable length\n");
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
	struct kstackwatch_config *config = &global_config;

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
		pr_err("KStackWatch: Failed to start watching with %d\n", ret);
		return ret;
	}

	return count;
}

static int kstackwatch_proc_show(struct seq_file *m, void *v)
{
	struct kstackwatch_config *config = &global_config;

	if (watching_active) {
		seq_printf(m, "KStackWatch: watch config %s\n",
			   config->config_str);
	} else {
		seq_printf(m, "Not watching\n");
		seq_printf(m, "\nUsage:\n");
		seq_printf(
			m,
			"  echo 'function+instruction_off[+depth] [local_var_offset:local_var_len]' > /proc/kstackwatch\n");
		seq_printf(
			m,
			"  if ignore the stack part, watch the canary");
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

static int is_hwbp_supported(void)
{
	static const char *supported_archs[] = { "x86_64", NULL };

	const char *current_arch = utsname()->machine;
	int i;

	for (i = 0; supported_archs[i] != NULL; i++) {
		if (strcmp(current_arch, supported_archs[i]) == 0) {
			pr_info("KStackWatch: Architecture %s supports hardware breakpoints\n",
				current_arch);
			return 1;
		}
	}

	pr_warn("KStackWatch: Architecture %s may not support hardware breakpoints\n",
		current_arch);
	return 1; /* Allow for testing */
}

static int __init kstackwatch_init(void)
{
	if (!is_hwbp_supported()) {
		return -EOPNOTSUPP;
	}

	/* Create proc interface */
	if (!proc_create("kstackwatch", 0644, NULL, &kstackwatch_proc_ops)) {
		return -ENOMEM;
	}

	pr_info("KStackWatch: Module loaded\n");
	pr_info("KStackWatch: Usage: echo 'function+instruction_off[+depth] [local_var_offset:local_var_len]' > /proc/kstackwatch\n");

	return 0;
}

static void __exit kstackwatch_exit(void)
{
	struct kstackwatch_config *config = &global_config;

	/* Cleanup active watching */
	if (watching_active)
		stop_watching(config);

	/* Remove proc interface */
	remove_proc_entry("kstackwatch", NULL);

	pr_info("KStackWatch: Module unloaded\n");
}

module_init(kstackwatch_init);
module_exit(kstackwatch_exit);