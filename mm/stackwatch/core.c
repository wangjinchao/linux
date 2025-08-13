#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "stackwatch.h"

MODULE_AUTHOR("Wang Jinchao");
MODULE_DESCRIPTION("Stack Corruption Debugger");
MODULE_LICENSE("GPL");

/* Global state */
char target_function[MAX_FUNC_NAME_LEN] = "";
unsigned long long offset;
bool monitoring_active;

/* Module parameters */
bool panic_on_corruption;
module_param(panic_on_corruption, bool, 0644);
MODULE_PARM_DESC(panic_on_corruption,
		 "Trigger kernel panic when corruption detected");

/* Proc interface for configuration */
static ssize_t stackwatch_proc_write(struct file *file,
				     const char __user *buffer, size_t count,
				     loff_t *pos)
{
	char func_offset_str[MAX_FUNC_NAME_LEN + 10];
	char *offset_str;
	int ret;

	if (count == 0 || count >= sizeof(func_offset_str))
		return -EINVAL;

	if (copy_from_user(func_offset_str, buffer, count))
		return -EFAULT;

	func_offset_str[count] = '\0';

	/* Remove trailing newline and any spaces */
	strim(func_offset_str);

	/* Stop current monitoring */
	if (monitoring_active)
		stop_monitoring();

	/* Check for a valid string to monitor */
	if (strlen(func_offset_str) == 0)
		return count;

	/* Parse the input string for "func_name+offset" */
	offset_str = strchr(func_offset_str, '+');
	if (offset_str) {
		// Found an offset. Separate the strings and parse.
		*offset_str = '\0';
		offset_str++;

		// Use kstrtoull to automatically handle hex (0x) and decimal
		ret = kstrtoull(offset_str, 0, &offset);
		if (ret) {
			pr_err("StackWatch: Invalid offset format.\n");
			return -EINVAL;
		}
	} else {
		pr_err("StackWatch: Offset must be supplied.");
		return -EINVAL;
	}

	strncpy(target_function, func_offset_str, MAX_FUNC_NAME_LEN - 1);
	target_function[MAX_FUNC_NAME_LEN - 1] = '\0';

	ret = start_monitoring(target_function, offset);
	if (ret < 0) {
		pr_err("StackWatch: Failed to monitor %s\n", target_function);
		return ret;
	}
	pr_info("StackWatch: Now monitoring %s+0x%llx\n", target_function,
		offset);

	return count;
}

static ssize_t stackwatch_proc_read(struct file *file, char __user *buffer,
				    size_t count, loff_t *pos)
{
	char output[256];
	int len;

	if (*pos > 0)
		return 0;

	if (monitoring_active) {
		len = snprintf(output, sizeof(output),
			       "Monitoring: %s+0x%llx\n", target_function,
			       offset);
	} else {
		len = snprintf(output, sizeof(output),
			       "Not monitoring\n"
			       "Usage: echo 'function_name+offset' > /proc/stackwatch\n");
	}

	if (count < len)
		return -EINVAL;

	if (copy_to_user(buffer, output, len))
		return -EFAULT;

	*pos = len;
	return len;
}

static const struct proc_ops stackwatch_proc_ops = {
	.proc_read = stackwatch_proc_read,
	.proc_write = stackwatch_proc_write,
};

static int __init stackwatch_init(void)
{
	int ret;

	/* Initialize HWBP subsystem */
	ret = hwbp_init();
	if (ret) {
		pr_err("StackWatch: Failed to initialize HWBP\n");
		return ret;
	}

	/* Create proc interface */
	if (!proc_create("stackwatch", 0644, NULL, &stackwatch_proc_ops)) {
		hwbp_cleanup();
		return -ENOMEM;
	}
	pr_info("StackWatch loaded - Phase 1\n");
	pr_info("Usage: echo 'function_name+offset' > /proc/stackwatch\n");

	return 0;
}

static void __exit stackwatch_exit(void)
{
	/* Cleanup active monitoring */
	if (monitoring_active)
		stop_monitoring();

	/* Remove proc interface */
	remove_proc_entry("stackwatch", NULL);

	/* Cleanup HWBP subsystem */
	hwbp_cleanup();

	pr_info("StackWatch unloaded\n");
}

int start_monitoring(const char *func_name, unsigned long long offset)
{
	int ret;

	ret = setup_probes(target_function, offset);
	if (ret)
		return ret;

	monitoring_active = true;
	return 0;
}

void stop_monitoring(void)
{
	cleanup_probes();
	hwbp_disarm_all();
	monitoring_active = false;
	target_function[0] = '\0';
}

module_init(stackwatch_init);
module_exit(stackwatch_exit);
