#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/utsname.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
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

static int start_monitoring(const char *func_name, unsigned long long offset)
{
	int ret;

	/* Initialize HWBP subsystem */
	ret = hwbp_init();
	if (ret) {
		pr_err("StackWatch: Failed to initialize HWBP subsystem: %d\n", ret);
		return ret;
	}
	ret = setup_probes(target_function, offset);
	if (ret) {
		pr_err("StackWatch: Failed to setup probes: %d\n", ret);
		return ret;
	}

	monitoring_active = true;
	return 0;
}

static void stop_monitoring(void)
{
	cleanup_probes();
	hwbp_cleanup();
	monitoring_active = false;
	target_function[0] = '\0';
}

/* Proc interface for configuration */
static ssize_t kstackwatch_proc_write(struct file *file,
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
			pr_err("StackWatch: Invalid offset format\n");
			return -EINVAL;
		}
	} else {
		pr_err("StackWatch: Offset must be supplied\n");
		return -EINVAL;
	}

	strncpy(target_function, func_offset_str, MAX_FUNC_NAME_LEN - 1);
	target_function[MAX_FUNC_NAME_LEN - 1] = '\0';

	ret = start_monitoring(target_function, offset);
	if (ret < 0) {
		pr_err("StackWatch: Failed to monitor %s: %d\n",
		       target_function, ret);
		return ret;
	}
	pr_info("StackWatch: Now monitoring %s+0x%llx\n", target_function,
		offset);

	return count;
}

static ssize_t kstackwatch_proc_read(struct file *file, char __user *buffer,
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
			       "Usage: echo 'function_name+offset' > /proc/kstackwatch\n");
	}

	if (count < len)
		return -EINVAL;

	if (copy_to_user(buffer, output, len))
		return -EFAULT;

	*pos = len;
	return len;
}

static const struct proc_ops kstackwatch_proc_ops = {
	.proc_read = kstackwatch_proc_read,
	.proc_write = kstackwatch_proc_write,
};

static int is_hwbp_supported(void)
{
	const char *supported_archs[] = {
	    "x86_64",
	    // "i386",
	    // "aarch64",
	    // "armv7l",
	    // "ppc64le",
	    // "s390x",
	    NULL
	};

	const char *current_arch = utsname()->machine;
	int i;

	for (i = 0; supported_archs[i] != NULL; i++) {
		if (strcmp(current_arch, supported_archs[i]) == 0) {
			pr_info("StackWatch: Architecture %s supports hardware breakpoints\n",
				current_arch);
			return 1;
		}
	}

	pr_warn("StackWatch: Architecture %s does not support hardware breakpoints\n",
		current_arch);

	return 0;
}

static int __init kstackwatch_init(void)
{
	if (!is_hwbp_supported()) {
		return 0;
	}
	/* Create proc interface */
	if (!proc_create("kstackwatch", 0644, NULL, &kstackwatch_proc_ops)) {
		hwbp_cleanup();
		return -ENOMEM;
	}
	pr_info("StackWatch: Module loaded - Phase 1\n");
	pr_info("StackWatch: Usage: echo 'function_name+offset' > /proc/kstackwatch\n");

	return 0;
}

static void __exit kstackwatch_exit(void)
{
	/* Cleanup active monitoring */
	if (monitoring_active)
		stop_monitoring();

	/* Remove proc interface */
	remove_proc_entry("kstackwatch", NULL);

	/* Cleanup HWBP subsystem */
	hwbp_cleanup();

	pr_info("StackWatch: Module unloaded\n");
}

module_init(kstackwatch_init);
module_exit(kstackwatch_exit);
