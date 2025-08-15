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
MODULE_DESCRIPTION("Stack Corruption Debugger with Offset Support");
MODULE_LICENSE("GPL");

/* Global state */
struct kstackwatch_config global_config;
bool watching_active;

/* Module parameters */
bool panic_on_corruption;
module_param(panic_on_corruption, bool, 0644);
MODULE_PARM_DESC(panic_on_corruption,
		 "Trigger kernel panic when corruption detected");

void show_config(void)
{
	struct kstackwatch_config *config = &global_config;
	pr_info("KStackWatch: watch config %s+0x%llx %s\n", config->function,
		config->instruction_offset, config->type_str);
}

static int start_watching(struct kstackwatch_config *config)
{
	int ret;

	if (strlen(config->function) == 0) {
		pr_err("KStackWatch: No target function specified\n");
		return -EINVAL;
	}

	/* Initialize HWBP  */
	ret = hwbp_init();
	if (ret) {
		pr_err("KStackWatch: Failed to initialize HWBP : %d\n", ret);
		return ret;
	}

	ret = setup_probes(config);
	if (ret) {
		pr_err("KStackWatch: Failed to setup probes: %d\n", ret);
		hwbp_cleanup();
		return ret;
	}
	watching_active = true;

	pr_info("KStackWatch: start watching:\n");
	show_config();

	return 0;
}

static void stop_watching(struct kstackwatch_config *config)
{
	cleanup_probes();
	hwbp_cleanup();
	watching_active = false;

	pr_info("KStackWatch: stop watching:\n");
	show_config();
}

/* Parse watch configuration: 
	function+instruction_off stack_offset:stack_size 
*/
static int parse_config(char *line, struct kstackwatch_config *config)
{
	char *func_name = NULL;
	char *instruct_offset_str = NULL;
	char *type_str = NULL;
	char *colon_pos;
	s64 stack_offset;
	int stack_size;
	int ret;

	/* Clear configuration */
	memset(config, 0, sizeof(*config));

	/* Split by space */
	type_str = line;
	func_name = strsep(&type_str, " ");

	if (!func_name || strlen(func_name) == 0) {
		pr_err("KStackWatch: Function name required\n");
		ret = -EINVAL;
	}

	/* Parse function+offset */
	instruct_offset_str = strchr(func_name, '+');
	if (!instruct_offset_str) {
		pr_err("KStackWatch: Invalid offset format\n");
		ret = -EINVAL;
	}

	*instruct_offset_str = '\0';
	instruct_offset_str++;
	ret = kstrtoull(instruct_offset_str, 0, &config->instruction_offset);
	if (ret) {
		pr_err("KStackWatch: Invalid offset format\n");
		ret = -EINVAL;
	}

	strncpy(config->function, func_name, MAX_FUNC_NAME_LEN - 1);
	config->function[MAX_FUNC_NAME_LEN - 1] = '\0';

	/* Default to canary watch */
	if (!type_str || strlen(type_str) == 0 ||
	    strcmp(type_str, "canary") == 0) {
		config->type = WATCH_CANARY;
		strncpy(config->type_str, "canary", MAX_TYPE_STR_LEN);
		return 0;
	}

	/* Check for offset:len format */
	colon_pos = strchr(type_str, ':');
	if (!colon_pos) {
		pr_err("KStackWatch: Invalid watch format, use 'canary' or 'offset:len'\n");
		return -EINVAL;
	}

	*colon_pos = '\0';
	ret = kstrtos64(type_str, 0, &stack_offset);
	if (ret) {
		pr_err("KStackWatch: Invalid offset format\n");
		return ret;
	}

	ret = kstrtoint(colon_pos + 1, 0, &stack_size);
	if (ret) {
		pr_err("KStackWatch: Invalid len format\n");
		return ret;
	}

	/* Validate len */
	if (stack_size != 1 && stack_size != 2 && stack_size != 4 &&
	    stack_size != 8) {
		pr_err("KStackWatch: Invalid len %d, must be 1,2,4,8\n",
		       stack_size);
		return -EINVAL;
	}

	config->type = WATCH_STACK_OFFSET;
	config->stack_var.offset = stack_offset;
	config->stack_var.len = stack_size;

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
		seq_printf(m, "KStackWatch: watch config %s+0x%llx %s\n",
			   config->function, config->instruction_offset,
			   config->type_str);
	} else {
		seq_printf(m, "Not watching\n");
		seq_printf(m, "\nUsage:\n");
		seq_printf(
			m,
			"  echo 'function_name+instruction_offset type_str' > /proc/kstackwatch\n");
		seq_printf(m, "\n type_str:\n");
		seq_printf(m, "  canary    - Watch stack canary\n");
		seq_printf(
			m,
			"  stack_offset:stack_size  - Watch stack variable by offset and len (1,2,4,8)\n");
		seq_printf(m, "\nExamples:\n");
		seq_printf(
			m,
			"  echo 'vulnerable_func+0x20 canary' > /proc/kstackwatch\n");
		seq_printf(
			m,
			"  echo 'test_func+0x32 -64:8,canary' > /proc/kstackwatch\n");
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
	pr_info("KStackWatch: Usage: echo 'function+offset stack_offset:stack_size' > /proc/kstackwatch\n");

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