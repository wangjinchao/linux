/* SPDX-License-Identifier: GPL-2.0 */
/*
 * StackWatch Guard Test Module
 * Creates intentional stack corruption for testing stackwatch detection
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/delay.h>

// call hwbp_addr_test for a direct test
// #include "stackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("StackWatch Guard Test Cases");
MODULE_LICENSE("GPL");

static struct proc_dir_entry *test_proc;


/* Test function 1: Simple buffer overflow */
static noinline void vulnerable_strcpy(const char *input)
{
	char buffer[32]; /* Small buffer to trigger overflow */

	pr_info("StackWatch Test: %s called with input: %s\n", __func__, input);

	// hwbp_addr_test();

	/* This will overflow if input > 32 chars */
	strcpy(buffer, input);

	pr_info("StackWatch Test: strcpy completed, buffer contains: %.32s\n", buffer);
}

/* Test function 2: Controlled overflow */
static noinline void controlled_overflow(int overflow_size)
{
	char buffer[64];
	char *overflow_ptr;

	pr_info("StackWatch Test: %s with overflow size %d\n", __func__, overflow_size);

	memset(buffer, 'A', sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';

	if (overflow_size > 0) {
		/* Intentionally write past buffer end */
		overflow_ptr = buffer + sizeof(buffer);
		memset(overflow_ptr, 'X', overflow_size);
		pr_info("StackWatch Test: Wrote %d bytes past buffer end\n",
			overflow_size);
	}

	pr_info("StackWatch Test: Function ending normally\n");
}

/* Test function 3: Recursive with overflow */
static noinline void recursive_vulnerable(int depth, int corrupt_at_depth)
{
	char buffer[48];

	pr_info("StackWatch Test: %s depth=%d, corrupt_at=%d\n", __func__, depth,
		corrupt_at_depth);

	memset(buffer, 'R', sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';

	if (depth == corrupt_at_depth) {
		/* Corrupt stack at specific depth */
		char *overflow = buffer + sizeof(buffer);
		*overflow = 'C'; /* Corrupt one byte past buffer */
		pr_info("StackWatch Test: Corrupted stack at depth %d\n", depth);
	}

	if (depth > 0)
		recursive_vulnerable(depth - 1, corrupt_at_depth);

	pr_info("StackWatch Test: Returning from depth %d\n", depth);
}

/* Test function 4: No corruption (control test) */
static noinline void safe_function(const char *input)
{
	char buffer[128]; /* Large enough buffer */

	pr_info("StackWatch Test: %s called\n", __func__);

	strncpy(buffer, input, sizeof(buffer) - 1);
	buffer[sizeof(buffer) - 1] = '\0';

	pr_info("StackWatch Test: %s completed normally\n", __func__);
}

/* Proc interface for triggering tests */
static ssize_t test_proc_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *pos)
{
	char cmd[256];
	char test_data[128];
	int test_num, param;

	if (count >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buffer, count))
		return -EFAULT;

	cmd[count] = '\0';

	/* Remove trailing newline */
	if (count > 0 && cmd[count - 1] == '\n')
		cmd[count - 1] = '\0';

	pr_info("StackWatch Test: Received command: %s\n", cmd);

	if (sscanf(cmd, "test%d %d", &test_num, &param) >= 1) {
		switch (test_num) {
		case 1:
			/* Test 1: Buffer overflow with long string */
			memset(test_data, 'A', sizeof(test_data));
			test_data[param > 0 ? min(param,
						  (int)sizeof(test_data) - 1) :
					      50] = '\0';
			pr_info("StackWatch Test: Starting test 1 - vulnerable_strcpy\n");
			vulnerable_strcpy(test_data);
			break;

		case 2:
			/* Test 2: Controlled overflow */
			pr_info("StackWatch Test: Starting test 2 - controlled_overflow\n");
			controlled_overflow(param > 0 ? param : 8);
			break;

		case 3:
			/* Test 3: Recursive corruption */
			pr_info("StackWatch Test: Starting test 3 - recursive_vulnerable\n");
			recursive_vulnerable(param > 0 ? param : 3, 1);
			break;

		case 4:
			/* Test 4: Safe function (no corruption) */
			pr_info("StackWatch Test: Starting test 4 - safe_function\n");
			strcpy(test_data, "Safe test string");
			safe_function(test_data);
			break;

		default:
			pr_err("StackWatch Test: Unknown test number %d\n",
			       test_num);
			return -EINVAL;
		}
	} else {
		pr_err("StackWatch Test: Invalid command format\n");
		pr_info("StackWatch Test: Usage: echo 'test[1-4] [param]' > /proc/stackwatch_test\n");
		return -EINVAL;
	}

	return count;
}

static ssize_t test_proc_read(struct file *file, char __user *buffer,
			      size_t count, loff_t *pos)
{
	static const char usage[] =
		"StackWatch Guard Test Module\n"
		"Commands:\n"
		"  test1 [size] - Buffer overflow test (default size=50)\n"
		"  test2 [size] - Controlled overflow (default size=8)\n"
		"  test3 [depth] - Recursive corruption (default depth=3)\n"
		"  test4	   - Safe function test (no corruption)\n"
		"\n"
		"Usage: echo 'test1 60' > /proc/stackwatch_test\n"
		"\n"
		"Make sure to setup stackwatch_guard first:\n"
		"  echo 'vulnerable_strcpy' > /proc/stackwatch_guard\n"
		"  echo 'controlled_overflow' > /proc/stackwatch_guard\n"
		"  echo 'recursive_vulnerable' > /proc/stackwatch_guard\n";

	if (*pos > 0)
		return 0;

	if (count < strlen(usage))
		return -EINVAL;

	if (copy_to_user(buffer, usage, strlen(usage)))
		return -EFAULT;

	*pos = strlen(usage);
	return strlen(usage);
}

static const struct proc_ops test_proc_ops = {
	.proc_read = test_proc_read,
	.proc_write = test_proc_write,
};

static int __init stackwatch_test_init(void)
{
	test_proc = proc_create("stackwatch_test", 0644, NULL, &test_proc_ops);
	if (!test_proc) {
		pr_err("StackWatch Test: Failed to create proc entry\n");
		return -ENOMEM;
	}

	pr_info("StackWatch Test: Module loaded\n");
	pr_info("StackWatch Test: Usage - cat /proc/stackwatch_test for instructions\n");

	return 0;
}

static void __exit stackwatch_test_exit(void)
{
	if (test_proc)
		remove_proc_entry("stackwatch_test", NULL);

	pr_info("StackWatch Test: Module unloaded\n");
}

module_init(stackwatch_test_init);
module_exit(stackwatch_test_exit);
