// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/prandom.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Simple KStackWatch Test Module");
MODULE_LICENSE("GPL");

static struct proc_dir_entry *test_proc;
#define BUFFER_SIZE 4
#define MAX_DEPTH 6

/* global variables for Silent corruption test */
static u64 *g_corrupt_ptr;

/*
 * Test Case 0: Write to the canary position directly (Canary Test)
 * use a u64 buffer array to ensure the canary will be placed
 * corrupt the stack canary using the debug function
 */
static void canary_test_write(void)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("starting %s\n", __func__);
	ksw_watch_show();
	ksw_watch_fire();

	buffer[0] = 0;

	/* make sure the compiler do not drop assign action */
	barrier_data(buffer);
	pr_info("canary write test completed\n");
}

/*
 * Test Case 1: Stack Overflow (Canary Test)
 * This function uses a u64 buffer 64-bit write
 * to corrupt the stack canary with a single operation
 */
static void canary_test_overflow(void)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("starting %s\n", __func__);
	pr_info("buffer 0x%lx\n", (unsigned long)buffer);

	/* intentionally overflow the u64 buffer. */
	((u64 *)buffer + BUFFER_SIZE)[0] = 0xdeadbeefdeadbeef;

	/* make sure the compiler do not drop assign action */
	barrier_data(buffer);

	pr_info("canary overflow test completed\n");
}

static void do_something(int min_ms, int max_ms)
{
	u32 rand;

	get_random_bytes(&rand, sizeof(rand));
	rand = min_ms + rand % (max_ms - min_ms + 1);
	msleep(rand);
}

static void silent_corruption_buggy(int i)
{
	u64 local_var;

	pr_info("starting %s\n", __func__);

	pr_info("%s %d local_var addr: 0x%lx\n", __func__, i,
		(unsigned long)&local_var);
	WRITE_ONCE(g_corrupt_ptr, &local_var);

	do_something(50, 150);
	//buggy: return without resetting g_corrupt_ptr
}

static void silent_corruption_victim(int i)
{
	u64 local_var;

	local_var = 0xdeadbeef;
	pr_info("starting %s %dth\n", __func__, i);
	pr_info("%s local_var addr: 0x%lx\n", __func__,
		(unsigned long)&local_var);

	do_something(50, 150);

	if (local_var != 0)
		pr_info("%s %d happy with 0x%llx\n", __func__, i, local_var);
	else
		pr_info("%s %d unhappy with 0x%llx\n", __func__, i, local_var);
}

static int silent_corruption_unwitting(void *data)
{
	u64 *local_ptr;

	pr_info("starting %s\n", __func__);

	do {
		local_ptr = READ_ONCE(g_corrupt_ptr);
		do_something(500, 1000);
	} while (!local_ptr);

	local_ptr[0] = 0;

	return 0;
}

/*
 * Test Case 2: Silent Corruption
 * buggy() does not protect its local var correctly
 * unwitting() simply does its intended work
 * victim() is unaware know what happened
 */
static void silent_corruption_test(void)
{
	struct task_struct *unwitting;

	pr_info("starting %s\n", __func__);
	WRITE_ONCE(g_corrupt_ptr, NULL);

	unwitting = kthread_run(silent_corruption_unwitting, NULL, "unwitting");
	if (IS_ERR(unwitting)) {
		pr_err("failed to create thread2\n");
		return;
	}

	silent_corruption_buggy(0);

	/*
	 * An iteration-based bug: The unwitting thread corrupts the victim's
	 * stack. In a twist of fate, the victim's subsequent repetitions ensure
	 * the corruption is contained, protecting the caller's stack.
	 */
	for (int i = 0; i < 20; i++)
		silent_corruption_victim(i);
}

/*
 * Test Case 3: Recursive Call Corruption
 * Test corruption detection at specified recursion depth
 */
static void recursive_corruption_test(int depth)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("recursive call at depth %d\n", depth);
	pr_info("buffer 0x%lx\n", (unsigned long)buffer);
	if (depth <= MAX_DEPTH)
		recursive_corruption_test(depth + 1);

	buffer[0] = depth;

	/* make sure the compiler do not drop assign action */
	barrier_data(buffer);

	pr_info("returning from depth %d\n", depth);
}

static ssize_t test_proc_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *pos)
{
	char cmd[256];
	int test_num;

	if (count >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buffer, count))
		return -EFAULT;

	cmd[count] = '\0';
	strim(cmd);

	pr_info("received command: %s\n", cmd);

	if (sscanf(cmd, "test%d", &test_num) == 1) {
		switch (test_num) {
		case 0:
			pr_info("triggering canary write test\n");
			canary_test_write();
			break;
		case 1:
			pr_info("triggering canary overflow test\n");
			canary_test_overflow();
			break;
		case 2:
			pr_info("triggering silent corruption test\n");
			silent_corruption_test();
			break;
		case 3:
			pr_info("triggering recursive corruption test\n");
			/* depth start with 0 */
			recursive_corruption_test(0);
			break;
		default:
			pr_err("Unknown test number %d\n", test_num);
			return -EINVAL;
		}
	} else {
		pr_err("invalid command format. Use 'test1', 'test2', or 'test3'.\n");
		return -EINVAL;
	}

	return count;
}

static ssize_t test_proc_read(struct file *file, char __user *buffer,
			      size_t count, loff_t *pos)
{
	static const char usage[] =
		"KStackWatch Simplified Test Module\n"
		"==================================\n"
		"Usage:\n"
		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n"
		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n"
		"  echo 'test2' > /proc/kstackwatch_test  - Silent corruption test\n"
		"  echo 'test3' > /proc/kstackwatch_test  - Recursive corruption test\n";

	return simple_read_from_buffer(buffer, count, pos, usage,
				       strlen(usage));
}

static const struct proc_ops test_proc_ops = {
	.proc_read = test_proc_read,
	.proc_write = test_proc_write,
};

static int __init kstackwatch_test_init(void)
{
	test_proc = proc_create("kstackwatch_test", 0600, NULL, &test_proc_ops);
	if (!test_proc) {
		pr_err("Failed to create proc entry\n");
		return -ENOMEM;
	}
	pr_info("module loaded\n");
	return 0;
}

static void __exit kstackwatch_test_exit(void)
{
	if (test_proc)
		remove_proc_entry("kstackwatch_test", NULL);
	pr_info("module unloaded\n");
}

module_init(kstackwatch_test_init);
module_exit(kstackwatch_test_exit);
