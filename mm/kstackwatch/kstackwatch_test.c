/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>

#include "kstackwatch.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Simplified KStackWatch Test Module ");

static struct proc_dir_entry *test_proc;
#define BUFFER_SIZE 4
#define MAX_DEPTH 4

/* Global variables for multi-thread test synchronization */
static volatile u64 *g_corrupt_ptr;
static struct completion g_wait_for_init;

/*
 * Test Case 0: Write to the canary position directly (Canary Test)
 * This function uses a u64 buffer
 * 64-bit write, corrupting the stack canary with a single operation.
 */
static void canary_test_write(void)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("KStackWatch Test: Starting canary_test_write with u64 write\n");
	ksw_watch_show();
	ksw_watch_fire();

	buffer[0] = 0;
	/* make sure the compiler do not drop assign action */
	barrier_data(buffer);
	pr_info("KStackWatch Test: Canary write test completed\n");
}

/*
 * Test Case 1: Stack Overflow (Canary Test)
 * This function uses a u64 buffer
 * 64-bit write, corrupting the stack canary with a single operation.
 */
static void canary_test_overflow(void)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("KStackWatch Test: Starting canary_test_overflow with u64 write\n");
	pr_info("KStackWatch Test: buffer 0x%px\n", buffer);

	/* Intentionally overflow the u64 buffer. */
	buffer[BUFFER_SIZE] = 0xdeadbeefdeadbeef;

	/* make sure the compiler do not drop assign action */
	barrier_data(buffer);

	pr_info("KStackWatch Test: Canary overflow test completed\n");
}

/*
 * Corrupts the variable on multi_thread_corruption_test's stack
 */
static int multi_thread_corruption_thread2(void *data)
{
	pr_info("KStackWatch Test: Starting multi_thread_corruption_thread2\n");

	wait_for_completion(&g_wait_for_init);

	pr_info("KStackWatch Test: Thread2  woke up. Corrupting variable at 0x%px\n",
		g_corrupt_ptr);
	if (g_corrupt_ptr) {
		*g_corrupt_ptr = 0xdeadbeefdeadbeef;
	}

	pr_info("KStackWatch Test: Thread2 finished corruption\n");

	return 0;
}

/*
 * Test Case 2: Multi-threaded Local Variable Corruption
 * multi_thread_corruption_test initializes a local variable
 * makes its address globally available,
 * and then sleeps. Thread B corrupts it.
 */
static void multi_thread_corruption_thread1(void)
{
	u64 local_var = 0x1234567887654321;

	pr_info("KStackWatch Test: Starting multi_thread_corruption_thread1\n");

	pr_info("KStackWatch Test: Thread1 local_var address: 0x%px, value: 0x%llx\n",
		&local_var, local_var);
	WRITE_ONCE(g_corrupt_ptr, &local_var);

	/* Signal Thread 2 that the pointer is ready, then sleep */
	complete(&g_wait_for_init);
	msleep(1000);

	pr_info("KStackWatch Test: Thread1 woke up. Final local_var value: 0x%llx\n",
		local_var);
}

static void multi_thread_corruption_test(void)
{
	struct task_struct *corrupt_thread;

	pr_info("KStackWatch Test: Starting multi_thread_corruption_test\n");

	/* Reset completion */
	init_completion(&g_wait_for_init);

	corrupt_thread = kthread_run(multi_thread_corruption_thread2, NULL,
				     "corruption_b");
	if (IS_ERR(corrupt_thread)) {
		pr_err("KStackWatch Test: Failed to create corruption thread\n");
		return;
	}
	multi_thread_corruption_thread1();
}

/*
 * Test Case 3: Recursive Call Corruption
 * This function calls itself recursively and corrupts the stack at a specific depth.
 * This tests whether KStackWatch can handle dynamic stack frames.
 */
static void recursive_corruption_test(int depth)
{
	u64 buffer[BUFFER_SIZE];


	pr_info("KStackWatch Test: Recursive call at depth %d\n", depth);
	pr_info("KStackWatch Test: buffer 0x%px\n", buffer);
	if (depth <= MAX_DEPTH)
		recursive_corruption_test(depth + 1);

	buffer[0] = depth;

	/* make sure the compiler do not drop assign action */
	barrier_data(buffer);

	pr_info("KStackWatch Test: Returning from depth %d\n", depth);
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

	pr_info("KStackWatch Test: Received command: %s\n", cmd);

	if (sscanf(cmd, "test%d", &test_num) == 1) {
		switch (test_num) {
		case 0:
			pr_info("KStackWatch Test: Triggering canary write test\n");
			canary_test_write();
			break;
		case 1:
			pr_info("KStackWatch Test: Triggering canary overflow test\n");
			canary_test_overflow();
			break;
		case 2:
			pr_info("KStackWatch Test: Triggering local variable corruption test\n");
			multi_thread_corruption_test();
			break;
		case 3:
			pr_info("KStackWatch Test: Triggering recursive corruption test\n");
			/* depth start with 0 */
			recursive_corruption_test(0);
			break;
		default:
			pr_err("KStackWatch Test: Unknown test number %d\n",
			       test_num);
			return -EINVAL;
		}
	} else {
		pr_err("KStackWatch Test: Invalid command format. Use 'test1', 'test2', or 'test3'.\n");
		return -EINVAL;
	}

	return count;
}

static ssize_t test_proc_read(struct file *file, char __user *buffer,
			      size_t count, loff_t *pos)
{
	static const char usage[] =
		"KStackWatch Simplified Test Module \n"
		"==================================\n"
		"Usage:\n"
		"  echo 'test0' > /proc/kstackwatch_test  - Canary test test\n"
		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n"
		"  echo 'test2' > /proc/kstackwatch_test  - Multi-threaded local variable corruption test\n"
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
	test_proc = proc_create("kstackwatch_test", 0644, NULL, &test_proc_ops);
	if (!test_proc) {
		pr_err("KStackWatch Test: Failed to create proc entry\n");
		return -ENOMEM;
	}
	pr_info("KStackWatch Test: Module loaded, use 'cat /proc/kstackwatch_test' for usage\n");
	return 0;
}

static void __exit kstackwatch_test_exit(void)
{
	if (test_proc)
		remove_proc_entry("kstackwatch_test", NULL);
	pr_info("KStackWatch Test: Module unloaded\n");
}

module_init(kstackwatch_test_init);
module_exit(kstackwatch_test_exit);
