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
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/random.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Simple KStackWatch Test Module");
MODULE_LICENSE("GPL");

static struct proc_dir_entry *test_proc;

#define BUFFER_SIZE 64
#define MAX_DEPTH 6
#define JUNK_SZ 256
#define VICTIM_BUF_SZ 128
#define NUM_WORKERS 4
#define NODE_BUF_SZ 32

/* global variables for original Silent corruption test (test3) */
static u64 *g_corrupt_ptr;

/*
 * Test Case 0: Write to the canary position directly (Canary Test)
 */
static void test_watch_fire(void)
{
	u64 buffer[BUFFER_SIZE] = { 0 };

	pr_info("entry of %s\n", __func__);
	ksw_watch_show();
	ksw_watch_fire();
	pr_info("buf[0]:%lld\n", buffer[0]);

	barrier_data(buffer);
	pr_info("exit of %s\n", __func__);
}

/*
 * Test Case 1: Stack Overflow (Canary Test)
 */
static void test_canary_overflow(void)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("entry of %s\n", __func__);

	/* intentionally overflow */
	((u64 *)buffer + BUFFER_SIZE)[0] = 0xdeadbeefdeadbeef;
	barrier_data(buffer);

	pr_info("exit of %s\n", __func__);
}

/*
 * Test Case 2: Recursive Call Corruption
 */
static void test_recursive_depth(int depth)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("entry of %s depth:%d\n", __func__, depth);

	if (depth <= MAX_DEPTH)
		test_recursive_depth(depth + 1);

	buffer[0] = depth;
	barrier_data(buffer);

	pr_info("exit of %s depth:%d\n", __func__, depth);
}

/*
 * Test Case 3: Silent Corruption
 */

static void test_silent_buggy(int i)
{
	u64 buf[BUFFER_SIZE];
	bool trigger;

	for (int j = 0; j < BUFFER_SIZE; j++)
		buf[j] = 0x01;

	WRITE_ONCE(g_corrupt_ptr, buf);
	trigger = (get_random_u32() % 100) < 5;

	/* buggy: return without resetting g_corrupt_ptr */
	if (trigger)
		return;

	while (true) {
		bool wait = false;

		for (int j = 0; j < BUFFER_SIZE / 4; j++) {
			if (!buf[j])
				wait = true;
		}
		if (!wait)
			break;
		usleep_range(1000, 2000);
	}
	WRITE_ONCE(g_corrupt_ptr, NULL);
}

static void test_silent_victim(int i)
{
	u64 buf[BUFFER_SIZE];

	for (int j = 0; j < BUFFER_SIZE; j++)
		buf[j] = 0xdeadbeaf;

	usleep_range(1000, 2000);

	for (int j = 0; j < BUFFER_SIZE; j++) {
		if (buf[j] != 0xdeadbeaf) {
			pr_warn("%s %d unhappy buf[%d]=0x%llx\n", __func__, i,
				j, buf[j]);
			return;
		}
	}

	pr_info("%s %d happy\n", __func__, i);
}

static int test_silent_unwit(void *data)
{
	u64 *local_ptr;

	while (!kthread_should_stop()) {
		usleep_range(1000, 2000);
		local_ptr = READ_ONCE(g_corrupt_ptr);
		if (!local_ptr)
			continue;

		// do not overwrite the victim's prologue
		for (int i = 0; i < BUFFER_SIZE / 4; i++)
			local_ptr[i] = 0xabcdabcd;
		WRITE_ONCE(g_corrupt_ptr, NULL);
	};

	return 0;
}

static void test_silent_corrupt(void)
{
	struct task_struct *unwitting;
	int i;

	pr_info("entry of %s\n", __func__);
	WRITE_ONCE(g_corrupt_ptr, NULL);

	unwitting = kthread_run(test_silent_unwit, NULL, "unwit");
	if (IS_ERR(unwitting)) {
		pr_err("failed to create unwit\n");
		return;
	}

	// trigger rate is 5%
	for (i = 0; i < 20; i++) {
		test_silent_buggy(i);
		test_silent_victim(i);
	}

	/* stop unwitting to avoid leaving extra thread running */
	kthread_stop(unwitting);
	pr_info("exit of %s\n", __func__);
}

/*
 * Procfs control
 */
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
			pr_info("test watch fire\n");
			test_watch_fire();
			break;
		case 1:
			pr_info("test canary overflow\n");
			test_canary_overflow();
			break;
		case 2:
			pr_info("test recursive corrupt\n");
			test_recursive_depth(0);
			break;
		case 3:
			pr_info("test silent corrupt\n");
			test_silent_corrupt();
			break;
		case 4:
			pr_info("test multiple recursive corrupt\n");
			test_multi_recursive_corrupt();
			break;
		default:
			pr_err("Unknown test number %d\n", test_num);
			return -EINVAL;
		}
	} else {
		pr_err("invalid command format. Use 'testN'.\n");
		return -EINVAL;
	}

	return count;
}

static ssize_t test_proc_read(struct file *file, char __user *buffer,
			      size_t count, loff_t *pos)
{
	static const char usage[] =
		"KStackWatch Simplified Test Module\n"
		"============ usuage ==============\n"
		"Usage:\n"
		"echo test0 > /proc/kstackwatch_test - test watch fire\n"
		"echo test1 > /proc/kstackwatch_test - test canary overflow\n"
		"echo test2 > /proc/kstackwatch_test - test recursive corrupt\n"
		"echo test3 > /proc/kstackwatch_test - test silent corrupt\n"
		"echo test4 > /proc/kstackwatch_test - test complex corrupt\n";

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
