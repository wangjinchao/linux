// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/prandom.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Simple KStackWatch Test Module");
MODULE_LICENSE("GPL");

static struct proc_dir_entry *test_proc;

#define BUFFER_SIZE 32
#define CORRUPT_SIZE 8 /* BUFFER_SIZE / 4 */
#define MAX_DEPTH 6
#define JUNK_SZ 256
#define VICTIM_BUF_SZ 128
#define NUM_WORKERS 10
#define NODE_BUF_SZ 32

struct work_node {
	ulong *ptr;
	struct completion done;
	struct list_head list;
};
struct completion work_res;

static LIST_HEAD(work_list);
static DEFINE_MUTEX(work_mutex);

static struct task_struct *unwitting_thread;
static struct task_struct *worker_threads[NUM_WORKERS];

/*
 * Test Case 0: Write to the watch addr directly
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
 * Test Case 1: Overflow Canary
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
 * Test Case 2: test watch on a specify depth
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

static void test_silent_buggy(int seq_id, int sdepth, int ddepth)
{
	ulong buf[BUFFER_SIZE];
	bool trigger;
	struct work_node *node;

	if (sdepth < ddepth) {
		test_silent_buggy(seq_id, sdepth + 1, ddepth);
		return;
	}

	for (int j = 0; j < BUFFER_SIZE; j++)
		buf[j] = 0x01;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return;

	init_completion(&node->done);
	node->ptr = buf;
	mutex_lock(&work_mutex);
	list_add(&node->list, &work_list);
	mutex_unlock(&work_mutex);
	complete(&work_res);

	trigger = (get_random_u32() % 100) < 10;

	/* buggy: return without wait for completion */
	if (trigger) {
		pr_info("trigger buggy %d\n", seq_id);
		return;
	}

	wait_for_completion(&node->done);
	kfree(node);
}

static void test_silent_victim(int seq_id, int sdepth, int ddepth)
{
	ulong buf[BUFFER_SIZE];
	bool trigger;
	struct work_node *node;

	for (int j = 0; j < BUFFER_SIZE; j++)
		buf[j] = 0xdeadbeef + sdepth;

	usleep_range(1000, 2000);
	for (int j = 0; j < BUFFER_SIZE; j++) {
		if (buf[j] != (0xdeadbeef + sdepth)) {
			pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
				seq_id, sdepth, j, buf[j]);
			break;
		}
	}

	// trigger always true; keep same stack size as buggy
	trigger = (get_random_u32() % 100) < 100;
	if (!trigger) {
		node = (struct work_node *)buf;
		list_add(&node->list, &work_list);
		return;
	}

	pr_info("victim[%d][%d]: happy\n", seq_id, sdepth);
	if (sdepth < ddepth)
		test_silent_victim(seq_id, sdepth + 1, ddepth);
}

static int test_silent_unwit(void *data)
{
	struct work_node *node;

	while (!kthread_should_stop()) {
		wait_for_completion(&work_res);

		while (true) {
			mutex_lock(&work_mutex);
			node = list_first_entry_or_null(&work_list,
							struct work_node, list);
			if (node)
				list_del(&node->list);
			mutex_unlock(&work_mutex);
			if (!node)
				break; /* no more nodes, exit inner loop */

			/* skip if already completed */
			if (completion_done(&node->done))
				continue;
			usleep_range(500, 1000);

			for (int i = 0; i < CORRUPT_SIZE; i++)
				node->ptr[i] = 0xabcdabcd;

			complete(&node->done);
		}
	}

	return 0;
}

/*
 * Test Case 3: Silent Corruption (1 worker, 0 depth)
 */
static void test_silent_corruption(void)
{
	struct task_struct *unwitting;
	int i;

	pr_info("entry of %s cpu:%d\n", __func__, smp_processor_id());
	init_completion(&work_res);

	unwitting = kthread_run(test_silent_unwit, NULL, "unwit");
	if (IS_ERR(unwitting)) {
		pr_err("failed to create unwit\n");
		return;
	}

	// trigger rate is 10%
	for (i = 0; i < 10; i++) {
		test_silent_buggy(i, 0, 0);
		test_silent_victim(i, 0, 0);
	}

	/* stop unwitting to avoid leaving extra thread running */
	kthread_stop(unwitting);
	pr_info("exit of %s\n", __func__);
}

/*
 * Worker thread function for test4
 */
static int test_multi_worker_thread(void *data)
{
	int seq_id = (long)data;
	int round = 0;

	while (!kthread_should_stop()) {
		round++;
		test_silent_buggy(seq_id, 0, 10);
		test_silent_victim(seq_id, 0, 10);
	}

	return 0;
}

/*
 * Test Case 4: Multi-threaded Recursive Corruption (20 workers, 10 depth)
 */
static void test_multi_recursive_uar(void)
{
	int i;

	pr_info("entry of %s\n", __func__);

	/* start unwitting thread */
	unwitting_thread = kthread_run(test_silent_unwit, NULL, "unwit");
	if (IS_ERR(unwitting_thread)) {
		pr_err("failed to create unwitting thread\n");
		return;
	}

	for (i = 0; i < NUM_WORKERS; i++) {
		worker_threads[i] = kthread_run(test_multi_worker_thread,
						(void *)(long)i, "worker_%d",
						i);
		if (IS_ERR(worker_threads[i])) {
			pr_err("failed to create worker thread %d\n", i);
			worker_threads[i] = NULL;
		}
	}

	usleep_range(3000, 5000);
	if (unwitting_thread && !IS_ERR(unwitting_thread)) {
		kthread_stop(unwitting_thread);
		unwitting_thread = NULL;
	}

	for (i = 0; i < NUM_WORKERS; i++) {
		if (worker_threads[i]) {
			kthread_stop(worker_threads[i]);
			worker_threads[i] = NULL;
		}
	}

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
			test_silent_corruption();
			break;
		case 4:
			pr_info("test multiple recursive corrupt\n");
			test_multi_recursive_uar();
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
		"echo test{i} > /proc/kstackwatch_test\n"
		" test1 - test canary overflow\n"
		" test2 - test recursive corruption\n"
		" test3 - test silent corruption\n"
		" test4 - test multiple thread recursive corruption\n";

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
