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

#define BUFFER_SIZE 16
#define MAX_DEPTH 10

struct work_node {
	ulong *ptr;
	struct completion done;
	struct list_head list;
};

static DECLARE_COMPLETION(work_res);
static DEFINE_MUTEX(work_mutex);
static LIST_HEAD(work_list);

static int global_corrupt_size;
static int global_loop_count;

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

static void test_canary_overflow(void)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("entry of %s\n", __func__);

	/* intentionally overflow */
	((u64 *)buffer + BUFFER_SIZE)[0] = 0xdeadbeefdeadbeef;
	barrier_data(buffer);

	pr_info("exit of %s\n", __func__);
}

static void test_recursive_depth(int depth)
{
	u64 buffer[BUFFER_SIZE];

	pr_info("entry of %s depth:%d\n", __func__, depth);

	if (depth < MAX_DEPTH)
		test_recursive_depth(depth + 1);

	buffer[0] = depth;
	barrier_data(buffer);

	pr_info("exit of %s depth:%d\n", __func__, depth);
}

static struct work_node *test_mthread_buggy(int thread_id, int seq_id)
{
	ulong buf[BUFFER_SIZE];
	struct work_node *node;
	bool trigger;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	init_completion(&node->done);
	node->ptr = buf;
	mutex_lock(&work_mutex);
	list_add(&node->list, &work_list);
	mutex_unlock(&work_mutex);
	complete(&work_res);

	trigger = (get_random_u32() % 100) < 10;
	if (trigger)
		return node;

	wait_for_completion(&node->done);
	kfree(node);
	return NULL;
}

static struct work_node *test_mthread_victim(int thread_id, int seq_id)
{
	ulong buf[BUFFER_SIZE];

	for (int j = 0; j < BUFFER_SIZE; j++)
		buf[j] = 0xdeadbeef + seq_id;

	usleep_range(1000, 2000);
	for (int j = 0; j < BUFFER_SIZE; j++) {
		if (buf[j] != (0xdeadbeef + seq_id)) {
			pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
				thread_id, seq_id, j, buf[j]);
			return NULL;
		}
	}

	pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);

	return NULL;
}

static int test_mthread_corrupting(void *data)
{
	struct work_node *node;
	int corrupt_size;

	while (!kthread_should_stop()) {
		if (!wait_for_completion_timeout(&work_res, HZ))
			continue;

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
			WARN_ON_ONCE(completion_done(&node->done));

			usleep_range(50, 100);

			corrupt_size = READ_ONCE(global_corrupt_size);
			for (int i = 0; i < corrupt_size; i++)
				node->ptr[i] = 0xabcdabcd;

			complete(&node->done);
		}
	}

	return 0;
}

static int test_mthread_worker(void *data)
{
	int thread_id = (long)data;
	int loop_count;
	struct work_node *node;

	// make sure global variables are visible
	rmb();
	loop_count = READ_ONCE(global_loop_count);

	for (int i = 0; i < loop_count; i++) {
		node = test_mthread_buggy(thread_id, i);
		test_mthread_victim(thread_id, i);
		if (node) {
			pr_info("worker[%d][%d] triggered\n", thread_id, i);
			wait_for_completion(&node->done);
			kfree(node);
		}
	}
	return 0;
}

static void test_mthread_case(int num_workers, int loop_count, int corrupt_size)
{
	static struct task_struct *corrupting;
	static struct task_struct **workers;

	WRITE_ONCE(global_loop_count, loop_count);
	WRITE_ONCE(global_corrupt_size, corrupt_size);

	// make sure global variables are visible
	wmb();

	init_completion(&work_res);
	workers = kmalloc_array(num_workers, sizeof(void *), GFP_KERNEL);
	memset(workers, 0, sizeof(struct task_struct *) * num_workers);

	corrupting = kthread_run(test_mthread_corrupting, NULL, "corrupting");
	if (IS_ERR(corrupting)) {
		pr_err("failed to create corrupting thread\n");
		return;
	}

	for (ulong i = 0; i < num_workers; i++) {
		workers[i] = kthread_run(test_mthread_worker, (void *)i,
					 "worker_%ld", i);
		if (IS_ERR(workers[i])) {
			pr_err("failto create worker thread %ld", i);
			workers[i] = NULL;
		}
	}

	for (ulong i = 0; i < num_workers; i++) {
		if (workers[i] && workers[i]->__state != TASK_DEAD) {
			usleep_range(1000, 2000);
			i--;
		}
	}
	kfree(workers);

	if (corrupting && !IS_ERR(corrupting)) {
		kthread_stop(corrupting);
		corrupting = NULL;
	}
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
			test_watch_fire();
			break;
		case 1:
			test_canary_overflow();
			break;
		case 2:
			test_recursive_depth(0);
			break;
		case 3:
			test_mthread_case(1, 20, BUFFER_SIZE / 4);
			break;
		case 4:
			test_mthread_case(20, 1, BUFFER_SIZE / 4);
			break;
		case 5:
			test_mthread_case(1, 1, BUFFER_SIZE * 2);
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
	static const char usage[] = "KStackWatch Simplified Test Module\n"
				    "============ usuage ==============\n"
				    "Usage:\n"
				    "echo test{i} > /proc/kstackwatch_test\n"
				    " test0 - test watch fire\n"
				    " test1 - test canary overflow\n"
				    " test2 - test recursive func\n"
				    " test3 - test silent corruption\n"
				    " test4 - test multiple silent corruption\n"
				    " test5 - test prologue corruption\n";

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
