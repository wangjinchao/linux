// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/fprobe.h>
#include <linux/kprobes.h>
#include <linux/kstackwatch_types.h>
#include <linux/printk.h>

#include "kstackwatch.h"

static struct kprobe entry_probe;
static struct fprobe exit_probe;
#define INVALID_PID -1
static atomic_t ksw_stack_pid = ATOMIC_INIT(INVALID_PID);

static int ksw_stack_prepare_watch(struct pt_regs *regs,
				   const struct ksw_config *config,
				   ulong *watch_addr, u16 *watch_len)
{
	/* implement logic will be added in following patches */
	*watch_addr = 0;
	*watch_len = 0;
	return 0;
}

static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
				    unsigned long flags)
{
	struct kstackwatch_ctx *ctx = &current->kstackwatch_ctx;
	ulong watch_addr;
	u16 watch_len;
	int ret;

	if (ctx->depth++ != ksw_get_config()->depth)
		return;

	if (atomic_cmpxchg(&ksw_stack_pid, INVALID_PID, current->pid) !=
	    INVALID_PID)
		return;

	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
				      &watch_len);
	if (ret) {
		atomic_set(&ksw_stack_pid, INVALID_PID);
		pr_err("failed to prepare watch target: %d\n", ret);
		return;
	}

	ret = ksw_watch_on(watch_addr, watch_len);
	if (ret) {
		atomic_set(&ksw_stack_pid, INVALID_PID);
		pr_err("failed to watch on depth:%d addr:0x%lx len:%u %d\n",
		       ksw_get_config()->depth, watch_addr, watch_len, ret);
		return;
	}

	ctx->watch_addr = watch_addr;
	ctx->watch_len = watch_len;
	ctx->watch_on = true;
}

static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
				   unsigned long ret_ip,
				   struct ftrace_regs *regs, void *data)
{
	struct kstackwatch_ctx *ctx = &current->kstackwatch_ctx;

	if (--ctx->depth != ksw_get_config()->depth)
		return;

	if (atomic_read(&ksw_stack_pid) != current->pid)
		return;
	WARN_ON_ONCE(!ctx->watch_on);
	WARN_ON_ONCE(ksw_watch_off(ctx->watch_addr, ctx->watch_len));
	ctx->watch_on = false;

	atomic_set(&ksw_stack_pid, INVALID_PID);
}

int ksw_stack_init(void)
{
	int ret;
	char *symbuf = NULL;

	memset(&entry_probe, 0, sizeof(entry_probe));
	entry_probe.symbol_name = ksw_get_config()->function;
	entry_probe.offset = ksw_get_config()->ip_offset;
	entry_probe.post_handler = ksw_stack_entry_handler;
	ret = register_kprobe(&entry_probe);
	if (ret) {
		pr_err("Failed to register kprobe ret %d\n", ret);
		return ret;
	}

	memset(&exit_probe, 0, sizeof(exit_probe));
	exit_probe.exit_handler = ksw_stack_exit_handler;
	symbuf = (char *)ksw_get_config()->function;

	ret = register_fprobe_syms(&exit_probe, (const char **)&symbuf, 1);
	if (ret < 0) {
		pr_err("register_fprobe_syms fail %d\n", ret);
		unregister_kprobe(&entry_probe);
		return ret;
	}

	return 0;
}

void ksw_stack_exit(void)
{
	unregister_fprobe(&exit_probe);
	unregister_kprobe(&entry_probe);
}
