// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kprobes.h>
#include <linux/fprobe.h>
#include <linux/sched.h>

#include "kwatch.h"

static struct kprobe entry_probe;
static struct kretprobe exit_probe;

static bool probe_enable;
static u16 probe_generation;

void kwatch_ctx_release(void)
{
	struct kwatch_ctx *ctx = &current->kwatch_ctx;

	if (ctx)
		kwatch_hwbp_put(ctx->wp);

	ctx->wp = NULL;
	ctx->sp = 0;
	ctx->depth = 0;
	ctx->generation = READ_ONCE(probe_generation);
}

static bool kwatch_check_ctx(bool entry)
{
	struct kwatch_ctx *ctx = &current->kwatch_ctx;
	u16 cur_enable = READ_ONCE(probe_enable);
	u16 cur_generation = READ_ONCE(probe_generation);
	u16 cur_depth, target_depth = kwatch_get_config()->depth;

	if (!cur_enable) {
		kwatch_ctx_release();
		return false;
	}

	if (ctx->generation != cur_generation)
		kwatch_ctx_release();

	if (!entry && !ctx->depth) {
		kwatch_ctx_release();
		return false;
	}

	if (entry)
		cur_depth = ctx->depth++;
	else
		cur_depth = --ctx->depth;

	if (cur_depth == target_depth)
		return true;
	else
		return false;
}

static void kwatch_fentry_handler(struct kprobe *p, struct pt_regs *regs,
				  unsigned long flags)
{
	kwatch_config *cfg = kwatch_get_config();
	struct kwatch_ctx *ctx = &current->kwatch_ctx;
	ulong stack_pointer;
	ulong watch_addr;
	u16 watch_len;
	enum kwatch_access_type type;

	stack_pointer = kernel_stack_pointer(regs);

	if (ctx->wp && ctx->sp == stack_pointer)
		return;

	if (!kwatch_check_ctx(true))
		return;

	if (kwatch_hwbp_get(&ctx->wp))
		return;

	if (cfg->mode_ops->resolve(regs,
				   cfg->mode_config,
				   &watch_addr,
				   &watch_len,
				   &type)) {
		kwatch_hwbp_put(ctx->wp);
		return;
	}

	kwatch_hwbp_on(ctx->wp, watch_addr, watch_len, type);
	ctx->sp = stack_pointer;
}

static int kwatch_fexit_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (!kwatch_check_ctx(false))
		return 0;

	kwatch_ctx_release();
	return 0;
}

int kwatch_probe_start(void)
{
	const struct kwatch_config *cfg = kwatch_get_config();
	int ret;

	memset(&entry_probe, 0, sizeof(entry_probe));
	entry_probe.symbol_name = cfg->func_name;
	entry_probe.offset = cfg->func_offset;
	entry_probe.post_handler = kwatch_fentry_handler;

	ret = register_kprobe(&entry_probe);
	if (ret)
		return ret;

	memset(&exit_probe, 0, sizeof(exit_probe));
	exit_probe.handler = kwatch_fexit_handler;
	exit_probe.kp.symbol_name = kwatch_get_config()->func_name;

	ret = register_kretprobe(&exit_probe);
	if (ret < 0) {
		unregister_kprobe(&entry_probe);
		return ret;
	}

	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
	WRITE_ONCE(probe_enable, true);
	return 0;
}

void kwatch_probe_stop(void)
{
	WRITE_ONCE(probe_enable, false);
	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
	unregister_kretprobe(&exit_probe);
	unregister_kprobe(&entry_probe);
}
