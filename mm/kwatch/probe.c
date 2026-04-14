// SPDX-License-Identifier: GPL-2.0
#include <linux/kprobes.h>
#include <linux/fprobe.h>
#include <linux/sched.h>

#include "kwatch.h"
#include "mode/mode.h"

struct kwatch_probe_ctx {
	struct kprobe kp;
	struct kretprobe rp;
	const struct kwatch_config *cfg;

	bool enable;
	u16 generation;
};

static struct kwatch_probe_ctx kwatch_probe_ctx;

void kwatch_tsk_ctx_reset(void)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;

	if (ctx->wp)
		kwatch_hwbp_put(ctx->wp);

	ctx->wp = NULL;
	ctx->sp = 0;
	ctx->depth = 0;
	ctx->generation = READ_ONCE(kwatch_probe_ctx.generation);
}

static bool kwatch_tsk_ctx_check(bool entry)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;
	u16 cur_enable = READ_ONCE(kwatch_probe_ctx.enable);
	u16 cur_generation = READ_ONCE(kwatch_probe_ctx.generation);
	u16 cur_depth, target_depth = kwatch_probe_ctx.cfg->depth;

	if (!cur_enable) {
		kwatch_tsk_ctx_reset();
		return false;
	}

	if (ctx->generation != cur_generation)
		kwatch_tsk_ctx_reset();

	if (!entry && !ctx->depth) {
		kwatch_tsk_ctx_reset();
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
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;
	enum kwatch_access_type type = kwatch_probe_ctx.cfg->access_type;
	ulong stack_pointer;
	ulong watch_addr;
	u16 watch_len;

	stack_pointer = kernel_stack_pointer(regs);

	if (ctx->wp && ctx->sp == stack_pointer)
		return;

	if (!kwatch_tsk_ctx_check(true))
		return;

	if (kwatch_hwbp_get(&ctx->wp))
		return;

	if (kwatch_mode_addr_len_resolve(regs,
					 &watch_addr,
					 &watch_len)) {
		kwatch_hwbp_put(ctx->wp);
		return;
	}

	kwatch_hwbp_arm(ctx->wp, watch_addr, watch_len, type);
	ctx->sp = stack_pointer;
}

static int kwatch_fexit_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (!kwatch_tsk_ctx_check(false))
		return 0;

	kwatch_tsk_ctx_reset();
	return 0;
}

int kwatch_probe_start(struct kwatch_config *cfg)
{
	int ret;

	if (kwatch_probe_ctx.enable)
		return -EBUSY;

	u16 cur_generation = READ_ONCE(kwatch_probe_ctx.generation);

	memset(&kwatch_probe_ctx, 0, sizeof(kwatch_probe_ctx));

	kwatch_probe_ctx.rp.handler = kwatch_fexit_handler;
	kwatch_probe_ctx.rp.kp.symbol_name = cfg->func_name;

	ret = register_kretprobe(&kwatch_probe_ctx.rp);
	if (ret < 0) {
		unregister_kprobe(&kwatch_probe_ctx.kp);
		return ret;
	}

	kwatch_probe_ctx.kp.symbol_name = cfg->func_name;
	kwatch_probe_ctx.kp.offset = cfg->func_offset;
	kwatch_probe_ctx.kp.post_handler = kwatch_fentry_handler;

	ret = register_kprobe(&kwatch_probe_ctx.kp);
	if (ret)
		return ret;

	WRITE_ONCE(kwatch_probe_ctx.generation, cur_generation + 1);
	WRITE_ONCE(kwatch_probe_ctx.enable, true);
	return 0;
}

void kwatch_probe_stop(void)
{
	u16 cur_generation = READ_ONCE(kwatch_probe_ctx.generation);

	unregister_kprobe(&kwatch_probe_ctx.kp);
	unregister_kretprobe(&kwatch_probe_ctx.rp);
	synchronize_rcu();
	WRITE_ONCE(kwatch_probe_ctx.enable, false);
	WRITE_ONCE(kwatch_probe_ctx.generation, cur_generation + 1);
}
