#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>

#include "kwatch.h"

#define TRAMPOLINE_CHECK_DEPTH 16
static DEFINE_PER_CPU(bool, kwatch_probe_cpu_muted);

struct kwatch_probe_ctx {
	struct kprobe kp;
	struct kretprobe rp;
	const struct kwatch_config *cfg;

	u32 epoch;

	unsigned long func_start;
	unsigned long func_end;
};

static struct kwatch_probe_ctx kwatch_probe_ctx;

static bool kwatch_probe_in_trampoline(unsigned long ip)
{
#ifdef CONFIG_RETHOOK
	if (is_rethook_trampoline(ip))
		return true;
#endif
#ifdef CONFIG_KPROBES
	if (is_kretprobe_trampoline(ip))
		return true;
#endif
	return false;
}

bool kwatch_probe_validate_hit(struct pt_regs *regs)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;
	unsigned long sp = kernel_stack_pointer(regs);
	unsigned long ip = instruction_pointer(regs);
	unsigned long entries[TRAMPOLINE_CHECK_DEPTH];
	int i, nr;

	if (ctx->sp && sp == ctx->sp && ip >= kwatch_probe_ctx.func_start &&
	    ip < kwatch_probe_ctx.func_end)
		return false;

	nr = stack_trace_save_regs(regs, entries, TRAMPOLINE_CHECK_DEPTH, 0);
	for (i = 0; i < nr; i++) {
		if (kwatch_probe_in_trampoline(entries[i]))
			return false;
	}

	return true;
}

void kwatch_probe_mute(bool mute)
{
	__this_cpu_write(kwatch_probe_cpu_muted, mute);
}

static inline bool kwatch_probe_is_muted(void)
{
	return __this_cpu_read(kwatch_probe_cpu_muted);
}

void kwatch_tsk_ctx_reset(void)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;

	if (ctx->wp) {
		kwatch_hwbp_put(ctx->wp);
		ctx->wp = NULL;
	}
	ctx->depth = 0;
	ctx->sp = 0;
}

enum kwatch_probe_position {
	KWATCH_PROBE_POSITION_ENTRY,
	KWATCH_PROBE_POSITION_ACTIVE,
	KWATCH_PROBE_POSITION_EXIT
};

static bool kwatch_tsk_ctx_check(enum kwatch_probe_position pos)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;

	/* Pairs with smp_store_release() in kwatch_probe_start/stop() */
	u32 epoch = smp_load_acquire(&kwatch_probe_ctx.epoch);

	if (unlikely(ctx->epoch != epoch)) {
		kwatch_tsk_ctx_reset();
		ctx->epoch = epoch;
	}

	if (unlikely(!epoch))
		return false;

	switch (pos) {
	case KWATCH_PROBE_POSITION_ENTRY:
		ctx->depth++;
		return true;
	case KWATCH_PROBE_POSITION_ACTIVE:
		return true;
	case KWATCH_PROBE_POSITION_EXIT:
		if (unlikely(ctx->depth == 0)) {
			kwatch_tsk_ctx_reset();
			return false;
		}

		ctx->depth--;
		return true;
	}
}

static int kwatch_activate_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;
	unsigned long watch_addr;
	u16 watch_len;

	if (unlikely(in_nmi()))
		return 0;

	if (unlikely(kwatch_probe_is_muted()))
		return 0;

	if (unlikely(!kwatch_tsk_ctx_check(KWATCH_PROBE_POSITION_ACTIVE)))
		return 0;

	if (ctx->depth != kwatch_probe_ctx.cfg->depth + 1 || ctx->wp)
		return 0;

	if (kwatch_deref_resolve(kwatch_probe_ctx.cfg, regs, &watch_addr,
				 &watch_len))
		return 0;

	if (kwatch_hwbp_get(&ctx->wp))
		return 0;

	ctx->sp = kernel_stack_pointer(regs);

	kwatch_hwbp_arm(ctx->wp, watch_addr, watch_len);
	return 0;
}

static int kwatch_lifecycle_entry(struct kretprobe_instance *ri,
				  struct pt_regs *regs)
{
	if (unlikely(in_nmi()))
		return 0;

	if (!kwatch_tsk_ctx_check(KWATCH_PROBE_POSITION_ENTRY))
		return 0;

	if (kwatch_probe_ctx.cfg->func_offset == 0)
		kwatch_activate_handler(NULL, regs);

	return 0;
}

static int kwatch_lifecycle_exit(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;

	if (unlikely(in_nmi()))
		return 0;

	if (!kwatch_tsk_ctx_check(KWATCH_PROBE_POSITION_EXIT))
		return 0;

	if (ctx->depth == kwatch_probe_ctx.cfg->depth && ctx->wp) {
		kwatch_hwbp_put(ctx->wp);
		ctx->wp = NULL;
		ctx->sp = 0;
	}

	return 0;
}

int kwatch_probe_start(struct kwatch_config *cfg, unsigned long func_start,
		       unsigned long func_end)
{
	static u32 next_epoch;
	u32 current_epoch;
	int ret;

	/*
	 * Lockless check to prevent concurrent starts. Strictly serialized
	 * by the control plane mutex, but serves as a sanity check.
	 */
	if (smp_load_acquire(&kwatch_probe_ctx.epoch) != 0)
		return -EBUSY;

	memset(&kwatch_probe_ctx, 0, sizeof(kwatch_probe_ctx));
	kwatch_probe_ctx.cfg = cfg;
	kwatch_probe_ctx.func_start = func_start;
	kwatch_probe_ctx.func_end = func_end;

	kwatch_probe_ctx.rp.entry_handler = kwatch_lifecycle_entry;
	kwatch_probe_ctx.rp.handler = kwatch_lifecycle_exit;
	kwatch_probe_ctx.rp.kp.symbol_name = cfg->func_name;

	ret = register_kretprobe(&kwatch_probe_ctx.rp);
	if (ret < 0)
		return ret;

	if (cfg->func_offset) {
		kwatch_probe_ctx.kp.symbol_name = cfg->func_name;
		kwatch_probe_ctx.kp.offset = cfg->func_offset;
		kwatch_probe_ctx.kp.pre_handler = kwatch_activate_handler;

		ret = register_kprobe(&kwatch_probe_ctx.kp);
		if (ret) {
			unregister_kretprobe(&kwatch_probe_ctx.rp);
			return ret;
		}
	}

	current_epoch = ++next_epoch;
	if (unlikely(!current_epoch))
		current_epoch = ++next_epoch;

	/* Pairs with smp_load_acquire() in kwatch_tsk_ctx_check() */
	smp_store_release(&kwatch_probe_ctx.epoch, current_epoch);

	return 0;
}

void kwatch_probe_stop(void)
{
	if (!kwatch_probe_ctx.epoch)
		return;

	/* Pairs with smp_load_acquire() in kwatch_tsk_ctx_check() */
	smp_store_release(&kwatch_probe_ctx.epoch, 0);

	if (kwatch_probe_ctx.cfg->func_offset > 0)
		unregister_kprobe(&kwatch_probe_ctx.kp);

	unregister_kretprobe(&kwatch_probe_ctx.rp);
}
