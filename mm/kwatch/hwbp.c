// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpuhotplug.h>
#include <linux/ftrace.h>
#include <linux/hw_breakpoint.h>
#include <linux/irqflags.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>

#include "kwatch.h"

static LLIST_HEAD(kwatch_free_wp_list);
static LIST_HEAD(kwatch_all_wp_list);
static DEFINE_MUTEX(kwatch_all_wp_mutex);
static unsigned long kwatch_dummy_holder;
#define TRAMPOLINE_CHECK_DEPTH 16

static void kwatch_hwbp_handler(struct perf_event *bp,
				struct perf_sample_data *data,
				struct pt_regs *regs)
{
	unsigned long entries[TRAMPOLINE_CHECK_DEPTH];
	struct kwatch_tsk_ctx *ctx = &current->kwatch_tsk_ctx;
	struct kwatch_watchpoint *wp = bp->overflow_handler_context;
	unsigned long sp = kernel_stack_pointer(regs);
	unsigned long ip = instruction_pointer(regs);
	int i, nr = 0;

	/*
	 * SP-based Spatial Filter:
	 * If regs->sp matches the activation frame (ctx->sp), the access
	 * originates from the monitored function itself (or inline logic).
	 * We ignore these to avoid self-inflicted false positives.
	 */
	if (ctx->sp && sp == ctx->sp && ip >= wp->func_start && ip < wp->func_end)
		return;

	nr = stack_trace_save_regs(regs, entries, TRAMPOLINE_CHECK_DEPTH, 0);
	for (i = 0; i < nr; i++) {
		if (kwatch_probe_in_trampoline(entries[i]))
			return;
	}

	pr_warn("========== KWatch Fired =======\n");
	dump_stack();
	pr_warn("========== KWatch   End =======\n");
}

bool kwatch_is_handler(struct perf_event *event)
{
	return unlikely(event->overflow_handler == kwatch_hwbp_handler);
}

static void kwatch_hwbp_arm_local(void *info)
{
	struct kwatch_watchpoint *wp = info;
	struct perf_event *bp;
	unsigned long flags;
	int cpu;

	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	bp = per_cpu(*wp->event, cpu);

	if (likely(bp)) {
		WARN_ONCE(modify_wide_hw_breakpoint_local(bp, &wp->attr),
			  "KWatch: reinstall HWBP failed on CPU%d", cpu);
	}
	local_irq_restore(flags);
}

static void kwatch_hwbp_disarm_local(void *info)
{
	struct kwatch_watchpoint *wp = info;

	kwatch_hwbp_arm_local(info);

	if (atomic_dec_and_test(&wp->pending_ipis))
		llist_add(&wp->node, &kwatch_free_wp_list);
}

static int kwatch_hwbp_cpu_online(unsigned int cpu)
{
	struct perf_event_attr attr;
	struct kwatch_watchpoint *wp;
	struct perf_event *bp;

	mutex_lock(&kwatch_all_wp_mutex);
	list_for_each_entry(wp, &kwatch_all_wp_list, list) {
		attr = wp->attr;
		attr.bp_addr = (unsigned long)&kwatch_dummy_holder;
		bp = perf_event_create_kernel_counter(&attr, cpu, NULL,
						      kwatch_hwbp_handler, wp);
		if (IS_ERR(bp)) {
			pr_warn("%s failed to create watch on CPU %d: %ld\n",
				__func__, cpu, PTR_ERR(bp));
			continue;
		}
		per_cpu(*wp->event, cpu) = bp;
		INIT_CSD(per_cpu_ptr(wp->csd_arm, cpu), kwatch_hwbp_arm_local,
			 wp);
		INIT_CSD(per_cpu_ptr(wp->csd_disarm, cpu),
			 kwatch_hwbp_disarm_local, wp);
	}
	mutex_unlock(&kwatch_all_wp_mutex);
	return 0;
}

static int kwatch_hwbp_cpu_offline(unsigned int cpu)
{
	struct kwatch_watchpoint *wp;
	struct perf_event *bp;

	mutex_lock(&kwatch_all_wp_mutex);
	list_for_each_entry(wp, &kwatch_all_wp_list, list) {
		bp = per_cpu(*wp->event, cpu);
		if (bp)
			unregister_hw_breakpoint(bp);
	}
	mutex_unlock(&kwatch_all_wp_mutex);
	return 0;
}

static void kwatch_wp_destroy(struct kwatch_watchpoint *wp)
{
	unregister_wide_hw_breakpoint(wp->event);
	free_percpu(wp->csd_arm);
	free_percpu(wp->csd_disarm);
	kfree(wp);
}

int kwatch_hwbp_get(struct kwatch_watchpoint **out_wp)
{
	struct llist_node *node = llist_del_first(&kwatch_free_wp_list);

	if (!node)
		return -EBUSY;

	*out_wp = llist_entry(node, struct kwatch_watchpoint, node);
	atomic_inc(&(*out_wp)->refcount);
	return 0;
}

void kwatch_hwbp_arm(struct kwatch_watchpoint *wp, unsigned long addr, u16 len,
		     enum kwatch_access_type type)
{
	int cur_cpu = raw_smp_processor_id();
	call_single_data_t *csd;
	int cpu, target_count = 0;
	bool is_disarm = (addr == (unsigned long)&kwatch_dummy_holder);

	wp->attr.bp_addr = addr;
	wp->attr.bp_len = len;
	wp->attr.bp_type = (type == KWATCH_ACCESS_X)  ? HW_BREAKPOINT_X :
			   (type == KWATCH_ACCESS_R)  ? HW_BREAKPOINT_R :
			   (type == KWATCH_ACCESS_RW) ? HW_BREAKPOINT_RW :
							HW_BREAKPOINT_W;

	/* FAST PATH OPTIMIZATION: Only track IPIs if we are disarming */
	if (is_disarm) {
		for_each_online_cpu(cpu)
			target_count++;
		atomic_set(&wp->pending_ipis, target_count);
	}

	for_each_online_cpu(cpu) {
		/* remote cpu first */
		if (cpu == cur_cpu)
			continue;
		csd = per_cpu_ptr(is_disarm ? wp->csd_disarm : wp->csd_arm,
				  cpu);

		/** If the CPU went offline after we counted it but before we
		 * queued the IPI, the queue fails. We must manually decrement.
		 */
		if (is_disarm && smp_call_function_single_async(cpu, csd)) {
			if (atomic_dec_and_test(&wp->pending_ipis))
				llist_add(&wp->node, &kwatch_free_wp_list);
		} else if (!is_disarm) {
			smp_call_function_single_async(cpu, csd);
		}
	}

	if (is_disarm)
		kwatch_hwbp_disarm_local(wp);
	else
		kwatch_hwbp_arm_local(wp);
}

int kwatch_hwbp_put(struct kwatch_watchpoint *wp)
{
	kwatch_hwbp_arm(wp, (unsigned long)&kwatch_dummy_holder, sizeof(unsigned long),
			KWATCH_ACCESS_W);

	// Drop task ownership. If pool is gone (ref == 0), task frees it.
	if (atomic_dec_and_test(&wp->refcount))
		kwatch_wp_destroy(wp);
	return 0;
}

int kwatch_hwbp_prealloc(u16 max_watch, unsigned long func_start, unsigned long func_end)
{
	struct kwatch_watchpoint *wp;
	int success = 0, cpu;

	init_llist_head(&kwatch_free_wp_list);

	while (!max_watch || success < max_watch) {
		wp = kzalloc_obj(*wp);
		if (!wp)
			break;

		wp->csd_arm = alloc_percpu(call_single_data_t);
		wp->csd_disarm = alloc_percpu(call_single_data_t);
		if (!wp->csd_arm || !wp->csd_disarm) {
			free_percpu(wp->csd_arm);
			free_percpu(wp->csd_disarm);
			kfree(wp);
			break;
		}

		for_each_possible_cpu(cpu) {
			INIT_CSD(per_cpu_ptr(wp->csd_arm, cpu),
				 kwatch_hwbp_arm_local, wp);
			INIT_CSD(per_cpu_ptr(wp->csd_disarm, cpu),
				 kwatch_hwbp_disarm_local, wp);
		}

		hw_breakpoint_init(&wp->attr);
		wp->attr.bp_addr = (unsigned long)&kwatch_dummy_holder;
		wp->attr.bp_len = sizeof(unsigned long);
		wp->attr.bp_type = HW_BREAKPOINT_X;

		wp->event = register_wide_hw_breakpoint(&wp->attr,
							kwatch_hwbp_handler,
							wp);
		if (IS_ERR((void *)wp->event)) {
			free_percpu(wp->csd_arm);
			free_percpu(wp->csd_disarm);
			kfree(wp);
			break;
		}

		wp->func_start = func_start;
		wp->func_end = func_end;

		atomic_set(&wp->refcount, 1);

		llist_add(&wp->node, &kwatch_free_wp_list);
		mutex_lock(&kwatch_all_wp_mutex);
		list_add(&wp->list, &kwatch_all_wp_list);
		mutex_unlock(&kwatch_all_wp_mutex);
		success++;
	}

	if (success > 0)
		cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN, "kwatch:online",
					  kwatch_hwbp_cpu_online,
					  kwatch_hwbp_cpu_offline);

	return success > 0 ? 0 : -EBUSY;
}

void kwatch_hwbp_free(void)
{
	struct kwatch_watchpoint *wp, *tmp;

	cpuhp_remove_state_nocalls(CPUHP_AP_ONLINE_DYN);
	mutex_lock(&kwatch_all_wp_mutex);
	list_for_each_entry_safe(wp, tmp, &kwatch_all_wp_list, list) {
		list_del(&wp->list);

		/* Drop pool ownership.
		 * If a flying task holds it, ref drops to 1, and task frees it later.
		 * If idle, ref drops to 0, and we free it immediately.
		 */
		if (atomic_dec_and_test(&wp->refcount))
			kwatch_wp_destroy(wp);
	}
	mutex_unlock(&kwatch_all_wp_mutex);
}
