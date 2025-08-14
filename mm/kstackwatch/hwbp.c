/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Hardware breakpoint management for StackWatch (minimal approach)
 */

#include <linux/kprobes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched/debug.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <asm/hw_breakpoint.h>
#include <linux/stacktrace.h>

#include "kstackwatch.h"

#define MAX_STACK_ENTRIES 64

/* Per-CPU minimal breakpoint storage */
static struct perf_event *__percpu *hwbp_events;
static DEFINE_SPINLOCK(hwbp_lock);

static unsigned long long marker;

struct hwbp_worker {
	struct work_struct work;
	int original_cpu;
} myworker;
static void setup_hwbp_on_cpu_wrapper(void *useless);

static DEFINE_PER_CPU(call_single_data_t,
		      hwbp_csd) = CSD_INIT(setup_hwbp_on_cpu_wrapper, NULL);

#define MAX_STACK_ENTRIES 64

/* Resolved once, then reused */
static unsigned long tramp_start, tramp_end;

static void kstackwatch_resolve_trampolines(void)
{
	unsigned long sz, off;

	if (likely(tramp_start && tramp_end))
		return;

	tramp_start = kallsyms_lookup_name("arch_rethook_trampoline");
	if (tramp_start && kallsyms_lookup_size_offset(tramp_start, &sz, &off))
		tramp_end = tramp_start + sz;
}

static bool kstackwatch_should_ignore(unsigned long ip)
{
	if (tramp_start && tramp_end && ip >= tramp_start && ip < tramp_end)
		return true;

	return false;
}

static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data,
			 struct pt_regs *regs)
{
	unsigned long entries[MAX_STACK_ENTRIES];
	int i, nr = 0;

	kstackwatch_resolve_trampolines();

#if IS_ENABLED(CONFIG_STACKTRACE)
	/* Unwind the *interrupted* context */
	nr = stack_trace_save_regs(regs, entries, MAX_STACK_ENTRIES, 0);

	/* If any frame is inside the rethook trampolines, ignore this hit */
	for (i = 0; i < nr; i++) {
		if (kstackwatch_should_ignore(entries[i])) {
			pr_debug("StackWatch: Found rethook trampolines, ignoring hit\n");
			return;
		}
	}
#else
	/* Cannot filter reliably without stacktrace support; proceed */
#endif

	pr_emerg("========== KStackWatch Triggered: Start =======\n");
	pr_emerg("  WatchFunction: %s\n", target_function);

	/* Registers at the trigger point */
	show_regs(regs);
	pr_emerg("========== KStackWatch Triggered: End ==========\n");

	if (panic_on_corruption)
		panic("StackWatch: Stack corruption detected");
}

/* Per-CPU HWBP setup - just install minimal event */
static void setup_hwbp_on_cpu(void *useless)
{
	struct perf_event *bp;
	int cpu = smp_processor_id();
	int ret;

	bp = *this_cpu_ptr(hwbp_events);

	/* Reparse arch-specific info with new address */
	ret = hw_breakpoint_arch_parse(bp, &bp->attr, counter_arch_bp(bp));
	if (ret) {
		pr_err("StackWatch: Failed to parse breakpoint for CPU %d: %d\n",
		       cpu, ret);
		return;
	}
	/* Use arch function that doesn't sleep */
	if (arch_reinstall_hw_breakpoint(bp)) {
		pr_err("StackWatch: Failed to install HWBP on CPU %d\n", cpu);
		return;
	}
	if (bp->attr.bp_addr == (unsigned long)&marker) {
		pr_info("StackWatch: HWBP disarmed on CPU %d at 0x%p\n", cpu,
			(void *)bp->attr.bp_addr);
	} else {
		pr_info("StackWatch: HWBP armed on CPU %d at 0x%p\n", cpu,
			(void *)bp->attr.bp_addr);
	}
}

static void setup_hwbp_on_cpu_wrapper(void *useless)
{
	if (smp_processor_id() == myworker.original_cpu)
		return;
	setup_hwbp_on_cpu(useless);
}

static void setup_hwbp_work_fn(struct work_struct *work)
{
	struct hwbp_worker *worker =
		container_of(work, struct hwbp_worker, work);
	int original_cpu = READ_ONCE(worker->original_cpu);
	call_single_data_t *csd;

	int cpu;

	for_each_online_cpu(cpu) {
		if (cpu == original_cpu)
			continue;
		// Asynchronously call the function on all other CPUs
		csd = &per_cpu(hwbp_csd, cpu);
		smp_call_function_single_async(cpu, csd);
	}
}

int hwbp_init(void)
{
	struct perf_event_attr attr;

	hw_breakpoint_init(&attr);
	attr.bp_addr = (unsigned long long)&marker;
	attr.bp_len = HW_BREAKPOINT_LEN_8;
	attr.bp_type = HW_BREAKPOINT_W;

	hwbp_events = register_wide_hw_breakpoint(&attr, hwbp_handler, NULL);
	if (IS_ERR((void *)hwbp_events)) {
		int ret = PTR_ERR((void *)hwbp_events);
		pr_err("StackWatch: Failed to register wide hw breakpoint: %d\n", ret);
		return ret;
	}

	INIT_WORK(&myworker.work, setup_hwbp_work_fn);

	return 0;
}

void hwbp_cleanup(void)
{
	if (!hwbp_events)
		return;

	/* Ensure all HWBPs are disarmed first */
	hwbp_disarm_all();

	unregister_wide_hw_breakpoint(hwbp_events);
	hwbp_events = NULL;
}

/* IRQ-safe functions using minimal breakpoint structures */
int hwbp_arm_all(unsigned long addr)
{
	struct perf_event *bp;
	unsigned long flags;
	int cpu;

	if (!addr) {
		pr_err("StackWatch: Invalid address for arming HWBP\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&hwbp_lock, flags);

	/* Check if already armed - only need to check one CPU since all share same addr */
	bp = *this_cpu_ptr(hwbp_events);
	if (bp->attr.bp_addr != 0 &&
	    bp->attr.bp_addr != (unsigned long)&marker && // installted
	    addr != (unsigned long)&marker) { //restore
		spin_unlock_irqrestore(&hwbp_lock, flags);
		return -EBUSY;
	}

	/* Update address in all minimal breakpoint structures */
	for_each_possible_cpu(cpu) {
		bp = *per_cpu_ptr(hwbp_events, cpu);
		WRITE_ONCE(bp->attr.bp_addr, addr);
	}

	WRITE_ONCE(myworker.original_cpu, smp_processor_id());

	spin_unlock_irqrestore(&hwbp_lock, flags);
	wmb();

	/* Then install on all CPUs */
	/* Run on current CPU directly */
	setup_hwbp_on_cpu(NULL);

	queue_work(system_highpri_wq, &myworker.work);
	return 0;
}

void hwbp_disarm_all(void)
{
	pr_info("StackWatch: Disarming all HWBPs\n");
	hwbp_arm_all((unsigned long)&marker);
	pr_info("StackWatch: All HWBPs disarmed\n");
}

void hwbp_addr_show(void)
{
	struct perf_event *bp;

	bp = *this_cpu_ptr(hwbp_events);
	pr_info("StackWatch: HWBP info test - bp_addr: 0x%llx\n", bp->attr.bp_addr);
}

void hwbp_addr_test(void)
{
	struct perf_event *bp;

	bp = *this_cpu_ptr(hwbp_events);
	volatile long *test_ptr = (volatile long *)bp->attr.bp_addr;
	*test_ptr = 0x12345678; // This should trigger immediately
}