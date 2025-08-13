/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Hardware breakpoint management for StackWatch (minimal approach)
 */

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <asm/hw_breakpoint.h>
#include "stackwatch.h"

/* Per-CPU minimal breakpoint storage */
static struct perf_event *__percpu *hwbp_events;
static DEFINE_SPINLOCK(hwbp_lock);

static unsigned long long marker;

/* Hardware breakpoint callback - corruption detected! */
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data,
			 struct pt_regs *regs)
{
	pr_alert("STACKWATCH: Stack corruption detected!\n");
	pr_alert("  Function: %s\n", target_function);
	pr_alert("  PID: %d (%s)\n", current->pid, current->comm);
	pr_alert("  Corruption at IP: 0x%lx\n", regs->ip);

	/* Dump stack trace */
	dump_stack();

	/* Optionally trigger panic for post-mortem analysis */
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
	pr_info("StackWatch: HWBP armed on CPU %d at 0x%llx\n", cpu,
		(unsigned long long)bp->attr.bp_addr);
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
		pr_err("register_wide_hw_breakpoint fail with %d\n", ret);
		return ret;
	}

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

static void setup_hwbp_work_fn(struct work_struct *work)
{
	smp_call_function(setup_hwbp_on_cpu, NULL, 1);
}

static DECLARE_WORK(setup_hwbp_work, setup_hwbp_work_fn);

/* IRQ-safe functions using minimal breakpoint structures */
int hwbp_arm_all(unsigned long addr)
{
	struct perf_event *bp;
	unsigned long flags;
	int cpu;

	if (!addr) {
		pr_err("hwbp_arm_all fail with invalid addr.\n");
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
		bp->attr.bp_addr = addr;
	}

	spin_unlock_irqrestore(&hwbp_lock, flags);
	wmb();

	/* Then install on all CPUs */
	/* Run on current CPU directly */
	setup_hwbp_on_cpu(NULL);

	queue_work(system_highpri_wq, &setup_hwbp_work);
	return 0;
}

void hwbp_disarm_all(void)
{
	hwbp_arm_all((unsigned long)&marker);
}

void hwbp_info_test(void)
{
	struct perf_event *bp;

	bp = *this_cpu_ptr(hwbp_events);
	pr_info("hwbp_info_test bp->attr.bp_addr: 0x%llx\n", bp->attr.bp_addr);
}

void hwbp_fire_test(void)
{
	struct perf_event *bp;

	bp = *this_cpu_ptr(hwbp_events);
	volatile long *test_ptr = (volatile long *)bp->attr.bp_addr;
	*test_ptr = 0x12345678; // This should trigger immediately
}