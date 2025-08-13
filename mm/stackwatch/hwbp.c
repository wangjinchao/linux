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

/* Minimal perf_event structure for hardware breakpoints */
struct stackwatch_bp {
	struct perf_event event;
	struct arch_hw_breakpoint hw_info;
};

/* Per-CPU minimal breakpoint storage */
static struct stackwatch_bp __percpu *hwbp_storage;
static DEFINE_SPINLOCK(hwbp_lock);

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

/* Initialize minimal breakpoint structure */
static int init_stackwatch_bp(struct stackwatch_bp *bp)
{
	struct perf_event *event = &bp->event;
	int ret;

	/* Initialize only essential fields */
	memset(bp, 0, sizeof(*bp));

	/* Set up perf_event attributes */
	event->attr.bp_addr = 0; /* Will be set later */
	event->attr.bp_type = HW_BREAKPOINT_W;
	event->attr.bp_len = HW_BREAKPOINT_LEN_8;
	event->overflow_handler = hwbp_handler;

	/* Copy arch-specific storage - hw.info is by value, not pointer */
	event->hw.info = bp->hw_info;

	/* Initialize arch-specific info - let arch code handle this */
	ret = hw_breakpoint_arch_parse(event, &event->attr, &bp->hw_info);
	if (ret) {
		pr_err("StackWatch: Failed to parse breakpoint attributes: %d\n",
		       ret);
		return ret;
	}

	return 0;
}

/* Per-CPU HWBP setup - just install minimal event */
static void setup_hwbp_on_cpu(void *data)
{
	struct stackwatch_bp *bp;
	int cpu = smp_processor_id();

	bp = per_cpu_ptr(hwbp_storage, cpu);
	if (!bp || !bp->event.attr.bp_addr)
		return;

	/* Use arch function that doesn't sleep */
	if (arch_install_hw_breakpoint(&bp->event) == 0) {
		pr_debug("StackWatch: HWBP armed on CPU %d at 0x%llx\n", cpu,
			 (unsigned long long)bp->event.attr.bp_addr);
	} else {
		pr_warn("StackWatch: Failed to install HWBP on CPU %d\n", cpu);
	}
}

/* Per-CPU HWBP cleanup - just uninstall */
static void cleanup_hwbp_on_cpu(void *data)
{
	struct stackwatch_bp *bp;
	int cpu = smp_processor_id();

	bp = per_cpu_ptr(hwbp_storage, cpu);
	if (bp && bp->event.attr.bp_addr) {
		/* Use arch function that doesn't sleep */
		arch_uninstall_hw_breakpoint(&bp->event);
		pr_debug("StackWatch: HWBP disarmed on CPU %d\n", cpu);
	}
}

int hwbp_init(void)
{
	struct stackwatch_bp *bp;
	int cpu, ret;

	/* Allocate per-CPU minimal breakpoint storage */
	hwbp_storage = alloc_percpu(struct stackwatch_bp);
	if (!hwbp_storage)
		return -ENOMEM;

	/* Initialize minimal breakpoint structures for all CPUs */
	for_each_possible_cpu(cpu) {
		bp = per_cpu_ptr(hwbp_storage, cpu);
		ret = init_stackwatch_bp(bp);
		if (ret) {
			pr_err("StackWatch: Failed to init breakpoint for CPU %d: %d\n",
			       cpu, ret);
			hwbp_cleanup();
			return ret;
		}
	}

	return 0;
}

void hwbp_cleanup(void)
{
	if (!hwbp_storage)
		return;

	/* Ensure all HWBPs are disarmed first */
	hwbp_disarm_all();

	free_percpu(hwbp_storage);
	hwbp_storage = NULL;
}

/* IRQ-safe functions using minimal breakpoint structures */
int hwbp_arm_all(unsigned long addr)
{
	struct stackwatch_bp *bp;
	unsigned long flags;
	int cpu;
	int ret;

	if (!addr)
		return -EINVAL;

	spin_lock_irqsave(&hwbp_lock, flags);

	/* Check if already armed - only need to check one CPU since all share same addr */
	bp = per_cpu_ptr(hwbp_storage, 0);
	if (bp->event.attr.bp_addr != 0) {
		spin_unlock_irqrestore(&hwbp_lock, flags);
		return -EBUSY;
	}

	/* Update address in all minimal breakpoint structures */
	for_each_possible_cpu(cpu) {
		bp = per_cpu_ptr(hwbp_storage, cpu);
		bp->event.attr.bp_addr = addr;
		/* Reparse arch-specific info with new address */
		ret = hw_breakpoint_arch_parse(&bp->event, &bp->event.attr,
					       &bp->hw_info);
		if (ret) {
			pr_err("StackWatch: Failed to parse breakpoint for CPU %d: %d\n",
			       cpu, ret);
			/* Reset all addresses on failure */
			for_each_possible_cpu(cpu) {
				bp = per_cpu_ptr(hwbp_storage, cpu);
				bp->event.attr.bp_addr = 0;
			}
			spin_unlock_irqrestore(&hwbp_lock, flags);
			return ret;
		}
		/* Copy updated hw_info back to event */
		bp->event.hw.info = bp->hw_info;
	}

	spin_unlock_irqrestore(&hwbp_lock, flags);

	/* Then install on all CPUs */
	on_each_cpu(setup_hwbp_on_cpu, NULL, 0);
	return 0;
}

void hwbp_disarm_all(void)
{
	struct stackwatch_bp *bp;
	unsigned long flags;
	int cpu;

	/* Use non-waiting version to avoid sleeping in IRQ context */
	on_each_cpu(cleanup_hwbp_on_cpu, NULL, 0);

	spin_lock_irqsave(&hwbp_lock, flags);
	/* Clear addresses after disarming */
	for_each_possible_cpu(cpu) {
		bp = per_cpu_ptr(hwbp_storage, cpu);
		bp->event.attr.bp_addr = 0;
	}
	spin_unlock_irqrestore(&hwbp_lock, flags);
}
