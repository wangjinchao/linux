/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Hardware breakpoint management for KStackWatch (enhanced multi-watch support)
 */

#include <linux/kprobes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sched/debug.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <asm/hw_breakpoint.h>
#include <linux/stacktrace.h>
#include <linux/delay.h>

#include "kstackwatch.h"

#define MAX_STACK_ENTRIES 64

struct perf_event *__percpu *hwbp_events;

static DEFINE_SPINLOCK(hwbp_lock);

static unsigned long long marker;

struct hwbp_worker {
	struct work_struct work;
	int original_cpu;
} myworker;

static void setup_hwbp_on_local_cpu(void *useless);

static DEFINE_PER_CPU(call_single_data_t,
		      hwbp_csd) = CSD_INIT(setup_hwbp_on_local_cpu, NULL);

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

/* Enhanced breakpoint handler with watch identification */
static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data,
			 struct pt_regs *regs)
{
	unsigned long entries[MAX_STACK_ENTRIES];
	int i, nr = 0;

	kstackwatch_resolve_trampolines();

#if IS_ENABLED(CONFIG_STACKTRACE)
	nr = stack_trace_save_regs(regs, entries, MAX_STACK_ENTRIES, 0);
	for (i = 0; i < nr; i++) {
		if (kstackwatch_should_ignore(entries[i])) {
			pr_info("KSW: Found rethook trampolines, ignoring hit\n");
			return;
		}
	}
#endif

	pr_emerg("========== KStackWatch: Caught stack corruption =======\n");
	ksw_show_config(KERN_EMERG);
	show_regs(regs);
	pr_emerg("========== KStackWatch End ==========\n");
	mdelay(100);

	if (panic_on_catch)
		panic("KSW: Stack corruption detected");
}

/* Setup single hardware breakpoint on current CPU */
static void setup_hwbp_on_local_cpu(void *useless)
{
	struct perf_event *bp;
	int cpu = smp_processor_id();
	int ret;

	bp = *per_cpu_ptr(hwbp_events, cpu);
	if (!bp)
		return;

	/* Update breakpoint address */
	ret = hw_breakpoint_arch_parse(bp, &bp->attr, counter_arch_bp(bp));
	if (ret) {
		pr_err("KSW: Failed to parse HWBP for CPU %d ret %d\n",
		       cpu, ret);
		return;
	}
	ret = arch_reinstall_hw_breakpoint(bp);
	if (ret) {
		pr_err("KSW: Failed to install HWBP on CPU %d ret %d\n",
		       cpu, ret);
		return;
	}

	if (bp->attr.bp_addr == (unsigned long)&marker) {
		pr_info("KSW: HWBP disarmed on CPU %d\n", cpu);
	} else {
		pr_info("KSW: HWBP armed on CPU %d at 0x%px ( len %llu)\n",
			cpu, (void *)bp->attr.bp_addr, bp->attr.bp_len);
	}
}

static void setup_hwbp_work_fn(struct work_struct *work)
{
	struct hwbp_worker *worker =
		container_of(work, struct hwbp_worker, work);
	int original_cpu = READ_ONCE(worker->original_cpu);
	int local_cpu = smp_processor_id();
	call_single_data_t *csd;
	int cpu;

	for_each_online_cpu(cpu) {
		if (cpu == original_cpu)
			continue;
		if (cpu == local_cpu)
			continue;
		csd = &per_cpu(hwbp_csd, cpu);
		smp_call_function_single_async(cpu, csd);
	}
	setup_hwbp_on_local_cpu(NULL);
}

/* Initialize hardware breakpoint  */
int ksw_watch_init(void)
{
	struct perf_event_attr attr;

	/* Initialize default breakpoint attributes */
	hw_breakpoint_init(&attr);
	attr.bp_addr = (unsigned long)&marker;
	attr.bp_len = HW_BREAKPOINT_LEN_8;
	attr.bp_type = HW_BREAKPOINT_W;
	hwbp_events = register_wide_hw_breakpoint(&attr, hwbp_handler, NULL);
	if (IS_ERR((void *)hwbp_events)) {
		int ret = PTR_ERR((void *)hwbp_events);
		pr_err("KSW: Failed to register wide hw breakpoint: %d\n",
		       ret);
		return ret;
	}

	/* Initialize work structure */
	INIT_WORK(&myworker.work, setup_hwbp_work_fn);

	pr_info("KSW: HWBP  initialized\n");
	return 0;
}

/* Cleanup hardware breakpoint  */
void ksw_watch_exit(void)
{
	unregister_wide_hw_breakpoint(hwbp_events);
	hwbp_events = NULL;

	pr_info("KSW: HWBP  cleaned up\n");
}

/* Legacy API: Arm single hardware breakpoint (backward compatibility) */
int ksw_watch_on(u64 watch_addr, u64 watch_len)
{
	struct perf_event *bp;
	unsigned long flags;
	int cpu;

	if (!watch_addr) {
		pr_err("KSW: Invalid address for arming HWBP\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&hwbp_lock, flags);

	/* Check if already armed - only need to check one CPU since all share same addr */
	bp = *this_cpu_ptr(hwbp_events);
	if (bp->attr.bp_addr != 0 &&
	    bp->attr.bp_addr != (unsigned long)&marker && // installted
	    watch_addr != (unsigned long)&marker) { //restore
		spin_unlock_irqrestore(&hwbp_lock, flags);
		return -EBUSY;
	}

	/* Update address in all minimal breakpoint structures */
	for_each_possible_cpu(cpu) {
		bp = *per_cpu_ptr(hwbp_events, cpu);
		WRITE_ONCE(bp->attr.bp_addr, watch_addr);
		WRITE_ONCE(bp->attr.bp_len, watch_len);
	}

	WRITE_ONCE(myworker.original_cpu, smp_processor_id());

	spin_unlock_irqrestore(&hwbp_lock, flags);
	wmb();

	/* Then install on all CPUs */
	/* Run on current CPU directly */
	queue_work(system_highpri_wq, &myworker.work);
	setup_hwbp_on_local_cpu(NULL);
	return 0;
}

void ksw_watch_off(void)
{
	pr_info("KSW: Disarming all HWBPs\n");
	ksw_watch_on((unsigned long)&marker, sizeof(marker));
	pr_info("KSW: All HWBPs disarmed\n");
}

/* Debug functions */
void ksw_watch_show(void)
{
	struct perf_event *bp;

	bp = *this_cpu_ptr(hwbp_events);
	pr_info("KSW: HWBP info test - bp_addr: 0x%px len:%llu\n",
		(void *)bp->attr.bp_addr, bp->attr.bp_len);
}

void ksw_watch_fire(void)
{
	struct perf_event *bp;
	char *ptr;

	bp = *this_cpu_ptr(hwbp_events);
	ptr = (char *)READ_ONCE(bp->attr.bp_addr);
	*ptr = 0x42; // This should trigger immediately
}