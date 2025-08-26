// SPDX-License-Identifier: GPL-2.0

#include "linux/kern_levels.h"
#include <asm/hw_breakpoint.h>
#include <linux/hw_breakpoint.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/perf_event.h>
#include <linux/sched/debug.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/stacktrace.h>

#include "kstackwatch.h"

#define MAX_STACK_ENTRIES 64

struct perf_event *__percpu *watch_events;
struct ksw_config *watch_config;
static DEFINE_SPINLOCK(watch_lock);

static unsigned long long watch_holder;

static struct watch_worker {
	struct work_struct work;
	/*
	 * caller of watch_on(), invoke ksw_watch_on_local_cpu()
	 * directly, mark it to skip the later SMP call
	 */
	int original_cpu;
} myworker;

static void ksw_watch_on_local_cpu(void *useless);

static DEFINE_PER_CPU(call_single_data_t,
		      watch_csd) = CSD_INIT(ksw_watch_on_local_cpu, NULL);

static void ksw_watch_handler(struct perf_event *bp,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	pr_err("========== KStackWatch: Caught stack corruption =======\n");
	pr_err("KSW: config %s\n", watch_config->config_str);
	show_regs(regs);
	pr_err("========== KStackWatch End ==========\n");

	if (panic_on_catch)
		panic("KSW: Stack corruption detected");
}

/*
 * set up watchon current CPU
 * addr and len updated by ksw_watch_on() already
 */
static void ksw_watch_on_local_cpu(void *useless)
{
	struct perf_event *bp;
	int cpu = smp_processor_id();
	int ret;

	bp = *per_cpu_ptr(watch_events, cpu);
	if (!bp)
		return;

	ret = hw_breakpoint_arch_parse(bp, &bp->attr, counter_arch_bp(bp));
	if (ret) {
		pr_err("KSW: failed to validate HWBP for CPU %d ret %d\n", cpu,
		       ret);
		return;
	}
	ret = arch_reinstall_hw_breakpoint(bp);
	if (ret) {
		pr_err("KSW: failed to reinstall HWBP on CPU %d ret %d\n", cpu,
		       ret);
		return;
	}

	if (bp->attr.bp_addr == (unsigned long)&watch_holder) {
		pr_info("KSW: watch off CPU %d\n", cpu);
	} else {
		pr_info("KSW: watch on CPU %d at 0x%px (len %llu)\n", cpu,
			(void *)bp->attr.bp_addr, bp->attr.bp_len);
	}
}

static void ksw_watch_on_work_fn(struct work_struct *work)
{
	struct watch_worker *worker =
		container_of(work, struct watch_worker, work);
	int original_cpu = READ_ONCE(worker->original_cpu);
	int local_cpu = smp_processor_id();
	call_single_data_t *csd;
	int cpu;

	for_each_online_cpu(cpu) {
		if (cpu == original_cpu)
			continue;
		if (cpu == local_cpu)
			continue;
		csd = &per_cpu(watch_csd, cpu);
		smp_call_function_single_async(cpu, csd);
	}
	ksw_watch_on_local_cpu(NULL);
}

int ksw_watch_init(struct ksw_config *config)
{
	struct perf_event_attr attr;

	hw_breakpoint_init(&attr);
	attr.bp_addr = (unsigned long)&watch_holder;
	attr.bp_len = HW_BREAKPOINT_LEN_8;
	attr.bp_type = HW_BREAKPOINT_W;
	watch_events =
		register_wide_hw_breakpoint(&attr, ksw_watch_handler, NULL);
	if (IS_ERR((void *)watch_events)) {
		int ret = PTR_ERR((void *)watch_events);

		pr_err("KSW: failed to register wide hw breakpoint: %d\n", ret);
		return ret;
	}

	INIT_WORK(&myworker.work, ksw_watch_on_work_fn);
	watch_config = config;
	pr_info("KSW: watch inited\n");
	return 0;
}

void ksw_watch_exit(void)
{
	unregister_wide_hw_breakpoint(watch_events);
	watch_events = NULL;

	pr_info("KSW: watch exited\n");
}

int ksw_watch_on(u64 watch_addr, u64 watch_len)
{
	struct perf_event *bp;
	unsigned long flags;
	int cpu;

	if (!watch_addr) {
		pr_err("KSW: invalid address for arming HWBP\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&watch_lock, flags);

	/*
	 * check if already watched
	 * only need to check one CPU since all share same addr
	 */
	bp = *this_cpu_ptr(watch_events);
	if (bp->attr.bp_addr != 0 &&
	    bp->attr.bp_addr != (unsigned long)&watch_holder && // installted
	    watch_addr != (unsigned long)&watch_holder) { //restore
		spin_unlock_irqrestore(&watch_lock, flags);
		return -EBUSY;
	}

	/*
	 * update address for all bp
	 * simplify the ksw_watch_on_local_cpu and work_fn
	 */
	for_each_possible_cpu(cpu) {
		bp = *per_cpu_ptr(watch_events, cpu);
		WRITE_ONCE(bp->attr.bp_addr, watch_addr);
		WRITE_ONCE(bp->attr.bp_len, watch_len);
	}

	WRITE_ONCE(myworker.original_cpu, smp_processor_id());

	spin_unlock_irqrestore(&watch_lock, flags);

	if (watch_addr == (unsigned long)&watch_holder)
		pr_info("KSW: watch off starting\n");
	else
		pr_info("KSW: watch on starting\n");

	queue_work(system_highpri_wq, &myworker.work);
	ksw_watch_on_local_cpu(NULL);
	return 0;
}

void ksw_watch_off(void)
{
	ksw_watch_on((unsigned long)&watch_holder, sizeof(watch_holder));
}

/* self debug function */
void ksw_watch_show(void)
{
	struct perf_event *bp;

	bp = *this_cpu_ptr(watch_events);
	pr_info("KSW: watch target bp_addr: 0x%px len:%llu\n",
		(void *)bp->attr.bp_addr, bp->attr.bp_len);
}

/* self debug function */
void ksw_watch_fire(void)
{
	struct perf_event *bp;
	char *ptr;

	bp = *this_cpu_ptr(watch_events);
	ptr = (char *)READ_ONCE(bp->attr.bp_addr);
	pr_warn("KSW: watch triggered immediately\n");
	*ptr = 0x42; // This should trigger immediately
}
