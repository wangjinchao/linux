// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpuhotplug.h>
#include <linux/hw_breakpoint.h>
#include <linux/irqflags.h>
#include <linux/perf_event.h>
#include <linux/printk.h>

#include "kstackwatch.h"

static struct perf_event *__percpu *watch_events;

static ulong watch_holder;
static atomic_long_t watched_addr = ATOMIC_LONG_INIT((ulong)&watch_holder);

static struct perf_event_attr watch_attr;

static void ksw_watch_on_local_cpu(void *info);

static DEFINE_PER_CPU(call_single_data_t,
		      watch_csd) = CSD_INIT(ksw_watch_on_local_cpu, NULL);

bool panic_on_catch;
module_param(panic_on_catch, bool, 0644);
MODULE_PARM_DESC(panic_on_catch, "panic immediately on corruption catch");
static void ksw_watch_handler(struct perf_event *bp,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	pr_err("========== KStackWatch: Caught stack corruption =======\n");
	pr_err("config %s\n", ksw_get_config()->config_str);
	dump_stack();
	pr_err("=================== KStackWatch End ===================\n");

	if (panic_on_catch)
		panic("Stack corruption detected");
}

static void ksw_watch_on_local_cpu(void *data)
{
	struct perf_event *bp;
	ulong flags;
	int cpu;
	int ret;

	local_irq_save(flags);
	cpu = raw_smp_processor_id();
	bp = *per_cpu_ptr(watch_events, cpu);
	if (!bp) {
		local_irq_restore(flags);
		return;
	}

	ret = modify_wide_hw_breakpoint_local(bp, &watch_attr);
	local_irq_restore(flags);

	if (ret) {
		pr_err("failed to reinstall HWBP on CPU %d ret %d\n", cpu,
		       ret);
		return;
	}
}

static int ksw_cpu_online(unsigned int cpu)
{
	struct perf_event *bp;

	bp = perf_event_create_kernel_counter(&watch_attr, cpu, NULL,
					      ksw_watch_handler, NULL);
	if (IS_ERR(bp)) {
		pr_err("Failed to create watch on CPU %d: %ld\n", cpu,
		       PTR_ERR(bp));
		return PTR_ERR(bp);
	}

	per_cpu(*watch_events, cpu) = bp;
	per_cpu(watch_csd, cpu) = CSD_INIT(ksw_watch_on_local_cpu, NULL);
	return 0;
}

static int ksw_cpu_offline(unsigned int cpu)
{
	struct perf_event *bp = per_cpu(*watch_events, cpu);

	if (bp)
		unregister_hw_breakpoint(bp);
	return 0;
}

static void __ksw_watch_target(ulong addr, u16 len)
{
	int cpu;
	call_single_data_t *csd;

	watch_attr.bp_addr = addr;
	watch_attr.bp_len = len;

	/* ensure watchpoint update is visible to other CPUs before IPI */
	smp_wmb();

	for_each_online_cpu(cpu) {
		if (cpu == raw_smp_processor_id()) {
			ksw_watch_on_local_cpu(NULL);
		} else {
			csd = &per_cpu(watch_csd, cpu);
			smp_call_function_single_async(cpu, csd);
		}
	}
}

static int ksw_watch_target(ulong old_addr, ulong new_addr, u16 watch_len)
{
	if (atomic_long_cmpxchg(&watched_addr, old_addr, new_addr) != old_addr)
		return -EINVAL;
	__ksw_watch_target(new_addr, watch_len);
	return 0;
}

int ksw_watch_on(ulong watch_addr, u16 watch_len)
{
	return ksw_watch_target((ulong)&watch_holder, watch_addr, watch_len);
}

int ksw_watch_off(ulong watch_addr, u16 watch_len)
{
	return ksw_watch_target(watch_addr, (ulong)&watch_holder, watch_len);
}

int ksw_watch_init(void)
{
	int ret;

	hw_breakpoint_init(&watch_attr);
	watch_attr.bp_addr = (unsigned long)&watch_holder;
	watch_attr.bp_len = sizeof(watch_holder);
	watch_attr.bp_type = HW_BREAKPOINT_W;
	watch_events = register_wide_hw_breakpoint(&watch_attr,
						   ksw_watch_handler,
						   NULL);
	if (IS_ERR(watch_events)) {
		ret = PTR_ERR(watch_events);
		pr_err("failed to register wide hw breakpoint: %d\n", ret);
		return ret;
	}

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"kstackwatch:online", ksw_cpu_online,
					ksw_cpu_offline);
	if (ret < 0) {
		unregister_wide_hw_breakpoint(watch_events);
		pr_err("Failed to register CPU hotplug notifier\n");
		return ret;
	}

	return 0;
}

void ksw_watch_exit(void)
{
	unregister_wide_hw_breakpoint(watch_events);
	watch_events = NULL;
}

/* self debug function */
void ksw_watch_show(void)
{
	pr_info("watch target bp_addr: 0x%llx len:%llu\n", watch_attr.bp_addr,
		watch_attr.bp_len);
}
EXPORT_SYMBOL_GPL(ksw_watch_show);

/* self debug function */
void ksw_watch_fire(void)
{
	char *ptr = (char *)watch_attr.bp_addr;

	pr_warn("watch triggered immediately\n");
	*ptr = 0x42; // This should trigger immediately for any bp_len
}
EXPORT_SYMBOL_GPL(ksw_watch_fire);
