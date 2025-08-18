// SPDX-License-Identifier: GPL-2.0
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

struct perf_event *__percpu *watch_events;
struct ksw_config *watch_config;

static unsigned long long marker;

/* Enhanced breakpoint handler with watch identification */
static void ksw_watch_handler(struct perf_event *bp,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	pr_emerg("========== KStackWatch: Caught stack corruption =======\n");
	pr_emerg("KSW: config %s\n", watch_config->config_str);
	show_regs(regs);
	pr_emerg("========== KStackWatch End ==========\n");
	mdelay(100);

	if (panic_on_catch)
		panic("KSW: Stack corruption detected");
}

/* Initialize hardware breakpoint  */
int ksw_watch_init(struct ksw_config *config)
{
	struct perf_event_attr attr;

	/* Initialize default breakpoint attributes */
	hw_breakpoint_init(&attr);
	attr.bp_addr = (unsigned long)&marker;
	attr.bp_len = HW_BREAKPOINT_LEN_8;
	attr.bp_type = HW_BREAKPOINT_W;
	watch_events =
		register_wide_hw_breakpoint(&attr, ksw_watch_handler, NULL);
	if (IS_ERR((void *)watch_events)) {
		int ret = PTR_ERR((void *)watch_events);

		pr_err("KSW: Failed to register wide hw breakpoint: %d\n", ret);
		return ret;
	}

	watch_config = config;
	pr_info("KSW: HWBP  initialized\n");
	return 0;
}

/* Cleanup hardware breakpoint  */
void ksw_watch_exit(void)
{
	unregister_wide_hw_breakpoint(watch_events);
	watch_events = NULL;

	pr_info("KSW: HWBP  cleaned up\n");
}
