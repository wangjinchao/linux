// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/printk.h>

#include "kstackwatch.h"

static struct perf_event *__percpu *watch_events;

static unsigned long watch_holder;

static struct perf_event_attr watch_attr;

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

	return 0;
}

void ksw_watch_exit(void)
{
	unregister_wide_hw_breakpoint(watch_events);
	watch_events = NULL;
}
