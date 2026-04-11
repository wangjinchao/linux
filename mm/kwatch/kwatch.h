/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_KWATCH_H
#define _MM_KWATCH_H

#include <linux/fprobe.h>
#include <linux/kprobes.h>
#include <linux/kwatch_types.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "mode/mode.h"
#define MAX_CONFIG_STR_LEN 512

struct kwatch_watchpoint {
	struct perf_event *__percpu *event;
	call_single_data_t __percpu *csd;
	struct perf_event_attr attr;
	struct llist_node node; // for atomic watch_on and off
	struct list_head list; // for cpu online and offline
};

struct kwatch_config {
	char *func_name;
	u16 func_offset;
	u16 depth;
	u16 sp_offset;
	u16 max_watch;

	/* mode */
	enum kwatch_mode_type mode_type;
	const struct kwatch_mode_ops *mode_ops;
	void *mode_config;
};

const struct kwatch_config *kwatch_get_config(void);
int kwatch_hwbp_prealloc(void);
void kwatch_hwbp_free(void);
int kwatch_hwbp_get(struct kwatch_watchpoint **out_wp);
void kwatch_hwbp_on(struct kwatch_watchpoint *wp, ulong addr, u16 len,
		    enum kwatch_access_type type);
int kwatch_hwbp_put(struct kwatch_watchpoint *wp);

int kwatch_probe_start(void);
void kwatch_probe_stop(void);
void kwatch_ctx_release(void);
void kwatch_action_trigger(struct perf_event *bp, struct pt_regs *regs);
bool is_kwatch_handler(struct perf_event *event);

#endif /* _MM_KWATCH_H */
