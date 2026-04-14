/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _MM_KWATCH_H
#define _MM_KWATCH_H

#include <linux/fprobe.h>
#include <linux/kprobes.h>
#include <linux/kwatch_types.h>
#include <linux/perf_event.h>
#include <linux/sched.h>
#include <linux/types.h>

#define MAX_CONFIG_STR_LEN 512

struct kwatch_watchpoint {
	struct perf_event *__percpu *event;
	call_single_data_t __percpu *csd;
	struct perf_event_attr attr;
	struct llist_node node; // for atomic get/put
	struct list_head list; // for cpu online and offline

	/* Async Reclaim State */
	atomic_t pending_ipis;
};

enum kwatch_access_type {
	KWATCH_ACCESS_W,
	KWATCH_ACCESS_R,
	KWATCH_ACCESS_RW,
	KWATCH_ACCESS_X,
};
struct kwatch_config {
	u16 max_watch;
	char func_name[KSYM_NAME_LEN];
	u16 func_offset;
	u16 depth;
	enum kwatch_access_type access_type;
};

int kwatch_hwbp_prealloc(u16 max_watch);
void kwatch_hwbp_free(void);
int kwatch_hwbp_get(struct kwatch_watchpoint **out_wp);
void kwatch_hwbp_arm(struct kwatch_watchpoint *wp, ulong addr, u16 len,
		     enum kwatch_access_type type);
int kwatch_hwbp_put(struct kwatch_watchpoint *wp);

int kwatch_probe_start(struct kwatch_config *cfg);
void kwatch_probe_stop(void);
void kwatch_tsk_ctx_reset(void);
bool kwatch_is_handler(struct perf_event *event);
bool kwatch_probe_in_trampoline(unsigned long ip);

#endif /* _MM_KWATCH_H */
