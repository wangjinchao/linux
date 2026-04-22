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
#define MAX_DEREF_CHAIN 4

struct kwatch_watchpoint {
	struct perf_event *__percpu *event;
	call_single_data_t __percpu *csd_arm;
	call_single_data_t __percpu *csd_disarm;
	struct perf_event_attr attr;
	struct llist_node node; // for atomic get/put
	struct list_head list; // for cpu online and offline

	/* Async disarm State */
	atomic_t pending_ipis;
	atomic_t refcount;

	unsigned long func_start;
	unsigned long func_end;

};

enum kwatch_access_type {
	KWATCH_ACCESS_W,
	KWATCH_ACCESS_R,
	KWATCH_ACCESS_RW,
	KWATCH_ACCESS_X,
};

enum kwatch_base_type {
	KWATCH_BASE_STACK,
	KWATCH_BASE_GLOBAL_SYM,
	KWATCH_BASE_ARG1,
	KWATCH_BASE_ARG2,
	KWATCH_BASE_ARG3,
	KWATCH_BASE_ARG4,
	KWATCH_BASE_ARG5,
	KWATCH_BASE_ARG6,
};

struct kwatch_config {
	u16 max_watch;
	char func_name[KSYM_NAME_LEN];
	u16 func_offset;
	u16 depth;
	enum kwatch_access_type access_type;
	u16 watch_len;

	/* Unified Deref Engine State */
	enum kwatch_base_type base;
	char sym_name[KSYM_NAME_LEN];
	unsigned long sym_addr;
	long offsets[MAX_DEREF_CHAIN];
	u8 offset_count;
};

int kwatch_hwbp_prealloc(u16 max_watch, unsigned long func_start, unsigned long func_end);
void kwatch_hwbp_free(void);
int kwatch_hwbp_get(struct kwatch_watchpoint **out_wp);
void kwatch_hwbp_arm(struct kwatch_watchpoint *wp, unsigned long addr, u16 len,
		     enum kwatch_access_type type);
int kwatch_hwbp_put(struct kwatch_watchpoint *wp);

int kwatch_probe_start(struct kwatch_config *cfg);
void kwatch_probe_stop(void);
void kwatch_tsk_ctx_reset(void);
bool kwatch_is_handler(struct perf_event *event);
bool kwatch_probe_in_trampoline(unsigned long ip);

int kwatch_deref_resolve(const struct kwatch_config *cfg, struct pt_regs *regs,
			 unsigned long *out_addr, u16 *out_len);

#endif /* _MM_KWATCH_H */
