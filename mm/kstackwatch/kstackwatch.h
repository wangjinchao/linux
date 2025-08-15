/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _STACKWATCH_H
#define _STACKWATCH_H

#include <linux/kprobes.h>
#include <linux/perf_event.h>

#define MAX_FUNC_NAME_LEN 64
#define MAX_TYPE_STR_LEN 32
#define MAX_FRAME_SEARCH 128
#define MAX_STACK_WATCHES 8

/* Watch target types */
enum watch_type {
	WATCH_CANARY = 0, /* Original canary watching */
	WATCH_STACK_OFFSET, /* Stack offset from frame base */
	WATCH_LOCAL_VAR, /* Named local variable (future) */
};

/* Single watch configuration */
struct kstackwatch_config {
	enum watch_type type;
	char function[MAX_FUNC_NAME_LEN];
	u64 instruction_offset;

	// save to show
	char type_str[MAX_TYPE_STR_LEN];

	/* For WATCH_STACK_OFFSET, useless for canary type */
	struct {
		s64 offset; /* Offset from stack base, assert(offset<=0)  */
		u64 len; /* Watch size (1,2,4,8 bytes) */
	} stack_var;
};

/* Global state */
extern bool panic_on_corruption;
void show_config(void);

/* Probe management */
int setup_probes(struct kstackwatch_config *config);
void cleanup_probes(void);

/* HWBP management */
int hwbp_init(void);
void hwbp_cleanup(void);
int hwbp_arm_all(u64 watch_addr, u64 watch_len);
void hwbp_disarm_all(void);
void hwbp_addr_show(void);
void hwbp_addr_test(void);


#endif /* _STACKWATCH_H */