/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _STACKWATCH_H
#define _STACKWATCH_H

#include <linux/kprobes.h>
#include <linux/perf_event.h>

#define MAX_FUNC_NAME_LEN 64
#define MAX_CONFIG_STR_LEN 128
#define MAX_FRAME_SEARCH 128
#define MAX_STACK_WATCHES 8

/* Watch target types */
enum watch_type {
	WATCH_CANARY = 0, /* Original canary watching */
	WATCH_STACK_VAR, /* Stack offset from frame base */
};

/* Single watch configuration */
struct kstackwatch_config {
	/* function part */
	char function[MAX_FUNC_NAME_LEN];
	u16 instruction_offset;
	u16 depth;

	/* stack part */
	u16 stack_var_offset; /* Offset from rsp  */
	u16 stack_var_len; /* Watch size (1,2,4,8 bytes) */

	enum watch_type type;

	// save to show
	char config_str[MAX_CONFIG_STR_LEN];
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