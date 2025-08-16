/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KSTACKWATCH_H
#define _KSTACKWATCH_H

#include <linux/kprobes.h>
#include <linux/perf_event.h>

#define MAX_FUNC_NAME_LEN 64
#define MAX_CONFIG_STR_LEN 128
#define MAX_FRAME_SEARCH 128
#define MAX_STACK_WATCHES 8

/* Watch target types */
enum watch_type {
	WATCH_CANARY = 0, /* canary placed by compiler */
	WATCH_LOCAL_VAR, /* local var defined by code */
};

/* Single watch configuration */
struct ksw_config {
	/* function part */
	char function[MAX_FUNC_NAME_LEN];
	u16 instruction_offset;
	u16 depth;

	/* stack part, useless for canary watch */
	/* offset from rsp at function+instruction_offset */
	u16 local_var_offset;

	/*
	 * local var size (1,2,4,8 bytes)
	 * it will be the watching len
	 */
	u16 local_var_len;

	/* easy for understand*/
	enum watch_type type;

	/* save to show */
	char config_str[MAX_CONFIG_STR_LEN];
};

/* Global state */
extern bool panic_on_catch;
void ksw_show_config(const char *lvl);

/* stack management */
int ksw_stack_init(struct ksw_config *config);
void ksw_stack_exit(void);

/* watch management */
int ksw_watch_init(void);
void ksw_watch_exit(void);
int ksw_watch_on(u64 watch_addr, u64 watch_len);
void ksw_watch_off(void);
void ksw_watch_show(void);
void ksw_watch_fire(void);

#endif /* _KSTACKWATCH_H */
