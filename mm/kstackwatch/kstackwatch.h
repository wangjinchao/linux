/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KSTACKWATCH_H
#define _KSTACKWATCH_H

#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/types.h>

#define MAX_FUNC_NAME_LEN 64
#define MAX_CONFIG_STR_LEN 128
#define MAX_FRAME_SEARCH 128

/* Watch target types */
enum watch_type {
	WATCH_CANARY = 0, /* canary placed by compiler */
	WATCH_LOCAL_VAR, /* local var defined by code */
};

struct ksw_config {
	/* function part */
	char function[MAX_FUNC_NAME_LEN];
	u16 ip_offset;
	u16 depth;

	/* stack part, useless for canary watch */
	/* offset from rsp at function+ip_offset */
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

extern bool panic_on_catch;

/* stack management */
int ksw_stack_init(struct ksw_config *config);
void ksw_stack_exit(void);
int ksw_stack_init_fprobe(struct ksw_config *config);
void ksw_stack_exit_fprobe(void);

/* watch management */
int ksw_watch_init(struct ksw_config *config);
void ksw_watch_exit(void);
int ksw_watch_on(u64 watch_addr, u64 watch_len);
void ksw_watch_off(void);
void ksw_watch_show(void);
void ksw_watch_fire(void);

#endif /* _KSTACKWATCH_H */
