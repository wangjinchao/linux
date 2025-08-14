/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _STACKWATCH_H
#define _STACKWATCH_H

#include <linux/kprobes.h>
#include <linux/perf_event.h>

#define MAX_FUNC_NAME_LEN 64
#define MAX_FRAME_SEARCH 128

/* Global state */
extern char target_function[MAX_FUNC_NAME_LEN];
extern bool monitoring_active;
extern bool panic_on_corruption;

/* Probe management - from core.c or separate probe.c if needed */
int setup_probes(const char *func_name, unsigned long long offset);
void cleanup_probes(void);

/* HWBP management - from hwbp.c */
int hwbp_init(void);
void hwbp_cleanup(void);
int hwbp_arm_all(unsigned long addr);
void hwbp_disarm_all(void);
void hwbp_addr_show(void);
void hwbp_addr_test(void);


#endif /* _STACKWATCH_H */
