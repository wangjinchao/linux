// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include "kwatch.h"

int kwatch_deref_resolve(const struct kwatch_config *cfg, struct pt_regs *regs,
			 unsigned long *out_addr, u16 *out_len)
{
	unsigned long addr = 0;
	int i;

	/* 1. Resolve the Base Anchor */
	if (cfg->base == KWATCH_BASE_STACK) {
		addr = kernel_stack_pointer(regs);
		if (unlikely(!addr))
			return -EINVAL;
	} else if (cfg->base >= KWATCH_BASE_ARG1 &&
		   cfg->base <= KWATCH_BASE_ARG6) {
		int arg_idx = cfg->base - KWATCH_BASE_ARG1;

		addr = regs_get_kernel_argument(regs, arg_idx);
	} else if (cfg->base == KWATCH_BASE_GLOBAL_SYM) {
		/* Zero-latency load of the static symbol location */
		addr = cfg->sym_addr;
	} else {
		return -EINVAL;
	}

	/* 2. Fast-Path Optimization: Local Stack Offset Calculation */
	if (cfg->base == KWATCH_BASE_STACK && cfg->offset_count == 1) {
		*out_addr = addr + cfg->offsets[0];
		*out_len = cfg->watch_len;
		return 0;
	}

	/* 3. The Pointer-Chasing FSM */
	for (i = 0; i < cfg->offset_count; i++) {
		addr += cfg->offsets[i];

		if (i < cfg->offset_count - 1) {
			unsigned long next_addr;

			/* Dynamically read the pointer contents at runtime */
			if (get_kernel_nofault(next_addr, (unsigned long *)addr))
				return -EFAULT;

			addr = next_addr;
		}
	}

	/* Enforce strict Kernel-Space boundary */
	if (unlikely(addr < TASK_SIZE_MAX))
		return -EINVAL;

	*out_addr = addr;
	*out_len = cfg->watch_len;
	return 0;
}
