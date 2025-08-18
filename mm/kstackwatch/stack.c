// SPDX-License-Identifier: GPL-2.0

#include <linux/stackprotector.h>
#include <linux/kprobes.h>
#include <asm/stacktrace.h>

#include "kstackwatch.h"

/* Find canary address in current stack frame */
static unsigned long __maybe_unused ksw_stack_find_canary(struct pt_regs *regs)
{
	unsigned long *stack_ptr, *stack_end;
	unsigned long expected_canary;
	unsigned int i;

	if (!regs || !regs->sp)
		return 0;

	stack_ptr = (unsigned long *)regs->sp;
	stack_end =
		(unsigned long *)current->stack + THREAD_SIZE / sizeof(long);
	expected_canary = current->stack_canary;

	for (i = 0; i < MAX_FRAME_SEARCH && &stack_ptr[i] < stack_end; i++) {
		if (stack_ptr[i] == expected_canary) {
			pr_info("KSW: Canary found i:%d 0x%px\n", i,
				&stack_ptr[i]);
			return (unsigned long)&stack_ptr[i];
		}
	}

	return 0;
}

/* Resolve stack offset to actual address */
static unsigned long __maybe_unused ksw_stack_resolve_offset(struct pt_regs *regs,
					      s64 local_var_offset)
{
	unsigned long stack_base;
	unsigned long target_addr;

	if (!regs)
		return 0;

	/* Use stack pointer as base for offset calculation */
	stack_base = regs->sp;
	target_addr = stack_base + local_var_offset;

	pr_info("KSW: %s sp:0x%lx offset: %llx, target: 0x%lx\n", __func__,
		stack_base, local_var_offset, target_addr);

	return target_addr;
}

/* Validate that address is within current stack bounds */
static int __maybe_unused ksw_stack_validate_addr(unsigned long addr, size_t size)
{
	unsigned long stack_start, stack_end;

	if (!addr || !size)
		return -EINVAL;

	stack_start = (unsigned long)current->stack;
	stack_end = stack_start + THREAD_SIZE;

	if (addr < stack_start || (addr + size) > stack_end) {
		pr_warn("KSW: Address 0x%lx (size %zu) outside stack bounds [0x%lx-0x%lx]\n",
			addr, size, stack_start, stack_end);
		return -ERANGE;
	}

	return 0;
}

/* Setup hardware breakpoints for active watches */
static int __maybe_unused ksw_stack_prepare_watch(struct pt_regs *regs,
				   struct ksw_config *config, u64 *watch_addr,
				   u64 *watch_len)
{
	u64 addr;
	u64 len;

	/* Resolve addresses for all active watches */
	switch (config->type) {
	case WATCH_CANARY:
		addr = ksw_stack_find_canary(regs);
		len = 8;
		break;

	case WATCH_LOCAL_VAR:
		addr = ksw_stack_resolve_offset(regs, config->local_var_offset);
		if (!addr) {
			pr_err("KSW: Invalid stack var offset %u\n",
			       config->local_var_offset);
			return -EINVAL;
		}
		if (ksw_stack_validate_addr(addr, config->local_var_len)) {
			pr_err("KSW: Invalid stack var len %u\n",
			       config->local_var_len);
		}
		len = config->local_var_len;
		break;

	default:
		pr_warn("KSW: Unknown watch type %d\n", config->type);
		return -EINVAL;
	}

	*watch_addr = addr;
	*watch_len = len;
	return 0;
}
