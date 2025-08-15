/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stack watching with support for canary and offset watching
 */

#include <linux/stackprotector.h>
#include <linux/kprobes.h>
#include <asm/stacktrace.h>

#include "kstackwatch.h"

/* Per-CPU watching state */
static DEFINE_PER_CPU(int, monitor_depth);
struct kstackwatch_config *probe_config;

/* Find canary address in current stack frame */
unsigned long find_canary_address(struct pt_regs *regs)
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

	pr_debug("KStackWatch: Expected canary: 0x%lx\n", expected_canary);

	for (i = 0; i < MAX_FRAME_SEARCH && &stack_ptr[i] < stack_end; i++) {
		if (stack_ptr[i] == expected_canary) {
			pr_debug("KStackWatch: Canary found at: 0x%p\n",
				 &stack_ptr[i]);
			return (unsigned long)&stack_ptr[i];
		}
	}

	return 0;
}

/* Resolve stack offset to actual address */
unsigned long resolve_stack_offset(struct pt_regs *regs, u64 offset)
{
	unsigned long stack_base;
	unsigned long target_addr;

	if (!regs)
		return 0;

	/* Use stack pointer as base for offset calculation */
	stack_base = regs->sp;
	target_addr = stack_base + offset;

	pr_debug(
		"KStackWatch: Stack base: 0x%lx, offset: %llu, target: 0x%lx\n",
		stack_base, offset, target_addr);

	return target_addr;
}

/* Validate that address is within current stack bounds */
int validate_stack_address(unsigned long addr, size_t size)
{
	unsigned long stack_start, stack_end;

	if (!addr || !size)
		return -EINVAL;

	stack_start = (unsigned long)current->stack;
	stack_end = stack_start + THREAD_SIZE;

	if (addr < stack_start || (addr + size) > stack_end) {
		pr_warn("KStackWatch: Address 0x%lx (size %zu) outside stack bounds [0x%lx-0x%lx]\n",
			addr, size, stack_start, stack_end);
		return -ERANGE;
	}

	return 0;
}

/* Setup hardware breakpoints for active watches */
static int parse_watch_info(struct pt_regs *regs,
			    struct kstackwatch_config *config, u64 *watch_addr,
			    u64 *watch_len)
{
	u64 addr;
	u64 len;

	/* Resolve addresses for all active watches */

	switch (config->type) {
	case WATCH_CANARY:
		addr = find_canary_address(regs);
		len = 8;
		break;

	case WATCH_STACK_OFFSET:
		addr = resolve_stack_offset(regs, config->stack_var.offset);
		if (!addr) {
			pr_err("KStackWatch: Invalid stack offset %llu\n",
			       config->stack_var.offset);
			return -EINVAL;
		}
		if (validate_stack_address(addr, config->stack_var.len)) {
			pr_err("KStackWatch: Invalid stack var len %llu\n",
			       config->stack_var.len);
		}
		len = config->stack_var.len;
		break;

	default:
		pr_warn("KStackWatch: Unknown watch type %d\n", config->type);
		return -EINVAL;
	}

	*watch_addr = addr;
	*watch_len = len;
	return 0;
}

/* Kprobe handlers */
static struct kprobe entry_probe;
static struct kretprobe exit_probe;

/* Function entry handler */
static void entry_handler(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	int *depth;
	int ret;
	u64 watch_addr;
	u64 watch_len;

	/* Handle nested calls - only monitor outermost */
	depth = this_cpu_ptr(&monitor_depth);
	(*depth)++;

	if (*depth > 1) {
		pr_debug("KStackWatch: Skipping nested call (depth %d)\n",
			 *depth);
		return;
	}

	/* Setup breakpoints for all active watches */
	ret = parse_watch_info(regs, probe_config, &watch_addr, &watch_len);
	if (ret) {
		pr_err("KStackWatch: Failed to parse watch info: %d\n", ret);
		(*depth)--;
		return;
	}
	hwbp_arm_all(watch_addr, watch_len);

	pr_debug("KStackWatch: Armed for %s at depth %d\n",
		 probe_config->function, *depth);
}

/* Function exit handler */
static int exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *depth;

	depth = this_cpu_ptr(&monitor_depth);
	(*depth)--;

	/* Only disarm when fully unwound */
	if (*depth == 0) {
		hwbp_disarm_all();
		pr_debug("KStackWatch: Disarmed for %s\n",
			 probe_config->function);
	}

	return 0;
}

int setup_probes(struct kstackwatch_config *config)
{
	int ret;

	/* Setup entry probe */
	memset(&entry_probe, 0, sizeof(entry_probe));
	entry_probe.symbol_name = config->function;
	entry_probe.offset = config->instruction_offset;
	entry_probe.post_handler = entry_handler;
	probe_config = config;

	ret = register_kprobe(&entry_probe);
	if (ret < 0) {
		pr_err("KStackWatch: Failed to register kprobe ret %d\n", ret);
		return ret;
	}

	/* Setup exit probe */
	memset(&exit_probe, 0, sizeof(exit_probe));
	exit_probe.kp.symbol_name = config->function;
	exit_probe.handler = exit_handler;
	exit_probe.maxactive = 20;

	ret = register_kretprobe(&exit_probe);
	if (ret < 0) {
		pr_err("KStackWatch: Failed to register exit probe for %s: %d\n",
		       probe_config->function, ret);
		unregister_kprobe(&entry_probe);
		return ret;
	}

	return 0;
}

void cleanup_probes(void)
{
	unregister_kretprobe(&exit_probe);
	unregister_kprobe(&entry_probe);
}