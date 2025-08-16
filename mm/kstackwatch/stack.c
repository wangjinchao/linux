/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/stackprotector.h>
#include <linux/kprobes.h>
#include <asm/stacktrace.h>

#include "kstackwatch.h"

/* Per-CPU watching state */
static DEFINE_PER_CPU(int, monitor_depth);
struct ksw_config *probe_config;

/* Find canary address in current stack frame */
static unsigned long find_canary_address(struct pt_regs *regs)
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
static unsigned long resolve_stack_offset(struct pt_regs *regs, s64 local_var_offset)
{
	unsigned long stack_base;
	unsigned long target_addr;

	if (!regs)
		return 0;

	/* Use stack pointer as base for offset calculation */
	stack_base = regs->sp;
	target_addr = stack_base + local_var_offset;

	pr_info("KSW: resolve_stack_offset sp:0x%lx offset: %llx, target: 0x%lx\n",
		stack_base, local_var_offset, target_addr);

	return target_addr;
}

/* Validate that address is within current stack bounds */
static int validate_stack_address(unsigned long addr, size_t size)
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
static int parse_watch_info(struct pt_regs *regs,
			    struct ksw_config *config, u64 *watch_addr,
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

	case WATCH_LOCAL_VAR:
		addr = resolve_stack_offset(regs, config->local_var_offset);
		if (!addr) {
			pr_err("KSW: Invalid stack var offset %u\n",
			       config->local_var_offset);
			return -EINVAL;
		}
		if (validate_stack_address(addr, config->local_var_len)) {
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

/* Kprobe handlers */
static struct kprobe entry_probe;
static struct kretprobe exit_probe;

/* Function entry handler */
static void entry_handler(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	int *depth, cur_depth;
	int ret;
	u64 watch_addr;
	u64 watch_len;

	/* Handle nested calls - only monitor outermost */
	depth = this_cpu_ptr(&monitor_depth);
	cur_depth = (*depth)++;

	if (cur_depth != probe_config->depth) {
		/* depth start from 0 */
		pr_info("KSW: config_depth:%u cur_depth:%d skipping entry_handler\n",
			probe_config->depth, cur_depth);
		return;
	}

	/* Setup breakpoints for all active watches */
	ret = parse_watch_info(regs, probe_config, &watch_addr, &watch_len);
	if (ret) {
		pr_err("KSW: Failed to parse watch info: %d\n", ret);
		return;
	}
	ret = ksw_watch_on(watch_addr, watch_len);
	if (ret) {
		pr_err("KSW: Failed to arm hwbp: %d\n", ret);
		return;
	}
	pr_info("KSW: Armed for %s at depth %d addr:0x%llx len:%llu\n",
		probe_config->function, cur_depth, watch_addr, watch_len);
}

/* Function exit handler */
static int exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *depth, cur_depth;

	depth = this_cpu_ptr(&monitor_depth);
	cur_depth = --(*depth);
	if (cur_depth != probe_config->depth) {
		/* depth start from 0 */
		pr_info("KSW: exit_handler config depth:%u cur_depth:%d skipping\n",
			probe_config->depth, cur_depth);
		return 0;
	}

	ksw_watch_off();
	pr_info("KSW: Disarmed for %s\n", probe_config->function);

	return 0;
}

int ksw_stack_init(struct ksw_config *config)
{
	int ret;
	int cpu;
	int *depth;

	for_each_possible_cpu(cpu) {
		depth = per_cpu_ptr(&monitor_depth, cpu);
		WRITE_ONCE(*depth, 0);
	}

	/* Setup entry probe */
	memset(&entry_probe, 0, sizeof(entry_probe));
	entry_probe.symbol_name = config->function;
	entry_probe.offset = config->instruction_offset;
	entry_probe.post_handler = entry_handler;
	probe_config = config;
	ret = register_kprobe(&entry_probe);
	if (ret < 0) {
		pr_err("KSW: Failed to register kprobe ret %d\n", ret);
		return ret;
	}

	/* Setup exit probe */
	memset(&exit_probe, 0, sizeof(exit_probe));
	exit_probe.kp.symbol_name = config->function;
	exit_probe.handler = exit_handler;
	exit_probe.maxactive = 20;

	ret = register_kretprobe(&exit_probe);
	if (ret < 0) {
		pr_err("KSW: Failed to register exit probe for %s: %d\n",
		       probe_config->function, ret);
		unregister_kprobe(&entry_probe);
		return ret;
	}

	return 0;
}

void ksw_stack_exit(void)
{
	unregister_kretprobe(&exit_probe);
	unregister_kprobe(&entry_probe);
}