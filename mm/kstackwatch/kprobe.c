/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stack canary detection for StackWatch
 */

#include <linux/stackprotector.h>
#include <linux/kprobes.h>
#include "kstackwatch.h"

/* Per-CPU monitoring state */
static DEFINE_PER_CPU(int, monitor_depth);

/* Find canary address in current stack frame */
static inline unsigned long find_canary_address(struct pt_regs *regs)
{
	unsigned long *stack_ptr, *stack_end;
	unsigned long expected_canary;
	unsigned int i;

	if (!regs || !regs->sp)
		return 0;

	stack_ptr = (unsigned long *)regs->sp;
	stack_end =
		(unsigned long *)current->stack + THREAD_SIZE / sizeof(long);
	expected_canary = current->stack_canary; /* Use stored canary */
	pr_info("StackWatch: Expected canary: 0x%lx\n", expected_canary);
	for (i = 0; i < MAX_FRAME_SEARCH && &stack_ptr[i] < stack_end; i++) {
		pr_debug("StackWatch: Stack[%d]: 0x%lx\n", i, stack_ptr[i]);
		if (stack_ptr[i] == expected_canary) {
			pr_info("StackWatch: Canary found at: 0x%p\n", &stack_ptr[i]);
			return (unsigned long)&stack_ptr[i];
		}
	}

	return 0;
}

/* Kprobe handlers */
static struct kprobe entry_probe;
static struct kretprobe exit_probe;

/* Function entry handler */
static void entry_handler(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	unsigned long canary_addr;
	int *depth;
	int ret;

	/* Handle nested calls - only monitor outermost */
	depth = this_cpu_ptr(&monitor_depth);
	(*depth)++;

	if (*depth > 1) {
		pr_debug("StackWatch: Skipping nested call (depth %d)\n",
			 *depth);
		return; /* Skip nested calls */
	}

	/* Find canary in current stack frame */
	canary_addr = find_canary_address(regs);
	if (!canary_addr) {
		pr_warn("StackWatch: Canary not found in %s\n",
			target_function);
		(*depth)--;
		return;
	}

	/* Arm HWBP on all CPUs */
	ret = hwbp_arm_all(canary_addr);
	if (ret) {
		pr_err("StackWatch: Failed to arm HWBP: %d\n", ret);
		return;
	}

	pr_debug("StackWatch: Armed for %s at 0x%px (depth %d)\n",
		 target_function, (void *)canary_addr, *depth);
}

/* Function exit handler */
static int exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int *depth;

	depth = this_cpu_ptr(&monitor_depth);
	(*depth)--;

	/* Only disarm when fully unwound */
	if (*depth == 0) {
		/* Disarm HWBP on all CPUs */
		hwbp_disarm_all();

		pr_debug("StackWatch: Disarmed for %s\n", target_function);
	}

	return 0;
}

int setup_probes(const char *func_name, unsigned long long offset)
{
	int ret;
	/* Setup entry probe */
	memset(&entry_probe, 0, sizeof(entry_probe));

	entry_probe.symbol_name = func_name;
	entry_probe.offset = offset;
	entry_probe.post_handler = entry_handler;

	ret = register_kprobe(&entry_probe);
	if (ret < 0) {
		pr_err("StackWatch: Failed to register kprobe: %d\n", ret);
		return ret;
	}

	/* Setup exit probe */
	memset(&exit_probe, 0, sizeof(exit_probe));
	exit_probe.kp.symbol_name = func_name;
	exit_probe.handler = exit_handler;
	exit_probe.maxactive = 20;

	ret = register_kretprobe(&exit_probe);
	if (ret < 0) {
		pr_err("StackWatch: Failed to register exit probe for %s: %d\n",
		       func_name, ret);
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
