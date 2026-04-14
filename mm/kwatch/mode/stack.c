// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/printk.h>
#include <linux/sched.h>

#include "internal.h"

struct kwatch_stack_cfg {
	u16 sp_offset;
	u16 watch_len;
} kwatch_stack_cfg;

static int stack_config_parse(const char *key, const char *val)
{
	if (!strcmp(key, "sp_offset"))
		return kstrtou16(val, 0, &kwatch_stack_cfg.sp_offset);
	if (!strcmp(key, "watch_len"))
		return kstrtou16(val, 0, &kwatch_stack_cfg.watch_len);

	return -EINVAL;
}

static int stack_config_validate(void)
{
	if (kwatch_stack_cfg.watch_len != 1 &&
	    kwatch_stack_cfg.watch_len != 2 &&
	    kwatch_stack_cfg.watch_len != 4 &&
	    kwatch_stack_cfg.watch_len != 8)
		return -EINVAL;

	if (kwatch_stack_cfg.sp_offset > THREAD_SIZE)
		return -EINVAL;

	return 0;
}

static int stack_config_show(char *buf, size_t size)
{
	int len = 0;

	if (!buf || size == 0)
		return 0;

	len = snprintf(buf, size,
		       "mode=stack\n"
		       "sp_offset=%u\n"
		       "watch_len=%u\n",
		       kwatch_stack_cfg.sp_offset, kwatch_stack_cfg.watch_len);

	/* snprintf returns the number of characters that *would* have been
	 * written if space was sufficient. We cap it at 'size - 1' to ensure
	 * the caller doesn't increment their offset beyond the actual buffer.
	 */
	return (len < size) ? len : size - 1;
}

static int kwatch_stack_resolve(struct pt_regs *regs, ulong *out_addr,
				u16 *out_len)
{
	ulong addr;
	u16 len;
	unsigned long stack_start = (unsigned long)current->stack;
	unsigned long stack_end = stack_start + THREAD_SIZE;

	addr = kernel_stack_pointer(regs) + kwatch_stack_cfg.sp_offset;
	len = kwatch_stack_cfg.watch_len;

	if (!addr || addr < stack_start || (addr + len) > stack_end) {
		pr_err("invalid stack addr:0x%lx len:%u\n", addr, len);
		return -ERANGE;
	}

	*out_addr = addr;
	*out_len = len;
	return 0;
}

const struct kwatch_mode_ops stack_mode_ops = {
	.config_parse = stack_config_parse,
	.config_validate = stack_config_validate,
	.config_show = stack_config_show,
	.addr_len_resolve = kwatch_stack_resolve
};
