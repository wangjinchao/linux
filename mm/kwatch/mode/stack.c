// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/printk.h>
#include <linux/sched.h>

#include "mode.h"

struct kwatch_stack_cfg {
	u16 sp_offset;
	u16 watch_len;
	enum kwatch_access_type access_type;
};

static void *stack_config_alloc(void)
{
	return kzalloc(sizeof(struct kwatch_stack_cfg), GFP_KERNEL);
}

static void stack_config_free(void *mode_config)
{
	kfree(mode_config);
}

static int stack_config_parse(void *mode_config, const char *key, const char *val)
{
	struct kwatch_stack_cfg *stack_config = mode_config;

	if (!strcmp(key, "sp_offset"))
		return kstrtou16(val, 0, &stack_config->sp_offset);
	if (!strcmp(key, "watch_len"))
		return kstrtou16(val, 0, &stack_config->watch_len);

	return -EINVAL;
}

static int stack_config_validate(void *mode_config)
{
	struct kwatch_stack_cfg *stack_config = mode_config;

	/* Verification logic: Early boundary checks */
	if (stack_config->watch_len == 0 || stack_config->watch_len > 8)
		return -ERANGE;

	if (stack_config->sp_offset > 4096)
		return -EINVAL;

	return 0;
}

static int stack_config_show(void *mode_config, char *buf, size_t size)
{
	struct kwatch_stack_cfg *cfg = mode_config;
	int len = 0;

	/* Boundary condition: Prevent null pointer dereference */
	if (!cfg || !buf || size == 0)
		return 0;

	len = snprintf(buf, size,
		       "sp_offset=%u\n"
		       "watch_len=%u\n"
		       "access_type=%d\n",
		       cfg->sp_offset,
		       cfg->watch_len,
		       cfg->access_type);

	/* * snprintf returns the number of characters that *would* have been
	 * written if space was sufficient. We cap it at 'size - 1' to ensure
	 * the caller doesn't increment their offset beyond the actual buffer.
	 */
	return (len < size) ? len : size - 1;
}

static int kwatch_stack_resolve(struct pt_regs *regs, void *mode_config,
				ulong *out_addr, u16 *out_len,
				enum kwatch_access_type *out_type)
{
	struct kwatch_stack_cfg *stack_config = mode_config;

	ulong addr;
	u16 len;
	unsigned long stack_start = (unsigned long)current->stack;
	unsigned long stack_end = stack_start + THREAD_SIZE;

	addr = kernel_stack_pointer(regs) + stack_config->sp_offset;
	len = stack_config->watch_len ? stack_config->watch_len : sizeof(ulong);

	if (!addr || addr < stack_start || (addr + len) > stack_end) {
		pr_err("invalid stack addr:0x%lx len:%u\n", addr, len);
		return -ERANGE;
	}

	*out_addr = addr;
	*out_len = len;
	*out_type = stack_config->access_type;
	return 0;
}

const struct kwatch_mode_ops stack_mode_ops = {
	.type        = KWATCH_MODE_STACK,
	.name        = "stack",
	.mode_config_alloc        = stack_config_alloc,
	.mode_config_free        = stack_config_free,
	.mode_config_parse = stack_config_parse,
	.mode_config_validate = stack_config_validate,
	.mode_config_show = stack_config_show,
	.resolve = kwatch_stack_resolve
};
