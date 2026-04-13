// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "mode.h"
#include "internal.h"


extern const struct kwatch_mode_ops stack_mode_ops;

static const struct kwatch_mode_ops *kwatch_mode_ops;

int kwatch_mode_init(const char *mode)
{
	if (!strcmp(mode, "stack"))
		kwatch_mode_ops = &stack_mode_ops;
	else
		return -EINVAL;
	return 0;
}

void kwatch_mode_uninit(void)
{
	kwatch_mode_ops = NULL;
}

int kwatch_mode_config_parse(const char *key, const char *val)
{
	if (!kwatch_mode_ops)
		return -EINVAL;
	if (!kwatch_mode_ops->config_parse)
		return -EOPNOTSUPP;
	return kwatch_mode_ops->config_parse(key, val);
}

int kwatch_mode_config_validate(void)
{
	if (!kwatch_mode_ops)
		return -EINVAL;
	if (!kwatch_mode_ops->config_validate)
		return -EOPNOTSUPP;
	return kwatch_mode_ops->config_validate();
}

int kwatch_mode_config_show(char *buf, size_t size)
{
	if (!kwatch_mode_ops)
		return -EINVAL;
	if (!kwatch_mode_ops->config_show)
		return -EOPNOTSUPP;
	return kwatch_mode_ops->config_show(buf, size);
}

int kwatch_mode_addr_len_resolve(struct pt_regs *regs, ulong *out_addr,
				 u16 *out_len)
{
	if (!kwatch_mode_ops)
		return -EINVAL;
	if (!kwatch_mode_ops->addr_len_resolve)
		return -EOPNOTSUPP;
	return kwatch_mode_ops->addr_len_resolve(regs, out_addr, out_len);
}
