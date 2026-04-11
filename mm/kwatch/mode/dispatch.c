// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "mode.h"

extern const struct kwatch_mode_ops stack_mode_ops;

/* The Registry */
static const struct kwatch_mode_ops *mode_registry[] = {
	[KWATCH_MODE_STACK] = &stack_mode_ops,
};

const struct kwatch_mode_ops *kwatch_mode_lookup(enum kwatch_mode_type type)
{
	if (type >= ARRAY_SIZE(mode_registry))
		return NULL;
	return mode_registry[type];
}
