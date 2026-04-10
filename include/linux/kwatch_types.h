/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KWATCH_TYPES_H
#define _LINUX_KWATCH_TYPES_H
#include <linux/types.h>

struct kwatch_watchpoint;
struct kwatch_ctx {
	struct kwatch_watchpoint *wp;
	ulong sp;
	u16 depth;
	u16 generation;
};

#endif /* _LINUX_KWATCH_TYPES_H */
