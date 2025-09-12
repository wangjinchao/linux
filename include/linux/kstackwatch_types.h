/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KSTACK_WATCH_TYPES_H
#define _LINUX_KSTACK_WATCH_TYPES_H
#include <linux/types.h>

struct kstackwatch_ctx {
	ulong watch_addr;
	u16 watch_len;
	u16 depth;
	bool watch_on;
};

#endif /* _LINUX_KSTACK_WATCH_TYPES_H */
