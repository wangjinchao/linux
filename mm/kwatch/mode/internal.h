#ifndef _KWATCH_MODE_INTERNAL_H_
#define _KWATCH_MODE_INTERNAL_H_
#include <linux/ptrace.h>

enum kwatch_mode_type {
	KWATCH_MODE_STACK,
	KWATCH_MODE_SYM,
	KWATCH_MODE_DEREF,
};

struct kwatch_mode_ops {
	int (*config_parse)(const char *key, const char *val);
	int (*config_validate)(void);
	int (*config_show)(char *buf, size_t size);
	int (*addr_len_resolve)(struct pt_regs *regs, ulong *out_addr,
				u16 *out_len);
};

#endif
