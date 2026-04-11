#ifndef _KWATCH_TARGET_H
#define _KWATCH_TARGET_H

#include <linux/ptrace.h>

struct kwatch_config;

enum kwatch_mode_type {
	KWATCH_MODE_STACK,
	KWATCH_MODE_SYM,
	KWATCH_MODE_DEREF,
};

enum kwatch_access_type {
	KWATCH_ACCESS_R,
	KWATCH_ACCESS_W,
	KWATCH_ACCESS_RW,
	KWATCH_ACCESS_X,
};

struct kwatch_mode_ops {
	enum kwatch_mode_type type;
	const char *name;

	void* (*mode_config_alloc)(void);
	void (*mode_config_free)(void *mode_config);
	int (*mode_config_parse)(void *mode_config, const char *key, const char *val);
	int (*mode_config_validate)(void *mode_config);
	int (*mode_config_show)(void *mode_config, char *buf, size_t size);
	int (*resolve)(struct pt_regs *regs, void *mode_config,
		       ulong *out_addr, u16 *out_len,
		       enum kwatch_access_type *out_type);
};

const struct kwatch_mode_ops *kwatch_mode_lookup(enum kwatch_mode_type type);

#endif
