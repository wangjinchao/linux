#ifndef _KWATCH_MODE_MODE_H
#define _KWATCH_MODE_MODE_H

#include <linux/ptrace.h>

int kwatch_mode_init(const char *mode);
void kwatch_mode_uninit(void);
int kwatch_mode_config_parse(const char *key, const char *val);
int kwatch_mode_config_validate(void);
int kwatch_mode_config_show(char *buf, size_t size);
int kwatch_mode_addr_len_resolve(struct pt_regs *regs, ulong *out_addr,
				 u16 *out_len);

#endif
