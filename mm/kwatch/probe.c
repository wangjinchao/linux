// SPDX-License-Identifier: GPL-2.0

#include "kwatch.h"

void kwatch_probe_mute(bool mute)
{
}

bool kwatch_probe_validate_hit(struct pt_regs *regs,
			       struct task_struct *arm_tsk)
{
	return true;
}

void kwatch_tsk_ctx_reset(void)
{
}
