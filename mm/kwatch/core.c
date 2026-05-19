// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>

static int __init kwatch_init(void)
{
	pr_info("module loaded\n");
	return 0;
}

module_init(kwatch_init);

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel watchpoint");
MODULE_LICENSE("GPL");
