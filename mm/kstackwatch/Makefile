# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
obj-$(CONFIG_KSTACK_WATCH_TEST)	+= kstackwatch_test.o

kstackwatch-y := core.o stack.o watch.o
CFLAGS_kstackwatch_test.o = -O1
