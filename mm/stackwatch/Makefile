# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_STACKWATCH)	+= stackwatch.o
obj-$(CONFIG_STACKWATCH_TEST)	+= stackwatch_test.o

stackwatch-y := core.o hwbp.o stack.o

# Force checking of return values
ccflags-y += -Wunused-result
# Alternative: use __must_check attribute checking
ccflags-y += -Werror=unused-result

# Optional: Additional useful warnings for kernel development
ccflags-y += -Wmissing-prototypes
ccflags-y += -Wstrict-prototypes
ccflags-y += -Wno-unused-parameter

# Enable all warnings and treat specific ones as errors
ccflags-y += -Wall -Werror=return-type -Werror=unused-result