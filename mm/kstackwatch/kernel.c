// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kstrtox.h>
#include <linux/module.h>
#include <linux/string.h>

#include "kstackwatch.h"

MODULE_AUTHOR("Jinchao Wang");
MODULE_DESCRIPTION("Kernel Stack Watch");
MODULE_LICENSE("GPL");

static struct ksw_config *ksw_config;

/*
 * Format of the configuration string:
 *    function+ip_offset[+depth] [local_var_offset:local_var_len]
 *
 * - function         : name of the target function
 * - ip_offset        : instruction pointer offset within the function
 * - depth            : recursion depth to watch
 * - local_var_offset : offset from the stack pointer at function+ip_offset
 * - local_var_len    : length of the local variable(1,2,4,8)
 */
static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
{
	char *func_part, *local_var_part = NULL;
	char *token;
	u16 local_var_len;

	memset(ksw_config, 0, sizeof(*ksw_config));

	/* set the watch type to the default canary-based watching */
	config->type = WATCH_CANARY;

	func_part = strim(buf);
	strscpy(config->config_str, func_part, MAX_CONFIG_STR_LEN);

	local_var_part = strchr(func_part, ' ');
	if (local_var_part) {
		*local_var_part = '\0'; // terminate the function part
		local_var_part = strim(local_var_part + 1);
	}

	/* parse the function part: function+ip_offset[+depth] */
	token = strsep(&func_part, "+");
	if (!token)
		goto fail;

	strscpy(config->function, token, MAX_FUNC_NAME_LEN - 1);

	token = strsep(&func_part, "+");
	if (!token || kstrtou16(token, 0, &config->ip_offset)) {
		pr_err("failed to parse instruction offset\n");
		goto fail;
	}

	token = strsep(&func_part, "+");
	if (token && kstrtou16(token, 0, &config->depth)) {
		pr_err("failed to parse depth\n");
		goto fail;
	}
	if (!local_var_part || !(*local_var_part))
		return 0;

	/* parse the optional local var offset:len */
	config->type = WATCH_LOCAL_VAR;
	token = strsep(&local_var_part, ":");
	if (!token || kstrtou16(token, 0, &config->local_var_offset)) {
		pr_err("failed to parse local var offset\n");
		goto fail;
	}

	if (!local_var_part || kstrtou16(local_var_part, 0, &local_var_len)) {
		pr_err("failed to parse local var len\n");
		goto fail;
	}

	if (local_var_len != 1 && local_var_len != 2 &&
	    local_var_len != 4 && local_var_len != 8) {
		pr_err("invalid local var len %u (must be 1,2,4,8)\n",
		       local_var_len);
		goto fail;
	}
	config->local_var_len = local_var_len;

	return 0;
fail:
	pr_err("invalid input: %s\n", config->config_str);
	config->config_str[0] = '\0';
	return -EINVAL;
}

static int __init kstackwatch_init(void)
{
	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
	if (!ksw_config)
		return -ENOMEM;

	pr_info("module loaded\n");
	return 0;
}

static void __exit kstackwatch_exit(void)
{
	kfree(ksw_config);

	pr_info("module unloaded\n");
}

module_init(kstackwatch_init);
module_exit(kstackwatch_exit);
