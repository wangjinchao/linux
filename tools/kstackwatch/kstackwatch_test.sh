#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

echo "IMPORTANT: Before running, make sure you have updated the config values!"

usage() {
	echo "Usage: $0 [0-5]"
	echo "  0  - test watch fire"
	echo "  1  - test canary overflow"
	echo "  2  - test recursive depth"
	echo "  3  - test silent corruption"
	echo "  4  - test multi-threaded silent corruption"
	echo "  5  - test multi-threaded overflow"
}

run_test() {
	local test_num=$1
	case "$test_num" in
	0) echo fn=test_watch_fire fo=0x29 wl=8 >/proc/kstackwatch
	   echo test0 > /proc/kstackwatch_test
	   ;;
	1) echo fn=test_canary_overflow fo=0x15 >/proc/kstackwatch
	   echo test1 >/proc/kstackwatch_test
	   ;;
	2) echo fn=test_recursive_depth fo=0x2f dp=3 wl=8 so=0 >/proc/kstackwatch
	   echo test2 >/proc/kstackwatch_test
	   ;;
	3) echo fn=test_mthread_victim fo=0x49 wl=8 >/proc/kstackwatch
	   echo test3 >/proc/kstackwatch_test
	   ;;
	4) echo fn=test_mthread_victim fo=0x49 wl=8 >/proc/kstackwatch
	   echo test4 >/proc/kstackwatch_test
	   ;;
	5) echo fn=test_mthread_victim fo=0x49 wl=8 >/proc/kstackwatch
	   echo test5 >/proc/kstackwatch_test
	   ;;
	*) usage
	   exit 1 ;;
	esac
	# Reset watch after test
	echo >/proc/kstackwatch
}

# Check root and module
[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1
for f in /proc/kstackwatch /proc/kstackwatch_test; do
	[ ! -f "$f" ] && echo "$f not found" && exit 1
done

# Run
[ -z "$1" ] && { usage; exit 0; }
run_test "$1"
