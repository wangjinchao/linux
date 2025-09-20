#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

echo "IMPORTANT: Before running, make sure you have updated the offset values!"

usage() {
	echo "Usage: $0 [0-3]"
	echo "  0  - Canary Write Test"
	echo "  1  - Canary Overflow Test"
	echo "  2  - Silent Corruption Test"
	echo "  3  - Recursive Corruption Test"
}

run_test() {
	local test_num=$1
	case "$test_num" in
	0) echo fn=test_watch_fire fo=0x18 wl=8 >/proc/kstackwatch
	   echo test0 > /proc/kstackwatch_test
	   ;;
	1) echo fn=test_canary_overflow fo=0x12 >/proc/kstackwatch
	   echo test1 >/proc/kstackwatch_test
	   ;;
	2) echo fn=test_recursive_depth fo=0x1b dp=3 wl=8 so=0 >/proc/kstackwatch
	   echo test2 >/proc/kstackwatch_test
	   ;;
	3) echo fn=test_silent_victim fo=0x4e so=0 wl=8 >/proc/kstackwatch
	   echo test3 >/proc/kstackwatch_test
	   ;;
	4) echo fn=test_multi_recursive_victim fo=0x28 wl=8 >/proc/kstackwatch
	   echo test4 >/proc/kstackwatch_test
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
