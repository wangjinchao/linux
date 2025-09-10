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
	0) echo "canary_test_write+0x19" >/proc/kstackwatch
	   echo "test0" >/proc/kstackwatch_test ;;
	1) echo "canary_test_overflow+0x1a" >/proc/kstackwatch
	   echo "test1" >/proc/kstackwatch_test ;;
	2) echo "silent_corruption_victim+0x32 0:8" >/proc/kstackwatch
	   echo "test2" >/proc/kstackwatch_test ;;
	3) echo "recursive_corruption_test+0x21+3 0:8" >/proc/kstackwatch
	   echo "test3" >/proc/kstackwatch_test ;;
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
