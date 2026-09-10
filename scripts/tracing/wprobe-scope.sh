#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# wprobe-scope.sh - watch an object with a hardware watchpoint while it is
# "in scope", that is between two kernel functions being called on it.
#
# This is a front end for the wprobe event triggers, see
# Documentation/trace/wprobetrace.rst. It creates:
#  - a wprobe event wprobes/NAME with SLOTS watchpoints,
#  - an fprobe event on ARM_FUNC whose set_wprobe trigger watches the
#    address fetched by ARM_ARG plus OFFSET,
#  - an fprobe event on CLEAR_FUNC whose clear_wprobe trigger stops
#    watching when CLEAR_ARG plus OFFSET is the watched address,
# and enables the two fprobe events. The watchpoint hits show up in the
# trace buffer as wprobes/NAME events.
#
# Usage:
#   wprobe-scope.sh [-n NAME] [-l LEN] [-w r|w|rw] [-o OFFSET] [-s SLOTS]
#                   [-T TIMEOUT] [-S] ARM_FUNC ARM_ARG CLEAR_FUNC[%return] CLEAR_ARG
#   wprobe-scope.sh -c [-n NAME]
#
#   -n NAME     event name (default: wscope)
#   -l LEN      watched length in bytes: 1, 2, 4 or 8 (default: 8)
#   -w TYPE     access type: r, w or rw (default: w)
#   -o OFFSET   offset of the watched field in the object (default: 0)
#   -s SLOTS    number of objects watched at once (default: 1)
#   -T TIMEOUT  release a window that is not cleared after TIMEOUT, e.g.
#               500ms or 2s (default: never)
#   -S          record the stack trace of the accessing code
#   -c          stop watching and remove everything created for NAME
#
# ARM_ARG and CLEAR_ARG are fprobe fetch arguments giving the address of
# the object, for example '$arg2', or '+8($arg1)' for a pointer stored in
# the object passed as the first argument. CLEAR_FUNC%return clears at the
# return of CLEAR_FUNC; a %return event can still use the entry arguments.
#
# Example - catch whoever overwrites the completion callback (offset 56)
# of a USB request while it is being given back to the gadget driver:
#
#   wprobe-scope.sh -o 56 -S usb_gadget_giveback_request '$arg2' \
#           usb_gadget_giveback_request%return '$arg2'
#   cat /sys/kernel/tracing/trace_pipe
#   wprobe-scope.sh -c

TRACEFS=${TRACEFS:-/sys/kernel/tracing}
NAME=wscope
LEN=8
TYPE=w
OFFSET=0
SLOTS=1
TIMEOUT=
STACK=
CLEANUP=

usage() {
	sed -n '/^# Usage:/,/^#   -c /p' "$0" | sed 's/^# \{0,1\}//'
	exit 1
}

while getopts "n:l:w:o:s:T:Sch" opt; do
	case $opt in
	n) NAME=$OPTARG ;;
	l) LEN=$OPTARG ;;
	w) TYPE=$OPTARG ;;
	o) OFFSET=$OPTARG ;;
	s) SLOTS=$OPTARG ;;
	T) TIMEOUT=$OPTARG ;;
	S) STACK=1 ;;
	c) CLEANUP=1 ;;
	*) usage ;;
	esac
done
shift $((OPTIND - 1))

if [ ! -d "$TRACEFS/events" ]; then
	echo "wprobe-scope: tracefs is not mounted at $TRACEFS" >&2
	exit 1
fi
cd "$TRACEFS" || exit 1

ARM_EV=wscope/${NAME}_arm
CLEAR_EV=wscope/${NAME}_clear
WP_EV=wprobes/$NAME

# One step of the tear down. The steps are named so that a failed setup
# can undo exactly what it created.
undo_step() {
	case $1 in
	arm_enable)	echo 0 > events/$ARM_EV/enable ;;
	clear_enable)	echo 0 > events/$CLEAR_EV/enable ;;
	stack)		echo '!stacktrace' >> events/$WP_EV/trigger ;;
	clear_trig)	echo "!clear_wprobe:$NAME" >> events/$CLEAR_EV/trigger ;;
	set_trig)	echo "!set_wprobe:$NAME:obj" >> events/$ARM_EV/trigger ;;
	# A window still open keeps the wprobe event enabled: close it.
	wp_enable)	echo 0 > events/$WP_EV/enable ;;
	clear_ev)	echo "-:$CLEAR_EV" >> dynamic_events ;;
	arm_ev)		echo "-:$ARM_EV" >> dynamic_events ;;
	wp_ev)		echo "-:$WP_EV" >> dynamic_events ;;
	esac
}

# Undo the given steps, last one first; a step may find nothing to undo.
undo() {
	rev=
	for step in $1; do
		rev="$step $rev"
	done
	for step in $rev; do
		undo_step "$step" 2>/dev/null
	done
}

ALL_STEPS="wp_ev arm_ev clear_ev set_trig clear_trig stack wp_enable clear_enable arm_enable"

if [ -n "$CLEANUP" ]; then
	undo "$ALL_STEPS"
	for ev in $WP_EV $ARM_EV $CLEAR_EV; do
		if [ -d events/$ev ]; then
			echo "wprobe-scope: events/$ev is still there, see error_log" >&2
			exit 1
		fi
	done
	exit 0
fi

[ $# -eq 4 ] || usage
ARM_FUNC=$1
ARM_ARG=$2
CLEAR_FUNC=$3
CLEAR_ARG=$4

for ev in $WP_EV $ARM_EV $CLEAR_EV; do
	if [ -d events/$ev ]; then
		echo "wprobe-scope: events/$ev exists, run '$0 -c -n $NAME' first" >&2
		exit 1
	fi
done

case $OFFSET in
0) ADJ= ;;
-*) ADJ=$OFFSET ;;
*) ADJ=+$OFFSET ;;
esac
TMO=
[ -n "$TIMEOUT" ] && TMO=":timeout=$TIMEOUT"
if [ "$SLOTS" -gt 1 ] 2>/dev/null; then
	W=w$SLOTS
else
	W=w
fi

# Append a line to a tracefs file and remember the step; on failure undo
# what this invocation created and bail out. Appending never truncates a
# file that is already in use.
CREATED=
tf() {
	if ! printf '%s\n' "$2" >> "$1"; then
		echo "wprobe-scope: writing '$2' to $1 failed:" >&2
		tail -n 1 error_log >&2
		undo "$CREATED"
		exit 1
	fi
	CREATED="$CREATED $3"
}

tf dynamic_events "$W:$WP_EV $TYPE@-1:$LEN address=\$addr value=+0(\$addr)" wp_ev
tf dynamic_events "f:$ARM_EV $ARM_FUNC obj=$ARM_ARG" arm_ev
tf dynamic_events "f:$CLEAR_EV $CLEAR_FUNC obj=$CLEAR_ARG" clear_ev
tf events/$ARM_EV/trigger "set_wprobe:$NAME:obj$ADJ$TMO" set_trig
CREATED="$CREATED wp_enable"
tf events/$CLEAR_EV/trigger "clear_wprobe:$NAME:obj$ADJ" clear_trig
[ -n "$STACK" ] && tf events/$WP_EV/trigger "stacktrace" stack
tf events/$CLEAR_EV/enable 1 clear_enable
tf events/$ARM_EV/enable 1 arm_enable

echo "wprobe-scope: watching $TYPE@(obj$ADJ):$LEN from $ARM_FUNC to $CLEAR_FUNC"
echo "  hits: cat $TRACEFS/trace_pipe (events $WP_EV)"
echo "  state: cat $TRACEFS/events/$ARM_EV/trigger"
echo "  stop: $0 -c -n $NAME"
