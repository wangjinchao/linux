.. SPDX-License-Identifier: GPL-2.0

====================================
KStackWatch: Kernel Stack Watch
====================================

Overview
========
KStackWatch is a lightweight debugging tool designed to detect
kernel stack corruption in real time. It helps developers capture the
moment corruption occurs, rather than only observing a later crash.

Motivation
==========
Stack corruption may originate in one function but manifest much later
with no direct call trace linking the two. This makes such issues
extremely difficult to diagnose. KStackWatch addresses this by combining
hardware breakpoints with kprobe and fprobe instrumentation, monitoring
stack canaries or local variables at the point of corruption.

Key Features
============
- Lightweight overhead:
   Minimal runtime cost, preserving bug reproducibility.
- Real-time detection:
  Detect stack corruption immediately.
- Flexible configuration:
  Control via a procfs interface.
- Depth filtering:
  Optional recursion depth tracking per task.

Configuration
=============
The control file is created at::

  /proc/kstackwatch

To configure, write a string in the following format::

  function+ip_offset[+depth] [local_var_offset:local_var_len]
    - function         : name of the target function
    - ip_offset        : instruction pointer offset within the function
    - depth            : recursion depth to watch, starting from 0
    - local_var_offset : offset from the stack pointer at function+ip_offset
    - local_var_len    : length of the local variable(1,2,4,8)

Fields
------
- ``function``:
  Name of the target function to watch.
- ``ip_offset``:
  Instruction pointer offset within the function.
- ``depth`` (optional):
  Maximum recursion depth for the watch.
- ``local_var_offset:local_var_len`` (optional):
  A region of a local variable to monitor, relative to the stack pointer.
  If not given, KStackWatch monitors the stack canary by default.

Examples
--------
1. Watch the canary at the entry of ``canary_test_write``::

     echo 'canary_test_write+0x12' > /proc/kstackwatch

2. Watch a local variable of 8 bytes at offset 0 in
   ``silent_corruption_victim``::

     echo 'silent_corruption_victim+0x7f 0:8' > /proc/kstackwatch

Module Parameters
=================
``panic_on_catch`` (bool)
  - If true, trigger a kernel panic immediately on detecting stack
    corruption.
  - Default is false (log a message only).

Implementation Notes
====================
- Hardware breakpoints are preallocated at watch start.
- Function exit is monitored using ``fprobe``.
- Per-task depth tracking is used to handle recursion across scheduling.
- The procfs interface allows dynamic reconfiguration at runtime.
- Active state is cleared before applying new settings.

Limitations
===========
- Only one active watch can be configured at a time (singleton).
- Local variable offset and size must be known in advance.

Testing
=======
KStackWatch includes a companion test module (`kstackwatch_test`) and
a helper script (`kstackwatch_test.sh`) to exercise different stack
corruption scenarios:
