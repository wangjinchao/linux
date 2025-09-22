.. SPDX-License-Identifier: GPL-2.0

=================================
KStackWatch: Kernel Stack Watch
=================================

Overview
========

KStackWatch is a lightweight debugging tool to detect kernel stack corruption
in real time. It installs a hardware breakpoint (watchpoint) at a function's
specified offset using ``kprobe.post_handler`` and removes it in
``fprobe.exit_handler``. This covers the full execution window and reports
corruption immediately with time, location, and a call stack.

Main features:

* Immediate and precise detection
* Supports concurrent calls to the watched function
* Lockless design, usable in any context
* Depth filter for recursive calls
* Minimal impact on reproducibility
* Flexible ``procfs`` configuration with ``key=val`` syntax

Usage
=====

KStackWatch is configured through ``/proc/kstackwatch`` using a key=value
format. Both long and short forms are supported.

The function name and the instruction offset where the watchpoint should be
placed must be known. This information can be obtained from ``objdump`` or
other tools.

Required parameters
~~~~~~~~~~~~~~~~~~~

+--------------+--------+-----------------------------------------+
| Parameter    | Short  | Description                             |
+==============+========+=========================================+
| func_name    | fn     | Name of the target function             |
+--------------+--------+-----------------------------------------+
| func_offset  | fo     | Instruction pointer offset (hex)        |
+--------------+--------+-----------------------------------------+

Optional parameters (default 0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+--------+------------------------------------------------+
| Parameter    | Short  | Description                                    |
+==============+========+================================================+
| depth        | dp     | Recursion depth filter (default 0)             |
+--------------+--------+------------------------------------------------+
| max_watch    | mw     | Maximum number of concurrent watchpoints       |
|              |        | (default 0, capped by available hardware       |
|              |        | breakpoints)                                   |
+--------------+--------+------------------------------------------------+
| sp_offset    | so     | Watching addr offset from stack pointer        |
+--------------+--------+------------------------------------------------+
| watch_len    | wl     | Watch length in bytes (1, 2, 4, 8, or 0)       |
|              |        | 0 means automatically watch the stack canary   |
|              |        | 0 will ignore the ``sp_offset`` parameter      |
+--------------+--------+------------------------------------------------+


Example
~~~~~~~

Consider ``test4`` in ``kstackwatch_test.sh``. Run the test4 directly:

.. code-block:: bash
	echo test4 >/proc/kstackwatch_test

Sometimes, ``test_mthread_victim()`` might report that its ``buf[0]`` was
unhappy, its source code is:

.. code-block:: c

	static struct work_node *test_mthread_victim(int thread_id, int seq_id)
	{
		ulong buf[BUFFER_SIZE];

		for (int j = 0; j < BUFFER_SIZE; j++)
			buf[j] = 0xdeadbeef + seq_id;

		usleep_range(1000, 2000);
		for (int j = 0; j < BUFFER_SIZE; j++) {
			if (buf[j] != (0xdeadbeef + seq_id)) {
				pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
					thread_id, seq_id, j, buf[j]);
				return NULL;
			}
		}

		pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);

		return NULL;
	}

From the source code, its unhappyness is because the ``buf`` array was
modified unexpected.

KStackWatch can be used to find the exact location of this corruption.

Use the ``objdump`` output to get the offset of the instruction where the
watchpoint should be set:

.. code-block:: bash

	objdump -S --disassemble=test_mthread_victim vmlinux

The output is:

.. code-block:: c

	static struct work_node *test_mthread_victim(int thread_id, int seq_id)
	{
	ffffffff815ce060:       e8 db 6f ca ff          call   ffffffff81275040 <__fentry__>
	...
	        ulong buf[BUFFER_SIZE];
	ffffffff815ce084:       48 89 e2                mov    %rsp,%rdx
	ffffffff815ce087:       b9 10 00 00 00          mov    $0x10,%ecx
	ffffffff815ce08c:       48 89 d7                mov    %rdx,%rdi
	ffffffff815ce08f:       f3 48 ab                rep stos %rax,%es:(%rdi)

	        for (int j = 0; j < BUFFER_SIZE; j++)
	ffffffff815ce092:       eb 10                   jmp    ffffffff815ce0a4 <test_mthread_victim+0x44>
	                buf[j] = 0xdeadbeef + seq_id;
	ffffffff815ce094:       8d 93 ef be ad de       lea    -0x21524111(%rbx),%edx
	ffffffff815ce09a:       48 63 c8                movslq %eax,%rcx
	ffffffff815ce09d:       48 89 14 cc             mov    %rdx,(%rsp,%rcx,8)
	        for (int j = 0; j < BUFFER_SIZE; j++)
	ffffffff815ce0a1:       83 c0 01                add    $0x1,%eax
	ffffffff815ce0a4:       83 f8 0f                cmp    $0xf,%eax
	ffffffff815ce0a7:       7e eb                   jle    ffffffff815ce094 <test_mthread_victim+0x34>

	        usleep_range(1000, 2000);
	ffffffff815ce0a9:       be d0 07 00 00          mov    $0x7d0,%esi
	ffffffff815ce0ae:       bf e8 03 00 00          mov    $0x3e8,%edi
	ffffffff815ce0b3:       e8 d8 fb ff ff          call   ffffffff815cdc90 <usleep_range>
	...

From the disassembly, the function begins at ffffffff815ce060. The ``buf`` array
is initialized in a loop. The instruction that stores into the array is at
ffffffff815ce09d, and the instruction following the loop is at ffffffff815ce0a9.

Because KStackWatch uses ``kprobe.post_handler``, the watchpoint can be set
right after an instruction executes such as ffffffff815ce09d. But this will
cause false positives for buf[i!=0] because the watchpoint is already active.
Anather option is to watch the first instruction after the loop completes which
is ffffffff815ce0a9, this will cause false negatives because there is a little
time between the assignment and the watchpoint setup.

So ffffffff815ce0a9 is selected for cleaner logs. If a false negative is
suspected, the test can be run multiple times to catch the corruption.
The required offset is calculated from the beginning of the function:
``func_offset`` is 0x49 (ffffffff815ce0a9 - ffffffff815ce060).

And other parameters:
* The ``depth`` is 0, as ``test_mthread_victim`` is not recursive.
* The ``max_watch`` is 0 to use all available hardware breakpoints, since
    the function may is called in multiple threads concurrently.
* The ``sp_offset`` is 0 because ``buf`` is located at the top of the
    stack frame, buf==sp while i=0.
* The ``watch_len`` is 8, for the size of a ``ulong`` on x86_64.

Parameters with a value of 0 can be omitted as they are defaults.
Configure the watch with the following command:

.. code-block:: bash

	echo "fn=test_mthread_victim fo=0x49 wl=8" > /proc/kstackwatch

Then, rerun the test:

.. code-block:: bash

	echo test4 >/proc/kstackwatch_test

the dmesg log will show the following:

.. code-block:: log

	[    9.308476] kstackwatch: ========== KStackWatch: Caught stack corruption =======
	[    9.308477] kstackwatch: config fn=test_mthread_victim fo=0x49 wl=8
	[    9.308478] CPU: 3 UID: 0 PID: 339 Comm: corrupting Not tainted 6.17.0-rc6-00050-g0c6a0205a183-dirty #214 PREEMPT(voluntary)
	[    9.308480] Call Trace:
	[    9.308482]  <#DB>
	[    9.308482]  dump_stack_lvl+0x66/0xa0
	[    9.308486]  ksw_watch_handler.part.0+0x2b/0x60
	[    9.308488]  ksw_watch_handler+0xa2/0x130
	[    9.308490]  ? test_mthread_corrupting+0x4f/0xe0
	[    9.308491]  ? kthread+0x10d/0x210
	[    9.308493]  ? ret_from_fork+0x187/0x1e0
	[    9.308495]  ? ret_from_fork_asm+0x1a/0x30
	[    9.308498]  __perf_event_overflow+0x154/0x570
	[    9.308501]  perf_bp_event+0xb4/0xc0
	[    9.308506]  ? look_up_lock_class+0x6b/0x150
	[    9.308508]  hw_breakpoint_exceptions_notify+0xf7/0x110
	[    9.308511]  notifier_call_chain+0x44/0x110
	[    9.308513]  atomic_notifier_call_chain+0x5f/0x110
	[    9.308515]  notify_die+0x4c/0xb0
	[    9.308517]  exc_debug_kernel+0xaf/0x170
	[    9.308518]  asm_exc_debug+0x1e/0x40
	[    9.308519] RIP: 0010:test_mthread_corrupting+0x4f/0xe0
	[    9.308520] Code: d7 05 f2 00 48 85 c0 74 dd eb 2e bb 00 00 00 00 eb 57 90 0f 0b 90 eb 76 48 63 c2 48 c1 e0 03 48 03 03 be cd ab cd ab 48 89 30 <83> c2 01 39 ca 7c e7 48 89 ef e8 62 5b d4 ff be 00 00 00 00 48 c7
	[    9.308521] RSP: 0018:ffffc90000ccbed8 EFLAGS: 00000286
	[    9.308523] RAX: ffffc90000a43e28 RBX: ffff888102fc1980 RCX: 0000000000000004
	[    9.308523] RDX: 0000000000000000 RSI: 00000000abcdabcd RDI: ffffc90000ccbe10
	[    9.308524] RBP: ffff888102fc1988 R08: 0000000000000001 R09: 0000000000000000
	[    9.308524] R10: 0000000000000001 R11: 0000000000000000 R12: ffff88810235d040
	[    9.308525] R13: ffff888100b25c00 R14: ffffffff815ce1d0 R15: 0000000000000000
	[    9.308525]  ? __pfx_test_mthread_corrupting+0x10/0x10
	[    9.308529]  </#DB>
	[    9.308529]  <TASK>
	[    9.308529]  kthread+0x10d/0x210
	[    9.308531]  ? __pfx_kthread+0x10/0x10
	[    9.308533]  ret_from_fork+0x187/0x1e0
	[    9.308534]  ? __pfx_kthread+0x10/0x10
	[    9.308535]  ret_from_fork_asm+0x1a/0x30
	[    9.308538]  </TASK>
	[    9.308538] kstackwatch: =================== KStackWatch End ===================
	[    9.309823] kstackwatch_test: victim[0][0]: happy
	[    9.309841] kstackwatch_test: victim[4][0]: unhappy buf[0]=0xabcdabcd

The line ``RIP: 0010:test_mthread_corrupting+0x4f/0xe0`` shows the exact
location where the corruption occurred.

Note the log sequence: KStackWatch reports the corruption before the victim
function signals unhappy. This is also earlier than when __stack_chk_fail would
report the issue in a stack canary corruption case (e.g., test 1).

More usage examples and corruption scenarios are provided in
``kstackwatch_test.sh`` and ``mm/kstackwatch/test.c``.

Limitations
===========

* Limited by available hardware breakpoints
* Only one function can be watched at a time