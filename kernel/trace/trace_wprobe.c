// SPDX-License-Identifier: GPL-2.0
/*
 * Hardware-breakpoint-based tracing events
 *
 * Copyright (C) 2023, Masami Hiramatsu <mhiramat@kernel.org>
 */
#define pr_fmt(fmt)	"trace_wprobe: " fmt

#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/rculist.h>
#include <linux/sched/clock.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/irq_work.h>
#include <linux/preempt.h>

#include <asm/ptrace.h>

#include "trace.h"
#include "trace_btf.h"
#include "trace_dynevent.h"
#include "trace_probe.h"
#include "trace_probe_kernel.h"
#include "trace_probe_tmpl.h"
#include "trace_output.h"

#define WPROBE_EVENT_SYSTEM "wprobes"

static int trace_wprobe_create(const char *raw_command);
static int trace_wprobe_show(struct seq_file *m, struct dyn_event *ev);
static int trace_wprobe_release(struct dyn_event *ev);
static bool trace_wprobe_is_busy(struct dyn_event *ev);
static bool trace_wprobe_match(const char *system, const char *event,
			       int argc, const char **argv, struct dyn_event *ev);

static struct dyn_event_operations trace_wprobe_ops = {
	.create = trace_wprobe_create,
	.show = trace_wprobe_show,
	.is_busy = trace_wprobe_is_busy,
	.free = trace_wprobe_release,
	.match = trace_wprobe_match,
};

struct trace_wprobe;

/* Per-CPU request to re-point that CPU's breakpoints to the current addresses. */
struct wprobe_cpu_update {
	struct irq_work		work;
	struct trace_wprobe	*tw;
	/* When this CPU last broadcast an arming update. */
	u64			last_arm_ipi;
};

/* One hardware watchpoint of the event, installed on every CPU. */
struct wprobe_slot {
	struct trace_wprobe	*tw;
	struct perf_event * __percpu *bp_event;
	unsigned long		addr;
	/* When a trigger armed it, for eviction. */
	u64			armed_at;
	/* When it is closed if no clear comes (jiffies), 0 for never. */
	unsigned long		expires;
	/* The wprobe event file to soft-disable, set by the arming trigger. */
	struct trace_event_file	*file;
};

struct trace_wprobe {
	struct dyn_event	devent;
	struct wprobe_cpu_update __percpu *update;
	struct wprobe_slot	*slots;
	unsigned int		max_slots;	/* as requested */
	unsigned int		nr_slots;	/* registered, 0 while disabled */
	unsigned long		addr;
	int			offset;
	int			len;
	int			type;
	const char		*symbol;
	raw_spinlock_t		lock;
	struct timer_list	expire_timer;
	/* Registered set triggers, and those with a timeout. */
	unsigned int		nr_set;
	unsigned int		nr_timeouts;
	unsigned long		expire_period;	/* how often to check for expiry */
	atomic_t		missed;
	atomic_t		ipi_suppressed;
	atomic_t		evicted;
	atomic_t		expired;
	struct trace_probe	tp;
};

#ifdef CONFIG_WPROBE_TRIGGERS
static void wprobe_expire_timer_func(struct timer_list *t);
static void wprobe_timer_kick(struct trace_wprobe *tw);

/* Deferrable: expiring a window late on an idle CPU costs nothing. */
static inline void wprobe_timer_setup(struct trace_wprobe *tw)
{
	timer_setup(&tw->expire_timer, wprobe_expire_timer_func, TIMER_DEFERRABLE);
}

static inline void wprobe_timer_stop(struct trace_wprobe *tw)
{
	timer_delete_sync(&tw->expire_timer);
}
#else
static inline void wprobe_timer_setup(struct trace_wprobe *tw) { }
static inline void wprobe_timer_stop(struct trace_wprobe *tw) { }
static inline void wprobe_timer_kick(struct trace_wprobe *tw) { }
#endif

static bool is_trace_wprobe(struct dyn_event *ev)
{
	return ev->ops == &trace_wprobe_ops;
}

static struct trace_wprobe *to_trace_wprobe(struct dyn_event *ev)
{
	return container_of(ev, struct trace_wprobe, devent);
}

#define for_each_trace_wprobe(pos, dpos)			\
	for_each_dyn_event(dpos)				\
		if (is_trace_wprobe(dpos) && (pos = to_trace_wprobe(dpos)))

static bool trace_wprobe_is_busy(struct dyn_event *ev)
{
	struct trace_wprobe *tw = to_trace_wprobe(ev);

	return trace_probe_is_enabled(&tw->tp);
}

static bool trace_wprobe_match(const char *system, const char *event,
			       int argc, const char **argv, struct dyn_event *ev)
{
	struct trace_wprobe *tw = to_trace_wprobe(ev);

	if (event[0] != '\0' && strcmp(trace_probe_name(&tw->tp), event))
		return false;

	if (system && strcmp(trace_probe_group_name(&tw->tp), system))
		return false;

	return trace_probe_match_command_args(&tw->tp, argc, argv);
}

/*
 * Note that we don't verify the fetch_insn code, since it does not come
 * from user space.
 */
static int
process_fetch_insn(struct fetch_insn *code, void *rec, void *edata,
		   void *dest, void *base)
{
	void *baddr = rec;
	unsigned long val;
	int ret;

retry:
	/* 1st stage: get value from context */
	switch (code->op) {
	case FETCH_OP_BADDR:
		val = (unsigned long)baddr;
		break;
	case FETCH_NOP_SYMBOL:	/* Ignore a place holder */
		code++;
		goto retry;
	default:
		ret = process_common_fetch_insn(code, &val);
		if (ret < 0)
			return ret;
	}
	code++;

	return process_fetch_insn_bottom(code, val, dest, base);
}
NOKPROBE_SYMBOL(process_fetch_insn)

static void wprobe_trace_handler(struct trace_wprobe *tw,
				 unsigned long addr,
				 struct pt_regs *regs,
				 struct trace_event_file *trace_file)
{
	struct wprobe_trace_entry_head *entry;
	struct trace_event_call *call = trace_probe_event_call(&tw->tp);
	struct trace_event_buffer fbuffer;
	int dsize;

	if (WARN_ON_ONCE(call != trace_file->event_call))
		return;

	if (trace_trigger_soft_disabled(trace_file))
		return;

	dsize = __get_data_size(&tw->tp, (void *)addr, NULL);

	entry = trace_event_buffer_reserve(&fbuffer, trace_file,
					   sizeof(*entry) + tw->tp.size + dsize);
	if (!entry)
		return;

	entry->ip = instruction_pointer(regs);
	store_trace_args(&entry[1], &tw->tp, (void *)addr, NULL, sizeof(*entry), dsize);

	fbuffer.regs = regs;
	trace_event_buffer_commit(&fbuffer);
}

static void wprobe_perf_handler(struct perf_event *bp,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	struct wprobe_slot *slot = bp->overflow_handler_context;
	struct trace_wprobe *tw = slot->tw;
	struct event_file_link *link;
	unsigned long addr = bp->attr.bp_addr;

	/* This CPU has not caught up with a trigger yet. */
	if (READ_ONCE(slot->addr) != addr)
		return;

	trace_probe_for_each_link_rcu(link, &tw->tp)
		wprobe_trace_handler(tw, addr, regs, link->file);
}

/* Wait for the update requests in flight, they may still use the slots. */
static void wprobe_sync_updates(struct trace_wprobe *tw)
{
	int cpu;

	for_each_possible_cpu(cpu)
		irq_work_sync(&per_cpu_ptr(tw->update, cpu)->work);
}

static int __register_trace_wprobe(struct trace_wprobe *tw)
{
	struct perf_event * __percpu *bp_event;
	struct perf_event_attr attr;
	unsigned long flags;
	unsigned int i;
	int ret;

	if (tw->nr_slots)
		return -EINVAL;

	for (i = 0; i < tw->tp.nr_args; i++) {
		ret = traceprobe_update_arg(&tw->tp.args[i]);
		if (ret)
			return ret;
	}

	hw_breakpoint_init(&attr);
	attr.bp_len = tw->len;
	attr.bp_type = tw->type;

	/*
	 * Best effort: the debug registers are shared with the other users of
	 * hardware breakpoints, so take what is available up to the request.
	 */
	for (i = 0; i < tw->max_slots; i++) {
		struct wprobe_slot *slot = &tw->slots[i];

		slot->addr = tw->addr;
		slot->armed_at = 0;
		slot->expires = 0;
		slot->file = NULL;
		attr.bp_addr = slot->addr;
		bp_event = register_wide_hw_breakpoint(&attr, wprobe_perf_handler, slot);
		if (IS_ERR_PCPU(bp_event)) {
			if (i)
				break;
			return PTR_ERR_PCPU(bp_event);
		}
		slot->bp_event = bp_event;
	}
	if (i < tw->max_slots)
		pr_info("%s: %u of %u watch slots available\n",
			trace_probe_name(&tw->tp), i, tw->max_slots);

	/* The trigger uses the slots under tw->lock, publish them there. */
	raw_spin_lock_irqsave(&tw->lock, flags);
	tw->nr_slots = i;
	raw_spin_unlock_irqrestore(&tw->lock, flags);
	wprobe_timer_kick(tw);

	return 0;
}

static void __unregister_trace_wprobe(struct trace_wprobe *tw)
{
	unsigned long flags;
	unsigned int i, nr;

	/* Retract them first so that no trigger touches a dying breakpoint. */
	raw_spin_lock_irqsave(&tw->lock, flags);
	nr = tw->nr_slots;
	tw->nr_slots = 0;
	raw_spin_unlock_irqrestore(&tw->lock, flags);

	if (!nr)
		return;

	wprobe_timer_stop(tw);
	wprobe_sync_updates(tw);
	for (i = 0; i < nr; i++) {
		unregister_wide_hw_breakpoint(tw->slots[i].bp_event);
		tw->slots[i].bp_event = NULL;
	}
}

/* Re-point this CPU's breakpoints to the current addresses of the slots. */
static void wprobe_update_local_cpu(struct trace_wprobe *tw)
{
	unsigned int i, nr = READ_ONCE(tw->nr_slots);

	for (i = 0; i < nr; i++) {
		struct wprobe_slot *slot = &tw->slots[i];
		struct perf_event * __percpu *bp_event = READ_ONCE(slot->bp_event);
		unsigned long addr = READ_ONCE(slot->addr);
		struct perf_event *bp;

		if (!bp_event)
			continue;
		bp = *this_cpu_ptr(bp_event);
		/* bp->attr.bp_addr is what this CPU watches right now. */
		if (!bp || READ_ONCE(bp->attr.bp_addr) == addr)
			continue;
		if (modify_local_hw_breakpoint_addr(bp, addr))
			atomic_inc(&tw->missed);
	}
}

/* Runs on a CPU asked to catch up, in hard interrupt context. */
static void wprobe_update_work_func(struct irq_work *work)
{
	struct wprobe_cpu_update *update = container_of(work, struct wprobe_cpu_update, work);

	wprobe_update_local_cpu(update->tw);
}

static void free_trace_wprobe(struct trace_wprobe *tw)
{
	if (tw) {
		wprobe_timer_stop(tw);
		if (tw->update) {
			wprobe_sync_updates(tw);
			free_percpu(tw->update);
		}
		trace_probe_cleanup(&tw->tp);
		kfree(tw->slots);
		kfree(tw->symbol);
		kfree(tw);
	}
}
DEFINE_FREE(free_trace_wprobe, struct trace_wprobe *,
	if (!IS_ERR_OR_NULL(_T))
		free_trace_wprobe(_T))


static struct trace_wprobe *alloc_trace_wprobe(const char *group,
					       const char *event,
					       const char *symbol,
					       int offset,
					       unsigned long addr,
					       int len, int type,
					       unsigned int max_slots, int nargs)
{
	struct trace_wprobe *tw __free(free_trace_wprobe) = NULL;
	unsigned int i;
	int ret, cpu;

	tw = kzalloc_flex(*tw, tp.args, nargs);
	if (!tw)
		return ERR_PTR(-ENOMEM);

	raw_spin_lock_init(&tw->lock);
	wprobe_timer_setup(tw);
	atomic_set(&tw->missed, 0);
	atomic_set(&tw->ipi_suppressed, 0);
	atomic_set(&tw->evicted, 0);
	atomic_set(&tw->expired, 0);

	tw->update = alloc_percpu(struct wprobe_cpu_update);
	if (!tw->update)
		return ERR_PTR(-ENOMEM);
	for_each_possible_cpu(cpu) {
		struct wprobe_cpu_update *update = per_cpu_ptr(tw->update, cpu);

		update->work = IRQ_WORK_INIT_HARD(wprobe_update_work_func);
		update->tw = tw;
	}

	tw->max_slots = max_slots;
	tw->slots = kcalloc(max_slots, sizeof(*tw->slots), GFP_KERNEL);
	if (!tw->slots)
		return ERR_PTR(-ENOMEM);
	for (i = 0; i < max_slots; i++)
		tw->slots[i].tw = tw;

	if (symbol) {
		tw->symbol = kstrdup(symbol, GFP_KERNEL);
		if (!tw->symbol)
			return ERR_PTR(-ENOMEM);
	}
	tw->offset = offset;
	tw->addr = addr;
	tw->len = len;
	tw->type = type;

	ret = trace_probe_init(&tw->tp, event, group, false, nargs);
	if (ret < 0)
		return ERR_PTR(ret);

	dyn_event_init(&tw->devent, &trace_wprobe_ops);
	return_ptr(tw);
}

static struct trace_wprobe *find_trace_wprobe(const char *event,
					      const char *group)
{
	struct dyn_event *pos;
	struct trace_wprobe *tw;

	for_each_trace_wprobe(tw, pos)
		if (strcmp(trace_probe_name(&tw->tp), event) == 0 &&
		    strcmp(trace_probe_group_name(&tw->tp), group) == 0)
			return tw;
	return NULL;
}

static enum print_line_t
print_wprobe_event(struct trace_iterator *iter, int flags,
		   struct trace_event *event)
{
	struct wprobe_trace_entry_head *field;
	struct trace_seq *s = &iter->seq;
	struct trace_probe *tp;

	field = (struct wprobe_trace_entry_head *)iter->ent;
	tp = trace_probe_primary_from_call(
		container_of(event, struct trace_event_call, event));
	if (WARN_ON_ONCE(!tp))
		goto out;

	trace_seq_printf(s, "%s: (", trace_probe_name(tp));

	if (!seq_print_ip_sym_offset(s, field->ip, flags))
		goto out;

	trace_seq_putc(s, ')');

	if (trace_probe_print_args(s, tp->args, tp->nr_args,
			     (u8 *)&field[1], field) < 0)
		goto out;

	trace_seq_putc(s, '\n');
out:
	return trace_handle_return(s);
}

static int wprobe_event_define_fields(struct trace_event_call *event_call)
{
	int ret;
	struct wprobe_trace_entry_head field;
	struct trace_probe *tp;

	tp = trace_probe_primary_from_call(event_call);
	if (WARN_ON_ONCE(!tp))
		return -ENOENT;

	DEFINE_FIELD(unsigned long, ip, FIELD_STRING_IP, 0);

	return traceprobe_define_arg_fields(event_call, sizeof(field), tp);
}

static struct trace_event_functions wprobe_funcs = {
	.trace	= print_wprobe_event
};

static struct trace_event_fields wprobe_fields_array[] = {
	{ .type = TRACE_FUNCTION_TYPE,
	  .define_fields = wprobe_event_define_fields },
	{}
};

static int wprobe_register(struct trace_event_call *event,
			   enum trace_reg type, void *data);

static inline void init_trace_event_call(struct trace_wprobe *tw)
{
	struct trace_event_call *call = trace_probe_event_call(&tw->tp);

	call->event.funcs = &wprobe_funcs;
	call->class->fields_array = wprobe_fields_array;
	call->flags = TRACE_EVENT_FL_WPROBE;
	call->class->reg = wprobe_register;
}

static int register_wprobe_event(struct trace_wprobe *tw)
{
	init_trace_event_call(tw);
	return trace_probe_register_event_call(&tw->tp);
}

static int register_trace_wprobe_event(struct trace_wprobe *tw)
{
	struct trace_wprobe *old_tw;
	int ret;

	guard(mutex)(&event_mutex);

	old_tw = find_trace_wprobe(trace_probe_name(&tw->tp),
				   trace_probe_group_name(&tw->tp));
	if (old_tw) {
		/*
		 * Wprobe does not support sibling probes because the event
		 * trigger (set_wprobe/clear_wprobe) identifies the target
		 * wprobe by its event name. Having multiple wprobes sharing
		 * the same event name would make the target ambiguous.
		 */
		trace_probe_log_set_index(0);
		trace_probe_log_err(0, WPROBE_NO_SIBLING);
		return -EBUSY;
	}

	ret = register_wprobe_event(tw);
	if (ret) {
		trace_probe_log_set_index(0);
		if (ret == -EEXIST)
			trace_probe_log_err(0, EVENT_EXIST);
		else if (ret != -ENOMEM)
			trace_probe_log_err(0, FAIL_REG_PROBE);
		return ret;
	}

	dyn_event_add(&tw->devent, trace_probe_event_call(&tw->tp));
	return 0;
}
static int unregister_wprobe_event(struct trace_wprobe *tw)
{
	return trace_probe_unregister_event_call(&tw->tp);
}

static int unregister_trace_wprobe(struct trace_wprobe *tw)
{
	if (trace_probe_has_sibling(&tw->tp))
		goto unreg;

	if (trace_probe_is_enabled(&tw->tp))
		return -EBUSY;

	if (trace_event_dyn_busy(trace_probe_event_call(&tw->tp)))
		return -EBUSY;

	if (unregister_wprobe_event(tw))
		return -EBUSY;

unreg:
	__unregister_trace_wprobe(tw);
	dyn_event_remove(&tw->devent);
	trace_probe_unlink(&tw->tp);

	return 0;
}

static int enable_trace_wprobe(struct trace_event_call *call,
			       struct trace_event_file *file)
{
	struct trace_probe *tp;
	struct trace_wprobe *tw;
	bool enabled;
	int ret = 0;

	tp = trace_probe_primary_from_call(call);
	if (WARN_ON_ONCE(!tp))
		return -ENODEV;
	enabled = trace_probe_is_enabled(tp);

	if (file) {
		ret = trace_probe_add_file(tp, file);
		if (ret)
			return ret;
	} else {
		trace_probe_set_flag(tp, TP_FLAG_PROFILE);
	}

	if (!enabled) {
		list_for_each_entry(tw, trace_probe_probe_list(tp), tp.list) {
			ret = __register_trace_wprobe(tw);
			if (ret < 0) {
				struct trace_wprobe *tmp;

				list_for_each_entry(tmp, trace_probe_probe_list(tp), tp.list) {
					if (tmp == tw)
						break;
					__unregister_trace_wprobe(tmp);
				}
				if (file)
					trace_probe_remove_file(tp, file);
				else
					trace_probe_clear_flag(tp, TP_FLAG_PROFILE);
				return ret;
			}
		}
	}

	return 0;
}

static int disable_trace_wprobe(struct trace_event_call *call,
				struct trace_event_file *file)
{
	struct trace_wprobe *tw;
	struct trace_probe *tp;

	tp = trace_probe_primary_from_call(call);
	if (WARN_ON_ONCE(!tp))
		return -ENODEV;

	if (file) {
		if (!trace_probe_get_file_link(tp, file))
			return -ENOENT;
		if (!trace_probe_has_single_file(tp))
			goto out;
		trace_probe_clear_flag(tp, TP_FLAG_TRACE);
	} else {
		trace_probe_clear_flag(tp, TP_FLAG_PROFILE);
	}

	if (!trace_probe_is_enabled(tp)) {
		list_for_each_entry(tw, trace_probe_probe_list(tp), tp.list) {
			__unregister_trace_wprobe(tw);
		}
	}

out:
	if (file)
		trace_probe_remove_file(tp, file);

	return 0;
}

static int wprobe_register(struct trace_event_call *event,
			   enum trace_reg type, void *data)
{
	struct trace_event_file *file = data;

	switch (type) {
	case TRACE_REG_REGISTER:
		return enable_trace_wprobe(event, file);
	case TRACE_REG_UNREGISTER:
		return disable_trace_wprobe(event, file);

#ifdef CONFIG_PERF_EVENTS
	case TRACE_REG_PERF_REGISTER:
	case TRACE_REG_PERF_UNREGISTER:
	case TRACE_REG_PERF_OPEN:
	case TRACE_REG_PERF_CLOSE:
	case TRACE_REG_PERF_ADD:
	case TRACE_REG_PERF_DEL:
		return -EOPNOTSUPP;
#endif
	}
	return 0;
}

static bool trace_wprobe_is_valid_addr(unsigned long addr, int len)
{
	if (addr < TASK_SIZE)
		return false;

	if (addr & (len - 1))
		return false;

	return true;
}

#ifdef CONFIG_WPROBE_TRIGGERS
static u64 wprobe_trigger_clear_target __aligned(8);
#define WPROBE_DEFAULT_CLEAR_ADDRESS ((unsigned long)&wprobe_trigger_clear_target)
#endif

static int parse_address_spec(const char *spec, unsigned long *addr, int *type,
			      int *len, char **symbol, int *offset)
{
	char *_spec __free(kfree) = NULL;
	int _len = HW_BREAKPOINT_LEN_4;
	int _type = HW_BREAKPOINT_RW;
	unsigned long _addr = 0;
	int _offset = 0;
	char *at, *col;

	_spec = kstrdup(spec, GFP_KERNEL);
	if (!_spec)
		return -ENOMEM;

	at = strchr(_spec, '@');
	col = strchr(_spec, ':');

	if (!at) {
		trace_probe_log_err(0, BAD_ACCESS_FMT);
		return -EINVAL;
	}

	if (at != _spec) {
		*at = '\0';

		if (strcmp(_spec, "r") == 0)
			_type = HW_BREAKPOINT_R;
		else if (strcmp(_spec, "w") == 0)
			_type = HW_BREAKPOINT_W;
		else if (strcmp(_spec, "rw") == 0)
			_type = HW_BREAKPOINT_RW;
		else {
			trace_probe_log_err(0, BAD_ACCESS_TYPE);
			return -EINVAL;
		}
	}

	if (col) {
		*col = '\0';
		if (kstrtoint(col + 1, 0, &_len)) {
			trace_probe_log_err(col + 1 - _spec, BAD_ACCESS_LEN);
			return -EINVAL;
		}

		switch (_len) {
		case 1:
			_len = HW_BREAKPOINT_LEN_1;
			break;
		case 2:
			_len = HW_BREAKPOINT_LEN_2;
			break;
		case 4:
			_len = HW_BREAKPOINT_LEN_4;
			break;
		case 8:
			_len = HW_BREAKPOINT_LEN_8;
			break;
		default:
			trace_probe_log_err(col + 1 - _spec, BAD_ACCESS_LEN);
			return -EINVAL;
		}
	}

#ifdef CONFIG_WPROBE_TRIGGERS
	if (strcmp(at + 1, "-1") == 0) {
		_addr = WPROBE_DEFAULT_CLEAR_ADDRESS;
	} else if (kstrtoul(at + 1, 0, &_addr) != 0) {
#else
	if (kstrtoul(at + 1, 0, &_addr) != 0) {
#endif
		char *off_str = strpbrk(at + 1, "+-");

		if (off_str) {
			if (kstrtoint(off_str, 0, &_offset) != 0) {
				trace_probe_log_err(off_str - _spec, BAD_PROBE_ADDR);
				return -EINVAL;
			}
			*off_str = '\0';
		}
		_addr = kallsyms_lookup_name(at + 1);
		if (!_addr) {
			trace_probe_log_err(at + 1 - _spec, BAD_ACCESS_ADDR);
			return -ENOENT;
		}
		_addr += _offset;
		*symbol = kstrdup(at + 1, GFP_KERNEL);
		if (!*symbol)
			return -ENOMEM;
	}

	if (!trace_wprobe_is_valid_addr(_addr, _len)) {
		trace_probe_log_err(at + 1 - _spec, BAD_ACCESS_ADDR);
		return -EINVAL;
	}

	*addr = _addr;
	*offset = _offset;
	*type = _type;
	*len = _len;
	return 0;
}

static int __trace_wprobe_create(int argc, const char *argv[])
{
	/*
	 * Argument syntax:
	 *  w[SLOTS][:[GRP/][EVENT]] SPEC
	 *
	 * SPEC:
	 *  [r|w|rw]@[ADDR|SYMBOL[+OFFS]][:LEN]
	 */
	struct traceprobe_parse_context *ctx __free(traceprobe_parse_context) = NULL;
	struct trace_wprobe *tw __free(free_trace_wprobe) = NULL;
	const char *event = NULL, *group = WPROBE_EVENT_SYSTEM;
	const char *tplog __free(trace_probe_log_clear) = NULL;
	char *symbol __free(kfree) = NULL;
	char *gbuf __free(kfree) = NULL;
	char *ebuf __free(kfree) = NULL;
	char *nbuf __free(kfree) = NULL;
	unsigned int max_slots = 1;
	unsigned long addr;
	int len, type, offset, i;
	int ret;

	if (argv[0][0] != 'w')
		return -ECANCELED;

	tplog = trace_probe_log_init("wprobe", argc, argv);

	if (argc < 2) {
		trace_probe_log_set_index(0);
		trace_probe_log_err(0, NO_ARG_BODY);
		return -EINVAL;
	}

	if (argv[0][1] != '\0') {
		event = strchr(&argv[0][1], ':');
		if (event)
			event++;
		/* wN: the number of hardware watchpoints, see the triggers. */
		if (argv[0][1] != ':') {
			const char *end = event ? event - 1 : argv[0] + strlen(argv[0]);

			trace_probe_log_set_index(0);
			nbuf = kmemdup_nul(&argv[0][1], end - &argv[0][1], GFP_KERNEL);
			if (!nbuf)
				return -ENOMEM;
			if (kstrtouint(nbuf, 0, &max_slots) || !max_slots) {
				trace_probe_log_err(1, WPROBE_BAD_SLOTS);
				return -EINVAL;
			}
			if (max_slots > hw_breakpoint_slots(TYPE_DATA)) {
				trace_probe_log_err(1, WPROBE_TOO_MANY_SLOTS);
				return -EINVAL;
			}
		}
	}

	trace_probe_log_set_index(1);
	ret = parse_address_spec(argv[1], &addr, &type, &len, &symbol, &offset);
	if (ret < 0)
		return ret;

	trace_probe_log_set_index(0);
	if (event) {
		gbuf = kmalloc(MAX_EVENT_NAME_LEN, GFP_KERNEL);
		if (!gbuf)
			return -ENOMEM;
		ret = traceprobe_parse_event_name(&event, &group, gbuf,
						  event - argv[0]);
		if (ret)
			return ret;
	}

	if (!event) {
		/* Make a new event name */
		ebuf = kmalloc(MAX_EVENT_NAME_LEN, GFP_KERNEL);
		if (!ebuf)
			return -ENOMEM;
		if (symbol)
			snprintf(ebuf, MAX_EVENT_NAME_LEN, "%s", symbol);
		else
			snprintf(ebuf, MAX_EVENT_NAME_LEN, "w_0x%lx", addr);
		sanitize_event_name(ebuf);
		event = ebuf;
	}

	argc -= 2; argv += 2;
	if (argc > MAX_TRACE_ARGS) {
		trace_probe_log_set_index(2);
		trace_probe_log_err(0, TOO_MANY_ARGS);
		return -E2BIG;
	}
	tw = alloc_trace_wprobe(group, event, symbol, offset, addr, len, type,
				max_slots, argc);
	if (IS_ERR(tw))
		return PTR_ERR(tw);

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	ctx->flags = TPARG_FL_KERNEL | TPARG_FL_WPROBE;

	/* parse arguments */
	for (i = 0; i < argc; i++) {
		trace_probe_log_set_index(i + 2);
		ctx->offset = 0;
		ret = traceprobe_parse_probe_arg(&tw->tp, i, argv[i], ctx);
		if (ret)
			return ret;	/* This can be -ENOMEM */
	}

	ret = traceprobe_set_print_fmt(&tw->tp, PROBE_PRINT_NORMAL);
	if (ret < 0)
		return ret;

	ret = register_trace_wprobe_event(tw);
	if (!ret)
		tw = NULL; /* To avoid free */

	return ret;
}

static int trace_wprobe_create(const char *raw_command)
{
	return trace_probe_create(raw_command, __trace_wprobe_create);
}

static int trace_wprobe_release(struct dyn_event *ev)
{
	struct trace_wprobe *tw = to_trace_wprobe(ev);
	int ret = unregister_trace_wprobe(tw);

	if (!ret)
		free_trace_wprobe(tw);
	return ret;
}

static int trace_wprobe_show(struct seq_file *m, struct dyn_event *ev)
{
	struct trace_wprobe *tw = to_trace_wprobe(ev);
	const char *type_str;
	int i, len;

	if (tw->max_slots > 1)
		seq_printf(m, "w%u", tw->max_slots);
	else
		seq_putc(m, 'w');
	seq_printf(m, ":%s/%s", trace_probe_group_name(&tw->tp),
		   trace_probe_name(&tw->tp));

	if (tw->type == HW_BREAKPOINT_R)
		type_str = "r";
	else if (tw->type == HW_BREAKPOINT_W)
		type_str = "w";
	else
		type_str = "rw";

	if (tw->len == HW_BREAKPOINT_LEN_1)
		len = 1;
	else if (tw->len == HW_BREAKPOINT_LEN_2)
		len = 2;
	else if (tw->len == HW_BREAKPOINT_LEN_4)
		len = 4;
	else
		len = 8;

	if (tw->symbol) {
		if (tw->offset)
			seq_printf(m, " %s@%s%+d:%d", type_str, tw->symbol,
				   tw->offset, len);
		else
			seq_printf(m, " %s@%s:%d", type_str, tw->symbol, len);
#ifdef CONFIG_WPROBE_TRIGGERS
	} else if (tw->addr == WPROBE_DEFAULT_CLEAR_ADDRESS) {
		seq_printf(m, " %s@-1:%d", type_str, len);
#endif
	} else {
		seq_printf(m, " %s@0x%lx:%d", type_str, tw->addr, len);
	}

	for (i = 0; i < tw->tp.nr_args; i++)
		seq_printf(m, " %s=%s", tw->tp.args[i].name, tw->tp.args[i].comm);
	seq_putc(m, '\n');

	return 0;
}

static __init int init_wprobe_trace(void)
{
	return dyn_event_register(&trace_wprobe_ops);
}
fs_initcall(init_wprobe_trace);

#ifdef CONFIG_WPROBE_TRIGGERS

#define SET_WPROBE_STR		"set_wprobe"
#define CLEAR_WPROBE_STR	"clear_wprobe"
#define wprobe_trigger_log_err(file, glob, offs, err) \
	tracing_log_err((file)->tr, "wprobe_trigger", glob, \
			trace_probe_err_text, TP_ERR_##err, offs)

struct wprobe_trigger_data {
	struct rcu_head		rcu;
	struct trace_event_file	*file;
	struct trace_wprobe	*tw;
	int			offset;
	long			adjust;
	const char		*field;
	bool			clear;
	bool			registered;
	/* Close the window after this many jiffies, 0 for never. */
	unsigned long		timeout;
};

/* Minimum spacing between the broadcasts that arm a window, per source CPU. */
#define WPROBE_ARM_IPI_MIN_NS	1000000ULL

/*
 * Ask the other CPUs to re-point their breakpoints to the slots' addresses.
 * Called with interrupts disabled, so no CPU can complete going offline
 * meanwhile.
 *
 * No bookkeeping is needed for requests already in flight: a request that
 * is still pending reads the addresses when it runs, and one queued while
 * its function executes runs it again (irq_work_single() clears the pending
 * bit before the call), so every CPU ends up on the latest addresses.
 *
 * Arming broadcasts are rate limited per source CPU so that a hot window
 * cannot storm the other CPUs with IPIs. While a broadcast is suppressed the
 * other CPUs keep watching the previous address, which the user can see in
 * the ipi_suppressed counter. Disarming is never suppressed: a stale watch
 * would keep firing on the other CPUs.
 */
static void wprobe_update_remote_cpus(struct trace_wprobe *tw, bool arm)
{
	struct wprobe_cpu_update *update = this_cpu_ptr(tw->update);
	int cpu, this_cpu = smp_processor_id();
	u64 now;

	if (arm) {
		now = local_clock();
		if (now - update->last_arm_ipi < WPROBE_ARM_IPI_MIN_NS) {
			atomic_inc(&tw->ipi_suppressed);
			return;
		}
		update->last_arm_ipi = now;
	}

	for_each_online_cpu(cpu) {
		if (cpu != this_cpu)
			irq_work_queue_on(&per_cpu_ptr(tw->update, cpu)->work, cpu);
	}
}

/* The slot helpers are called with tw->lock held. */
static struct wprobe_slot *wprobe_find_slot(struct trace_wprobe *tw, unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < tw->nr_slots; i++) {
		if (tw->slots[i].addr == addr)
			return &tw->slots[i];
	}
	return NULL;
}

static struct wprobe_slot *wprobe_oldest_slot(struct trace_wprobe *tw)
{
	struct wprobe_slot *oldest = &tw->slots[0];
	unsigned int i;

	for (i = 1; i < tw->nr_slots; i++) {
		if (tw->slots[i].armed_at < oldest->armed_at)
			oldest = &tw->slots[i];
	}
	return oldest;
}

static bool wprobe_is_armed(struct trace_wprobe *tw)
{
	unsigned int i;

	for (i = 0; i < tw->nr_slots; i++) {
		if (tw->slots[i].addr != WPROBE_DEFAULT_CLEAR_ADDRESS)
			return true;
	}
	return false;
}

/*
 * The expiry scan runs periodically while the event is enabled and one of
 * its set triggers has a timeout, so that the trigger itself never touches
 * the timer: arming a window only stamps its deadline.
 */
static void wprobe_timer_kick(struct trace_wprobe *tw)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&tw->lock, flags);
	if (tw->nr_timeouts && tw->nr_slots)
		mod_timer(&tw->expire_timer, jiffies + tw->expire_period);
	raw_spin_unlock_irqrestore(&tw->lock, flags);
}

/* A set trigger with a timeout is added. */
static void wprobe_timeout_get(struct trace_wprobe *tw, unsigned long timeout)
{
	unsigned long flags, period = max(timeout / 2, 1UL);

	raw_spin_lock_irqsave(&tw->lock, flags);
	if (!tw->nr_timeouts++ || period < tw->expire_period)
		tw->expire_period = period;
	raw_spin_unlock_irqrestore(&tw->lock, flags);
	wprobe_timer_kick(tw);
}

/* A set trigger with a timeout is removed. */
static void wprobe_timeout_put(struct trace_wprobe *tw)
{
	unsigned long flags;
	bool last;

	raw_spin_lock_irqsave(&tw->lock, flags);
	last = !--tw->nr_timeouts;
	raw_spin_unlock_irqrestore(&tw->lock, flags);
	if (last)
		wprobe_timer_stop(tw);
}

/* Close the windows whose clear never came. */
static void wprobe_expire_timer_func(struct timer_list *t)
{
	struct trace_wprobe *tw = timer_container_of(tw, t, expire_timer);
	bool changed = false;
	unsigned long flags;
	unsigned int i;

	raw_spin_lock_irqsave(&tw->lock, flags);
	for (i = 0; i < tw->nr_slots; i++) {
		struct wprobe_slot *slot = &tw->slots[i];

		if (slot->addr == WPROBE_DEFAULT_CLEAR_ADDRESS || !slot->expires ||
		    time_before(jiffies, slot->expires))
			continue;
		WRITE_ONCE(slot->addr, WPROBE_DEFAULT_CLEAR_ADDRESS);
		slot->expires = 0;
		atomic_inc(&tw->expired);
		if (slot->file && !wprobe_is_armed(tw))
			set_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &slot->file->flags);
		changed = true;
	}
	if (changed) {
		wprobe_update_local_cpu(tw);
		wprobe_update_remote_cpus(tw, false);
	}
	/* Stops on its own once the triggers or the slots are gone. */
	if (tw->nr_timeouts && tw->nr_slots)
		mod_timer(&tw->expire_timer, jiffies + tw->expire_period);
	raw_spin_unlock_irqrestore(&tw->lock, flags);
}

static void wprobe_trigger(struct event_trigger_data *data,
			   struct trace_buffer *buffer,  void *rec,
			   struct ring_buffer_event *event)
{
	struct wprobe_trigger_data *wprobe_data = data->private_data;
	struct trace_wprobe *tw = wprobe_data->tw;
	bool changed = false, evicted = false;
	unsigned long addr = 0, flags;
	struct wprobe_slot *slot;
	unsigned int i;

	if (in_nmi()) {
		atomic_inc(&tw->missed);
		return;
	}

	if (wprobe_data->field) {
		addr = *(unsigned long *)((char *)rec + wprobe_data->offset);
		addr += wprobe_data->adjust;
	}

	raw_spin_lock_irqsave(&tw->lock, flags);

	/* Not enabled: no hardware to program. */
	if (!tw->nr_slots)
		goto out;

	if (!wprobe_data->clear) {
		if (!trace_wprobe_is_valid_addr(addr, tw->len)) {
			atomic_inc(&tw->missed);
			goto out;
		}
		/* Already watched: a nested or concurrent window on the object. */
		if (wprobe_find_slot(tw, addr))
			goto out;
		slot = wprobe_find_slot(tw, WPROBE_DEFAULT_CLEAR_ADDRESS);
		if (!slot) {
			/* All slots busy: the oldest window makes room. */
			slot = wprobe_oldest_slot(tw);
			atomic_inc(&tw->evicted);
			evicted = true;
		}
		WRITE_ONCE(slot->addr, addr);
		slot->armed_at = local_clock();
		slot->file = wprobe_data->file;
		slot->expires = wprobe_data->timeout ? jiffies + wprobe_data->timeout : 0;
		changed = true;
		clear_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &wprobe_data->file->flags);
	} else {
		if (wprobe_data->field) {
			slot = wprobe_find_slot(tw, addr);
			if (slot) {
				WRITE_ONCE(slot->addr, WPROBE_DEFAULT_CLEAR_ADDRESS);
				slot->expires = 0;
				changed = true;
			}
		} else {
			/* No field: forcibly close every window. */
			for (i = 0; i < tw->nr_slots; i++) {
				slot = &tw->slots[i];
				if (slot->addr == WPROBE_DEFAULT_CLEAR_ADDRESS)
					continue;
				WRITE_ONCE(slot->addr, WPROBE_DEFAULT_CLEAR_ADDRESS);
				slot->expires = 0;
				changed = true;
			}
		}
		if (changed && !wprobe_is_armed(tw))
			set_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &wprobe_data->file->flags);
	}

	if (changed) {
		/*
		 * The window opens or closes on this CPU first: re-point the
		 * local breakpoints right away, then ask the others.
		 */
		wprobe_update_local_cpu(tw);
		/* Evicting retires an address too: never hold that back. */
		wprobe_update_remote_cpus(tw, !wprobe_data->clear && !evicted);
	}

out:
	raw_spin_unlock_irqrestore(&tw->lock, flags);
}

/* Bookkeeping for a set trigger that is now registered on its event. */
static void wprobe_set_trigger_added(struct trace_wprobe *tw,
				     struct wprobe_trigger_data *wprobe_data)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&tw->lock, flags);
	tw->nr_set++;
	raw_spin_unlock_irqrestore(&tw->lock, flags);
	wprobe_data->registered = true;
	if (wprobe_data->timeout)
		wprobe_timeout_get(tw, wprobe_data->timeout);
}

/*
 * A registered set trigger goes away. Nothing can close a window any more
 * once the last one is gone, so the last one takes the windows with it.
 */
static void wprobe_set_trigger_removed(struct trace_wprobe *tw,
				       struct wprobe_trigger_data *wprobe_data)
{
	bool changed = false;
	unsigned long flags;
	unsigned int i;

	raw_spin_lock_irqsave(&tw->lock, flags);
	tw->nr_set--;
	for (i = 0; i < tw->nr_slots; i++) {
		struct wprobe_slot *slot = &tw->slots[i];

		/* The file may go away with the trigger. */
		if (slot->file == wprobe_data->file)
			slot->file = NULL;
		if (tw->nr_set || slot->addr == WPROBE_DEFAULT_CLEAR_ADDRESS)
			continue;
		WRITE_ONCE(slot->addr, WPROBE_DEFAULT_CLEAR_ADDRESS);
		slot->expires = 0;
		changed = true;
	}
	if (changed) {
		wprobe_update_local_cpu(tw);
		wprobe_update_remote_cpus(tw, false);
	}
	if (!tw->nr_set)
		set_bit(EVENT_FILE_FL_SOFT_DISABLED_BIT, &wprobe_data->file->flags);
	raw_spin_unlock_irqrestore(&tw->lock, flags);

	if (wprobe_data->timeout)
		wprobe_timeout_put(tw);
}

/* Deferred (trigger_data_free()): the event may be gone, only free memory. */
static void free_wprobe_trigger_data(struct wprobe_trigger_data *wprobe_data)
{
	if (wprobe_data) {
		kfree(wprobe_data->field);
		kfree(wprobe_data);
	}
}
DEFINE_FREE(free_wprobe_trigger_data, struct wprobe_trigger_data *, free_wprobe_trigger_data(_T));

static void free_private_wprobe_trigger_data(struct event_trigger_data *data)
{
	free_wprobe_trigger_data(data->private_data);
}

static int wprobe_trigger_print(struct seq_file *m,
			       struct event_trigger_data *data)
{
	struct wprobe_trigger_data *wprobe_data = data->private_data;
	struct trace_wprobe *tw = wprobe_data->tw;
	int suppressed = atomic_read(&tw->ipi_suppressed);
	int evicted = atomic_read(&tw->evicted);
	int expired = atomic_read(&tw->expired);
	int missed = atomic_read(&tw->missed);

	if (wprobe_data->clear) {
		seq_printf(m, "%s:%s", CLEAR_WPROBE_STR,
			   trace_event_name(wprobe_data->file->event_call));
		if (wprobe_data->field) {
			seq_printf(m, ":%s%+ld",
				   wprobe_data->field, wprobe_data->adjust);
		}
	} else {
		seq_printf(m, "%s:%s:%s%+ld", SET_WPROBE_STR,
			   trace_event_name(wprobe_data->file->event_call),
			   wprobe_data->field, wprobe_data->adjust);
		if (wprobe_data->timeout)
			seq_printf(m, ":timeout=%ums",
				   jiffies_to_msecs(wprobe_data->timeout));
	}

	if (data->count == -1)
		seq_puts(m, ":unlimited");
	else
		seq_printf(m, ":count=%ld", data->count);

	if (data->filter_str)
		seq_printf(m, " if %s", data->filter_str);

	if (tw->max_slots > 1 || missed || suppressed || evicted || expired)
		seq_puts(m, " #");
	if (tw->max_slots > 1)
		seq_printf(m, " slots: %u/%u", READ_ONCE(tw->nr_slots), tw->max_slots);
	if (missed)
		seq_printf(m, " missed: %d", missed);
	if (suppressed)
		seq_printf(m, " ipi_suppressed: %d", suppressed);
	if (evicted)
		seq_printf(m, " evicted: %d", evicted);
	if (expired)
		seq_printf(m, " expired: %d", expired);

	seq_putc(m, '\n');

	return 0;
}

static struct wprobe_trigger_data *
wprobe_trigger_alloc(struct trace_wprobe *tw, struct trace_event_file *file,
		     bool clear)
{
	struct wprobe_trigger_data *wprobe_data;

	wprobe_data = kzalloc_obj(*wprobe_data);
	if (!wprobe_data)
		return NULL;

	wprobe_data->tw = tw;
	wprobe_data->clear = clear;
	wprobe_data->file = file;

	return wprobe_data;
}

static void wprobe_trigger_free(struct event_trigger_data *data)
{
	struct wprobe_trigger_data *wprobe_data = data->private_data;

	if (WARN_ON_ONCE(data->ref <= 0))
		return;

	data->ref--;
	if (!data->ref) {
		/* While the trigger's reference keeps the event alive. */
		if (wprobe_data->registered && !wprobe_data->clear)
			wprobe_set_trigger_removed(wprobe_data->tw, wprobe_data);
		/* Remove the SOFT_MODE flag */
		trace_event_enable_disable(wprobe_data->file, 0, 1);
		trace_event_put_ref(wprobe_data->file->event_call);
		trigger_data_free(data);
	}
}

#ifdef CONFIG_PROBE_EVENTS_BTF_ARGS

static int get_offset_of_field(struct btf *btf, const struct btf_type *type, char *field_name)
{
	const struct btf_member *field;
	const struct btf_type *mtype;
	int bitoffs = 0;
	u32 anon_offs;
	char *next;

	do {
		next = strchr(field_name, '.');
		if (next)
			*next++ = '\0';

		field = btf_find_struct_member(btf, type, field_name, &anon_offs, &mtype);
		if (IS_ERR_OR_NULL(field))
			return -ENOENT;

		if (btf_type_kflag(mtype)) {
			/* Reject bitfield member access */
			if (BTF_MEMBER_BITFIELD_SIZE(field->offset))
				return -EINVAL;
			bitoffs += anon_offs + BTF_MEMBER_BIT_OFFSET(field->offset);
		} else {
			bitoffs += anon_offs + field->offset;
		}

		field_name = next;
		if (next) {
			type = btf_type_skip_modifiers(btf, field->type, NULL);
			if (!type)
				return -ENOENT;
		}
	} while (next);
	return bitoffs / BITS_PER_BYTE;
}

/* btf_put(NULL) is acceptable. */
DEFINE_FREE(btf_put, struct btf *, btf_put(_T))

/* parse typecast: (TYPE[,ASGN])EVENT_FIELD->FIELD[.SUBFIELD...][+-OFFS] and set adjust. */
static int wprobe_trigger_typecast_parse(char *field_str,
					 struct trace_event_file *file,
					 struct wprobe_trigger_data *wprobe_data,
					 const char *glob)
{
	struct btf *btf __free(btf_put) = NULL;
	char *buf __free(kfree) = NULL;
	struct ftrace_event_field *field;
	const struct btf_type *type;
	char *assign_field;
	char *event_field;
	char *type_field;
	char *type_name;
	char *offs;
	long val = 0;
	int base_offset = field_str - glob;
	int event_field_offset;
	int id, adjust;

	buf = kstrdup(field_str, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	type_name = buf + 1;
	event_field = strchr(type_name, ')');
	if (!event_field) {
		wprobe_trigger_log_err(file, glob,
				       base_offset + (type_name - buf),
				       DEREF_OPEN_BRACE);
		return -EINVAL;
	}
	*event_field++ = '\0';

	/* Check the optional assign field. */
	assign_field = strchr(type_name, ',');
	if (assign_field)
		*assign_field++ = '\0';

	/* Get the type field name. */
	type_field = strstr(event_field, "->");
	if (!type_field) {
		wprobe_trigger_log_err(file, glob,
				       base_offset + (event_field - buf),
				       TYPECAST_REQ_FIELD);
		return -EINVAL;
	}
	*type_field = '\0';
	type_field += 2;

	offs = strpbrk(type_field, "+-");
	if (offs) {
		if (kstrtol(offs, 0, &val) < 0) {
			wprobe_trigger_log_err(file, glob,
					       base_offset + (offs - buf),
					       BAD_DEREF_OFFS);
			return -EINVAL;
		}
		*offs = '\0';
	}

	/* find type from BTF */
	id = bpf_find_btf_id(type_name, BTF_KIND_STRUCT, &btf);
	if (id < 0) {
		wprobe_trigger_log_err(file, glob,
				       base_offset + (type_name - buf),
				       BAD_BTF_TID);
		return id;
	}

	type = btf_type_by_id(btf, id);
	if (!type) {
		wprobe_trigger_log_err(file, glob,
				       base_offset + (type_name - buf),
				       BAD_BTF_TID);
		return -EINVAL;
	}

	adjust = get_offset_of_field(btf, type, type_field);
	if (adjust < 0) {
		wprobe_trigger_log_err(file, glob,
				       base_offset + (type_field - buf),
				       NO_BTF_FIELD);
		return adjust;
	}
	wprobe_data->adjust = adjust + val;

	if (assign_field) {
		/* assign_field should be a struct field */
		adjust = get_offset_of_field(btf, type, assign_field);
		if (adjust < 0) {
			wprobe_trigger_log_err(file, glob,
					       base_offset + (assign_field - buf),
					       NO_BTF_FIELD);
			return adjust;
		}
		wprobe_data->adjust -= adjust;
	}

	event_field_offset = base_offset + (event_field - buf);
	field = trace_find_event_field(file->event_call, event_field);
	if (!field) {
		wprobe_trigger_log_err(file, glob, event_field_offset, NO_EVENT_FIELD);
		return -ENOENT;
	}
	if (field->size != sizeof(void *)) {
		wprobe_trigger_log_err(file, glob, event_field_offset, WPROBE_BAD_FIELD);
		return -ENOEXEC;
	}
	wprobe_data->offset = field->offset;
	wprobe_data->field = kstrdup(event_field, GFP_KERNEL);
	if (!wprobe_data->field)
		return -ENOMEM;

	return 0;
}
#else
static int wprobe_trigger_typecast_parse(char *field_str,
					 struct trace_event_file *file,
					 struct wprobe_trigger_data *wprobe_data,
					 const char *glob)
{
	wprobe_trigger_log_err(file, glob, field_str - glob, NOSUP_BTFARG);
	return -EOPNOTSUPP;
}
#endif /* CONFIG_PROBE_EVENTS_BTF_ARGS */

static int wprobe_trigger_field_parse(char *field_str, struct trace_event_file *file,
					struct wprobe_trigger_data *wprobe_data,
					const char *glob)
{
	struct ftrace_event_field *field;
	char *offs;

	if (field_str[0] == '(')
		return wprobe_trigger_typecast_parse(field_str, file, wprobe_data, glob);

	offs = strpbrk(field_str, "+-");
	if (offs) {
		long val;

		if (kstrtol(offs, 0, &val) < 0) {
			wprobe_trigger_log_err(file, glob, offs - glob, BAD_DEREF_OFFS);
			return -EINVAL;
		}
		wprobe_data->adjust = val;
		*offs = '\0';
	}

	field = trace_find_event_field(file->event_call, field_str);
	if (!field) {
		wprobe_trigger_log_err(file, glob, field_str - glob, NO_EVENT_FIELD);
		return -ENOENT;
	}
	if (field->size != sizeof(void *)) {
		wprobe_trigger_log_err(file, glob, field_str - glob, WPROBE_BAD_FIELD);
		return -ENOEXEC;
	}
	wprobe_data->offset = field->offset;
	wprobe_data->field = kstrdup(field_str, GFP_KERNEL);
	if (!wprobe_data->field)
		return -ENOMEM;

	return 0;
}

/* TIME is a number of milliseconds, or of seconds with an "s" suffix. */
static int wprobe_trigger_timeout_parse(const char *str, unsigned long *timeout)
{
	size_t len = strspn(str, "0123456789");
	unsigned long ms;
	char buf[16];

	if (!len || len >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, str, len);
	buf[len] = '\0';
	if (kstrtoul(buf, 10, &ms) || !ms)
		return -EINVAL;

	str += len;
	if (!strcmp(str, "s"))
		ms *= MSEC_PER_SEC;
	else if (*str && strcmp(str, "ms"))
		return -EINVAL;

	*timeout = msecs_to_jiffies(ms);
	return 0;
}

static int wprobe_trigger_cmd_parse(struct event_command *cmd_ops,
				    struct trace_event_file *file,
				    char *glob, char *cmd,
				    char *param_and_filter)
{
	/*
	 * set_wprobe:EVENT:FIELD[+OFFS]
	 * clear_wprobe:EVENT[:FIELD[+OFFS]]
	 */
	struct wprobe_trigger_data *wprobe_data = NULL;
	struct event_trigger_data *trigger_data = NULL;
	struct trace_event_file *wprobe_file;
	char *event_str, *comment;
	struct trace_array *tr = file->tr;
	bool remove, clear = false;
	unsigned long orig_addr = 0;
	struct trace_wprobe *tw;
	char *param, *filter;
	int ret;

	remove = event_trigger_check_remove(glob);

	if (!strcmp(cmd, CLEAR_WPROBE_STR))
		clear = true;

	if (param_and_filter) {
		/* Recover original trigger string to show the error log correctly. */
		if (*(param_and_filter - 1) == '\0')
			*(param_and_filter - 1) = ':';
		comment = strchr(param_and_filter, '#');
		if (comment)
			*comment = '\0';
	}

	if (event_trigger_empty_param(param_and_filter)) {
		wprobe_trigger_log_err(file, glob, strlen(cmd) + 1, WPROBE_NOT_FOUND);
		return -EINVAL;
	}

	ret = event_trigger_separate_filter(param_and_filter, &param, &filter, true);
	if (ret)
		return ret;

	if (file->event_call->flags & TRACE_EVENT_FL_KPROBE) {
		wprobe_trigger_log_err(file, glob, 0, WPROBE_ON_KPROBE);
		return -EOPNOTSUPP;
	}

	event_str = strsep(&param, ":");

	/* Find target wprobe */
	tw = find_trace_wprobe(event_str, WPROBE_EVENT_SYSTEM);
	if (!tw) {
		wprobe_trigger_log_err(file, glob, event_str - glob, WPROBE_NOT_FOUND);
		return -ENOENT;
	}
	/* The target wprobe must not be used (unless clear) */
	if (!remove && !clear && trace_probe_is_enabled(&tw->tp)) {
		wprobe_trigger_log_err(file, glob, event_str - glob, WPROBE_BUSY);
		return -EBUSY;
	}

	wprobe_file = find_event_file(tr, WPROBE_EVENT_SYSTEM, event_str);
	if (!wprobe_file) {
		wprobe_trigger_log_err(file, glob, event_str - glob, WPROBE_NOT_FOUND);
		return -EINVAL;
	}

	wprobe_data = wprobe_trigger_alloc(tw, wprobe_file, clear);
	if (!wprobe_data)
		return -ENOMEM;

	/* clear_wprobe does not need field, but can have optional field. */
	if (!clear) {
		char *field_str = strsep(&param, ":");

		if (!field_str) {
			wprobe_trigger_log_err(file, glob, strlen(glob), WPROBE_NEED_FIELD);
			ret = -EINVAL;
			goto out_free;
		}
		ret = wprobe_trigger_field_parse(field_str, file, wprobe_data, glob);
		if (ret < 0)
			goto out_free;
		if (param && !strncmp(param, "timeout=", 8)) {
			char *tstr = strsep(&param, ":") + 8;

			if (wprobe_trigger_timeout_parse(tstr, &wprobe_data->timeout)) {
				wprobe_trigger_log_err(file, glob, tstr - glob, WPROBE_BAD_TIMEOUT);
				ret = -EINVAL;
				goto out_free;
			}
		}
	} else if (param && !strncmp(param, "timeout=", 8)) {
		wprobe_trigger_log_err(file, glob, param - glob, WPROBE_TIMEOUT_ON_CLEAR);
		ret = -EINVAL;
		goto out_free;
	} else if (param && (isalpha(param[0]) || param[0] == '_' || param[0] == '(')) {
		if (strncmp(param, "count=", 6) != 0 &&
		    strncmp(param, "unlimited", 9) != 0) {
			char *field_str = strsep(&param, ":");

			ret = wprobe_trigger_field_parse(field_str, file, wprobe_data, glob);
			if (ret < 0)
				goto out_free;
		}
	}

	trigger_data = trigger_data_alloc(cmd_ops, cmd, param, wprobe_data);
	if (!trigger_data) {
		ret = -ENOMEM;
		goto out_free;
	}

	trigger_data->private_data_free = free_private_wprobe_trigger_data;

	if (remove) {
		event_trigger_unregister(cmd_ops, file, glob+1, trigger_data);
		trigger_data_free(trigger_data);
		return 0;
	}

	/* Up the trigger_data count to make sure nothing frees it on failure */
	event_trigger_init(trigger_data);

	ret = event_trigger_parse_num(param, trigger_data);
	if (ret) {
		wprobe_trigger_log_err(file, glob, param - glob, BAD_IMM);
		goto out_free_trigger;
	}

	ret = event_trigger_set_filter(cmd_ops, file, filter, trigger_data);
	if (ret < 0)
		goto out_free_trigger;

	/* Soft-enable (register) wprobe event on WPROBE_DEFAULT_CLEAR_ADDRESS */
	if (!trace_event_try_get_ref(wprobe_file->event_call)) {
		ret = -ENODEV;
		goto out_free_trigger;
	}

	if (!clear) {
		orig_addr = tw->addr;
		WRITE_ONCE(tw->addr, WPROBE_DEFAULT_CLEAR_ADDRESS);
	}

	ret = trace_event_enable_disable(wprobe_file, 1, 1);
	if (ret < 0) {
		if (!clear)
			WRITE_ONCE(tw->addr, orig_addr);
		goto out_put;
	}

	ret = event_trigger_register(cmd_ops, file, glob, trigger_data);
	if (ret)
		goto out_disable;

	/* Balance the event_trigger_init() at registration start */
	event_trigger_free(trigger_data);
	return 0;

out_disable:
	if (!clear)
		WRITE_ONCE(tw->addr, orig_addr);
	trace_event_enable_disable(wprobe_file, 0, 1);
out_put:
	trace_event_put_ref(wprobe_file->event_call);
out_free_trigger:
	event_trigger_reset_filter(cmd_ops, trigger_data);
	trigger_data_free(trigger_data);
	return ret;

out_free:
	free_wprobe_trigger_data(wprobe_data);
	return ret;
}

/* Return event_trigger_data if there is a trigger which points the same wprobe */
static struct event_trigger_data *
wprobe_trigger_find_same(struct event_trigger_data *test,
			 struct trace_event_file *file)
{
	struct wprobe_trigger_data *test_wprobe_data = test->private_data;
	struct wprobe_trigger_data *wprobe_data;
	struct event_trigger_data *iter;

	list_for_each_entry(iter, &file->triggers, list) {
		wprobe_data = iter->private_data;
		if (!wprobe_data ||
		    iter->cmd_ops->trigger_type !=
		    test->cmd_ops->trigger_type)
			continue;
		if (wprobe_data->tw == test_wprobe_data->tw &&
		    wprobe_data->clear == test_wprobe_data->clear)
			return iter;
	}
	return NULL;
}

static int wprobe_register_trigger(char *glob,
				   struct event_trigger_data *data,
				   struct trace_event_file *file)
{
	struct wprobe_trigger_data *wprobe_data = data->private_data;
	int ret = 0;

	lockdep_assert_held(&event_mutex);

	/* The same wprobe is not accept on the same file (event) */
	if (wprobe_trigger_find_same(data, file))
		return -EEXIST;

	if (data->cmd_ops->init) {
		ret = data->cmd_ops->init(data);
		if (ret < 0)
			return ret;
	}

	list_add_rcu(&data->list, &file->triggers);

	update_cond_flag(file);
	ret = trace_event_trigger_enable_disable(file, 1);
	if (ret < 0) {
		list_del_rcu(&data->list);
		update_cond_flag(file);
		if (data->cmd_ops->free)
			data->cmd_ops->free(data);
		return ret;
	}

	if (!wprobe_data->clear)
		wprobe_set_trigger_added(wprobe_data->tw, wprobe_data);
	return 0;
}

static void wprobe_unregister_trigger(char *glob,
				      struct event_trigger_data *test,
				      struct trace_event_file *file)
{
	struct event_trigger_data *data;

	lockdep_assert_held(&event_mutex);

	data = wprobe_trigger_find_same(test, file);
	if (!data)
		return;

	list_del_rcu(&data->list);
	trace_event_trigger_enable_disable(file, 0);
	update_cond_flag(file);
	tracepoint_synchronize_unregister();
	if (data->cmd_ops->free)
		data->cmd_ops->free(data);
}

static struct event_command trigger_wprobe_set_cmd = {
	.name			= SET_WPROBE_STR,
	.trigger_type		= ETT_EVENT_WPROBE,
	/* This triggers after when the event is recorded. */
	.flags			= EVENT_CMD_FL_NEEDS_REC,
	.parse			= wprobe_trigger_cmd_parse,
	.reg			= wprobe_register_trigger,
	.unreg			= wprobe_unregister_trigger,
	.set_filter		= set_trigger_filter,
	.trigger		= wprobe_trigger,
	.count_func		= event_trigger_count,
	.print			= wprobe_trigger_print,
	.init			= event_trigger_init,
	.free			= wprobe_trigger_free,
};

static struct event_command trigger_wprobe_clear_cmd = {
	.name			= CLEAR_WPROBE_STR,
	.trigger_type		= ETT_EVENT_WPROBE,
	/* This triggers after when the event is recorded. */
	.flags			= EVENT_CMD_FL_NEEDS_REC,
	.parse			= wprobe_trigger_cmd_parse,
	.reg			= wprobe_register_trigger,
	.unreg			= wprobe_unregister_trigger,
	.set_filter		= set_trigger_filter,
	.trigger		= wprobe_trigger,
	.count_func		= event_trigger_count,
	.print			= wprobe_trigger_print,
	.init			= event_trigger_init,
	.free			= wprobe_trigger_free,
};

static __init int init_trigger_wprobe_cmds(void)
{
	int ret;

	ret = register_event_command(&trigger_wprobe_set_cmd);
	if (WARN_ON(ret < 0))
		return ret;
	ret = register_event_command(&trigger_wprobe_clear_cmd);
	if (WARN_ON(ret < 0))
		unregister_event_command(&trigger_wprobe_set_cmd);

	return ret;
}
fs_initcall(init_trigger_wprobe_cmds);
#endif /* CONFIG_WPROBE_TRIGGERS */
