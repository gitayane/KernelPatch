/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "syscall.h"

#include <cache.h>
#include <ktypes.h>
#include <hook.h>
#include <hotpatch.h>
#include <common.h>
#include <linux/string.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>
#include <asm-generic/compat.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>
#include <kputils.h>
#include <kallsyms.h>
#include <kp_spinlock.h>
#include <linux/kernel.h>
#include <linux/string.h>

uintptr_t *sys_call_table = 0;
KP_EXPORT_SYMBOL(sys_call_table);

uintptr_t *compat_sys_call_table = 0;
KP_EXPORT_SYMBOL(compat_sys_call_table);

int has_syscall_wrapper = 0;
KP_EXPORT_SYMBOL(has_syscall_wrapper);

int has_config_compat = 0;
KP_EXPORT_SYMBOL(has_config_compat);

struct user_arg_ptr
{
    union
    {
        const char __user *const __user *native;
    } ptr;
};

struct user_arg_ptr_compat
{
    bool is_compat;
    union
    {
        const char __user *const __user *native;
        const compat_uptr_t __user *compat;
    } ptr;
};

// actually, a0 is true if it is compat
const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) size = 4; // compat
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    char __user **upptr = memdup_user(native, size);
    if (IS_ERR(upptr)) return ERR_PTR((long)upptr);

    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kfree(upptr);
    return uptr;
}

int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val)
{
    uintptr_t valp = (uintptr_t)&val;
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) {
            size = 4; // compat
            valp += 4;
        }
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    int cplen = compat_copy_to_user((void *)native, (void *)valp, size);
    return cplen == size ? 0 : cplen;
}

typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)();
typedef long (*raw_syscall1_f)(long arg0);
typedef long (*raw_syscall2_f)(long arg0, long arg1);
typedef long (*raw_syscall3_f)(long arg0, long arg1, long arg2);
typedef long (*raw_syscall4_f)(long arg0, long arg1, long arg2, long arg3);
typedef long (*raw_syscall5_f)(long arg0, long arg1, long arg2, long arg3, long arg4);
typedef long (*raw_syscall6_f)(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    const char *name = 0;
    if (!is_compat) {
        if (syscall_name_table[nr].addr) {
            return syscall_name_table[nr].addr;
        }
        name = syscall_name_table[nr].name;
    } else {
        if (compat_syscall_name_table[nr].addr) {
            return compat_syscall_name_table[nr].addr;
        }
        name = compat_syscall_name_table[nr].name;
    }

    if (!name) return 0;

    const char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";
    const char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    uintptr_t addr = 0;

    char buffer[256];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            snprintf(buffer, sizeof(buffer), "%s%s%s", prefix[i], name, suffix[j]);
            addr = kallsyms_lookup_name(buffer);
            if (addr) break;
        }
        if (addr) break;
    }
    if (!is_compat) {
        syscall_name_table[nr].addr = addr;
    } else {
        compat_syscall_name_table[nr].addr = addr;
    }
    return addr;
}
KP_EXPORT_SYMBOL(syscalln_name_addr);

uintptr_t syscalln_addr(int nr, int is_compat)
{
    if (!is_compat && sys_call_table) return sys_call_table[nr];
    if (is_compat && compat_sys_call_table) return compat_sys_call_table[nr];
    return syscalln_name_addr(nr, is_compat);
}
KP_EXPORT_SYMBOL(syscalln_addr);

long raw_syscall0(long nr)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
}
KP_EXPORT_SYMBOL(raw_syscall0);

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}
KP_EXPORT_SYMBOL(raw_syscall1);

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}
KP_EXPORT_SYMBOL(raw_syscall2);

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}
KP_EXPORT_SYMBOL(raw_syscall3);

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}
KP_EXPORT_SYMBOL(raw_syscall4);

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}
KP_EXPORT_SYMBOL(raw_syscall5);

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        regs.regs[5] = arg5;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall6_f)addr)(arg0, arg1, arg2, arg3, arg4, arg5);
}
KP_EXPORT_SYMBOL(raw_syscall6);

/*
 * The dispatcher cannot safely take over after any legacy syscall-table hooks
 * have been installed: a table slot may then point at a hook-chain transit,
 * which is not a syscall handler that the new backend may call as an origin.
 * Record successful legacy registrations before the dispatcher starts and fail
 * closed if the experimental 4.4 backend is ever enabled in that state.
 */
static volatile int syscall_4_4_legacy_slot_hooks_seen;

static void syscall_4_4_note_legacy_slot_hook(void)
{
    if (kver >= VERSION(4, 4, 0) && kver < VERSION(4, 5, 0) &&
        !syscall_hook_global_enabled()) {
        syscall_4_4_legacy_slot_hooks_seen = 1;
    }
}

hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    hook_err_t rc;

    if (kver >= VERSION(4, 4, 0) && kver < VERSION(4, 5, 0) &&
        syscall_hook_global_enabled()) return HOOK_BAD_ADDRESS;

    if (!is_compat) {
        if (!sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        rc = fp_hook_wrap(fp_addr, narg, before, after, udata);
    } else {
        if (!compat_sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        rc = fp_hook_wrap(fp_addr, narg, before, after, udata);
    }

    if (!rc) syscall_4_4_note_legacy_slot_hook();
    return rc;
}
KP_EXPORT_SYMBOL(fp_wrap_syscalln);

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    if (!is_compat) {
        if (!sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    } else {
        if (!compat_sys_call_table) return;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        fp_hook_unwrap(fp_addr, before, after);
    }
}
KP_EXPORT_SYMBOL(fp_unwrap_syscalln);

/*
sys_xxx.cfi_jt

hint #0x22  # bti c
b #0xfffffffffeb452f4
*/
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr;
    hook_err_t rc;

    if (kver >= VERSION(4, 4, 0) && kver < VERSION(4, 5, 0) &&
        syscall_hook_global_enabled()) return HOOK_BAD_ADDRESS;

    addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    rc = hook_wrap((void *)addr, narg, before, after, udata);
    if (!rc) syscall_4_4_note_legacy_slot_hook();
    return rc;
}
KP_EXPORT_SYMBOL(inline_wrap_syscalln);

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    hook_unwrap((void *)addr, before, after);
}
KP_EXPORT_SYMBOL(inline_unwrap_syscalln);

/*
 * Global syscall dispatcher.
 *
 * A single inline hook on el0_svc_common covers every syscall, native and
 * compat32 alike, with one uniform trampoline. Per-syscall registrations are
 * kept in a small static table and fanned out from that one hook, so the
 * sys_call_table entries are never patched and every syscall pays the same
 * overhead (no per-syscall timing fingerprint).
 *
 * The registered callbacks run against the hook_fargs8_t captured by the inline
 * hook's transit, whose arg0 is the pt_regs pointer; syscall_args() therefore
 * reads regs->regs[] exactly as it did under the per-syscall hook, and
 * syscall_argn_p() still writes straight into the live register frame.
 *
 * skip_origin (only used by the magic supercall) is honoured only when the hook
 * target is invoke_syscall, i.e. at handler granularity: there it suppresses the
 * real syscall while el0_svc_common still runs syscall_trace_enter/exit around it.
 * If only el0_svc_common could be resolved, skip_origin is refused (it would skip
 * that whole function) and such callers fall back to hook_syscalln_legacy().
 */
#define SYSCALL_HOOK_SLOT_NUM 64
/* More than this many callbacks on one syscall number would be unusual; the
 * excess is skipped rather than overflowing the dispatch stack frame. */
#define SYSCALL_HOOK_MAX_MATCH 16

typedef void (*syscall_hook_cb_t)(void *fargs, void *udata);
typedef int (*syscall_hook_gate_t)(void);

typedef struct
{
    int32_t nr;
    int32_t is_compat;
    void *before;
    void *after;
    void *udata;
    int8_t allow_skip;
    int8_t bypass_gate;
    volatile int8_t state;
} syscall_hook_slot_t;

static syscall_hook_slot_t syscall_hooks[SYSCALL_HOOK_SLOT_NUM];
/* High-water mark of used slots; lets the hot path bail out immediately when
 * nothing is registered. */
static volatile int syscall_hook_high = 0;
static volatile int syscall_hook_global = 0;
/* 1 when hooked at invoke_syscall (handler granularity), 0 when hooked at
 * el0_svc_common's entry. Only the former can honour skip_origin. */
static volatile int syscall_hook_handler_granular = 0;
/* Optional uid gate, evaluated once per syscall for all callbacks. */
static syscall_hook_gate_t syscall_hook_gate = 0;
static spinlock_t syscall_hook_lock;

struct syscall_hook_snapshot
{
    syscall_hook_cb_t before;
    syscall_hook_cb_t after;
    void *udata;
    int8_t allow_skip;
};

static void syscall_hook_barrier(void)
{
    asm volatile("dsb ish" ::: "memory");
}

static int syscall_hook_collect(int nr, int is_compat, int gate_ok, struct syscall_hook_snapshot *out, int max)
{
    int n = 0;
    int high = syscall_hook_high;
    if (high > SYSCALL_HOOK_SLOT_NUM) high = SYSCALL_HOOK_SLOT_NUM;

    for (int i = 0; i < high; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        if (!gate_ok && !syscall_hooks[i].bypass_gate) continue;
        if (n >= max) break;
        out[n].before = (syscall_hook_cb_t)syscall_hooks[i].before;
        out[n].after = (syscall_hook_cb_t)syscall_hooks[i].after;
        out[n].udata = syscall_hooks[i].udata;
        out[n].allow_skip = syscall_hooks[i].allow_skip;
        n++;
    }
    return n;
}

/* Implemented with the Linux 4.4 special-wrapper table below. */
static bool syscall_4_4_hook_target_is_special(int nr, int is_compat);

static hook_err_t syscall_hook_add(int nr, int is_compat, void *before, void *after, void *udata, int allow_skip,
                                   int bypass_gate)
{
    /* Special 4.4 wrappers tail-dispatch with the original pt_regs stack and
     * cannot run the generic callback chain. Reject such registrations rather
     * than reporting success for a hook that would never be invoked. */
    if (syscall_hook_global && syscall_4_4_hook_target_is_special(nr, is_compat)) {
        logkv("syscall hook rejected: 4.4 special wrapper nr=%d compat=%d\n", nr, is_compat);
        return -HOOK_BAD_ADDRESS;
    }

    unsigned long flags = kp_private_spin_lock(&syscall_hook_lock);

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        if ((before && syscall_hooks[i].before == before) || (after && syscall_hooks[i].after == after)) {
            kp_private_spin_unlock(&syscall_hook_lock, flags);
            return -HOOK_DUPLICATED;
        }
    }

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_EMPTY) continue;
        syscall_hooks[i].state = CHAIN_ITEM_STATE_BUSY;
        syscall_hook_barrier();
        syscall_hooks[i].nr = nr;
        syscall_hooks[i].is_compat = is_compat;
        syscall_hooks[i].udata = udata;
        syscall_hooks[i].before = before;
        syscall_hooks[i].after = after;
        syscall_hooks[i].allow_skip = allow_skip;
        syscall_hooks[i].bypass_gate = bypass_gate;
        syscall_hook_barrier();
        syscall_hooks[i].state = CHAIN_ITEM_STATE_READY;
        if (i + 1 > syscall_hook_high) syscall_hook_high = i + 1;
        kp_private_spin_unlock(&syscall_hook_lock, flags);
        logkv("syscall hook add: nr %d compat %d, %llx, %llx\n", nr, is_compat, before, after);
        return HOOK_NO_ERR;
    }

    kp_private_spin_unlock(&syscall_hook_lock, flags);
    logkv("syscall hook add: nr %d compat %d failed\n", nr, is_compat);
    return -HOOK_CHAIN_FULL;
}

static void syscall_hook_remove(int nr, int is_compat, void *before, void *after)
{
    unsigned long flags = kp_private_spin_lock(&syscall_hook_lock);

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        int match = 0;
        if (before && syscall_hooks[i].before == before) match = 1;
        if (after && syscall_hooks[i].after == after) match = 1;
        if (!match) continue;
        syscall_hooks[i].state = CHAIN_ITEM_STATE_BUSY;
        syscall_hook_barrier();
        syscall_hooks[i].udata = 0;
        syscall_hooks[i].before = 0;
        syscall_hooks[i].after = 0;
        syscall_hooks[i].allow_skip = 0;
        syscall_hooks[i].bypass_gate = 0;
        syscall_hook_barrier();
        syscall_hooks[i].state = CHAIN_ITEM_STATE_EMPTY;
        break;
    }

    kp_private_spin_unlock(&syscall_hook_lock, flags);
}

int syscall_hook_global_enabled(void)
{
    return syscall_hook_global;
}
KP_EXPORT_SYMBOL(syscall_hook_global_enabled);

/* Register the single uid gate evaluated once per syscall before dispatching any
 * callback. Passing NULL disables gating (all callbacks run). */
void syscall_hook_set_gate(int (*gate)(void))
{
    syscall_hook_gate = gate;
}
KP_EXPORT_SYMBOL(syscall_hook_set_gate);

/* scno is arg1 of el0_svc_common; on the odd kernel where that argument is
 * absent, fall back to the userspace syscall-number register (x8 native, r7
 * compat32), which is what the entry stubs load scno from. */
static long syscall_dispatch_nr(struct pt_regs *regs, unsigned long scno, int is_compat)
{
    long nr = (long)scno;
    if (nr < 0 || nr >= 1024) nr = (long)(is_compat ? regs->regs[7] : regs->regs[8]);
    return nr;
}

/* Sized as hook_fargs8_t (the largest callback type used in-tree) even though
 * el0_svc_common takes four arguments: has_syscall_wrapper makes syscall_argn()
 * read the register frame rather than the struct's args[], but keeping the
 * buffer large enough means a callback that does read args->arg4..7 directly
 * stays in bounds. */
static void syscall_dispatch_before(hook_fargs8_t *args, void *udata)
{
    (void)udata;
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    if (!regs) return;

    int is_compat = compat_user_mode(regs) ? 1 : 0;
    long nr = syscall_dispatch_nr(regs, args->arg1, is_compat);

    if (!syscall_hook_high) return;

    /* One uid gate, evaluated once per syscall for every callback, instead of a
     * root check inside each callback. For a process that is not su-authorized
     * nothing is dispatched, so behavior and cost are the same across all
     * syscalls: no per-syscall fingerprint, and fstatat/statx/... cannot
     * disagree. Slots registered with bypass_gate (the magic supercall, which
     * authenticates with its own key) still run. */
    int gate_ok = 1;
    if (syscall_hook_gate) gate_ok = syscall_hook_gate() ? 1 : 0;

    struct syscall_hook_snapshot snap[SYSCALL_HOOK_MAX_MATCH];
    int n = syscall_hook_collect((int)nr, is_compat, gate_ok, snap, SYSCALL_HOOK_MAX_MATCH);
    if (!n) return;

    /* Hooked at invoke_syscall (handler granularity) el0_svc_common has already
     * set these; hooked at its entry we must set them ourselves so callbacks
     * that inspect them (resolve_pt_regs scans the stack for a matching frame)
     * see the same state as under the per-syscall hook. */
    if (!syscall_hook_handler_granular) {
        regs->orig_x0 = regs->regs[0];
        regs->syscallno = nr;
    }

    /* arg1..arg3 are scno/sc_nr/table, not syscall arguments; they must reach the
     * origin unchanged for it to pick the right handler. */
    uint64_t keep_arg1 = args->arg1;
    uint64_t keep_arg2 = args->arg2;
    uint64_t keep_arg3 = args->arg3;

    args->skip_origin = 0;
    args->ret = 0;

    int can_skip = 0;
    for (int i = 0; i < n; i++) {
        if (snap[i].allow_skip) can_skip = 1;
        if (snap[i].before) snap[i].before(args, snap[i].udata);
    }

    args->arg1 = keep_arg1;
    args->arg2 = keep_arg2;
    args->arg3 = keep_arg3;

    /* Honour skip_origin only where it means "skip this one syscall's handler".
     * At invoke_syscall granularity el0_svc_common still runs syscall_trace_enter
     * and syscall_trace_exit around it, so the overridden result has to be placed
     * in regs->regs[0] here. When hooked at el0_svc_common's entry, skip_origin
     * would skip that whole function (tracing, exit work and all), so it is
     * refused unless the caller explicitly opted in. */
    if (args->skip_origin && can_skip && syscall_hook_handler_granular) {
        regs->regs[0] = args->ret;
    } else {
        args->skip_origin = 0;
    }
}

static void syscall_dispatch_after(hook_fargs8_t *args, void *udata)
{
    (void)udata;
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    if (!regs) return;

    int is_compat = compat_user_mode(regs) ? 1 : 0;
    /* Use the scno captured by the transit at function entry, not regs->syscallno:
     * el0_svc_common only assigns syscallno for in-range syscalls, so an invalid
     * number would leave the previous syscall's value there and we would run the
     * wrong afters. args->arg1 is the original scno; callbacks that rewrite a
     * syscall argument go through set_syscall_argn(), which touches regs->regs[],
     * not this copy. */
    long nr = syscall_dispatch_nr(regs, args->arg1, is_compat);

    if (!syscall_hook_high) return;

    /* Same gate as the before phase: an after callback must never run without
     * its before callback having run. */
    int gate_ok = 1;
    if (syscall_hook_gate) gate_ok = syscall_hook_gate() ? 1 : 0;

    struct syscall_hook_snapshot snap[SYSCALL_HOOK_MAX_MATCH];
    int n = syscall_hook_collect((int)nr, is_compat, gate_ok, snap, SYSCALL_HOOK_MAX_MATCH);
    if (!n) return;

    /* The real return value lives in regs->regs[0]; el0_svc_common returns void,
     * so mirror it into fargs->ret for the after callbacks and copy any change
     * back, matching the fp-hook chain semantics. */
    args->ret = regs->regs[0];
    for (int i = n - 1; i >= 0; i--) {
        if (snap[i].after) snap[i].after(args, snap[i].udata);
    }
    regs->regs[0] = args->ret;
}


/*
 * Linux 4.4 syscall entry backend.
 *
 * 4.4 does not have invoke_syscall()/el0_svc_common(). The actual ARM64 entry
 * path selects the handler directly in el0_svc_naked:
 *
 *   ldr x16, [stbl, scno, lsl #3]
 *   blr x16
 *
 * The same sequence occurs once in the fast path and once in __sys_trace.
 * Patch both sites to a small KP assembly entry. The KP dispatcher then calls
 * the original table entry and continues at the original return path.
 */
#define KP4_SYSCALL_LDR_X16_SCNO 0xf87a7b70u
#define KP4_SYSCALL_BLR_X16      0xd63f0200u
/* Exact STR X0, [SP] encoding used to save the syscall return value. */
#define KP4_SYSCALL_STR_X0_SP      0xf90003e0u
#define KP4_SYSCALL_B_MASK        0xfc000000u
#define KP4_SYSCALL_B             0x14000000u

extern void kp_syscall_4_4_fast_entry(void);
extern void kp_syscall_4_4_trace_entry(void);
extern void __noreturn kp_syscall_4_4_resume(uintptr_t frame, long ret, uintptr_t target);
extern void __noreturn kp_syscall_4_4_resume_special(uintptr_t frame, uintptr_t handler, uintptr_t target, int trace);

static uintptr_t syscall_4_4_fast_site;
static uintptr_t syscall_4_4_trace_site;
static uintptr_t syscall_4_4_fast_return;
/* Read by the 4.4 special-wrapper trace trampoline after the handler returns. */
uintptr_t kp_syscall_4_4_trace_return;
static uint32_t syscall_4_4_fast_backup[3];
static uint32_t syscall_4_4_trace_backup[3];

/*
 * Linux 4.4 ARM64/compat has syscall-table entries that are assembly wrappers,
 * not ordinary C handlers. They depend on SP pointing at the original pt_regs
 * frame and, for some compat calls, translate split 32-bit arguments. Calling
 * those entries from the C dispatcher corrupts their ABI (notably sigreturn).
 *
 * These handlers must be tail-dispatched from the original pt_regs stack and
 * therefore bypass generic before/after callbacks. No current KP hook relies
 * on observing these special syscalls.
 */
static const char *const syscall_4_4_special_wrapper_names[] = {
    "sys_rt_sigreturn_wrapper",
    "compat_sys_sigreturn_wrapper",
    "compat_sys_rt_sigreturn_wrapper",
    "compat_sys_statfs64_wrapper",
    "compat_sys_fstatfs64_wrapper",
    "compat_sys_pread64_wrapper",
    "compat_sys_pwrite64_wrapper",
    "compat_sys_truncate64_wrapper",
    "compat_sys_ftruncate64_wrapper",
    "compat_sys_readahead_wrapper",
    "compat_sys_fadvise64_64_wrapper",
    "compat_sys_sync_file_range2_wrapper",
    "compat_sys_fallocate_wrapper",
    "compat_sys_mmap2_wrapper",
};
#define SYSCALL_4_4_SPECIAL_WRAPPER_NUM \
    (sizeof(syscall_4_4_special_wrapper_names) / sizeof(syscall_4_4_special_wrapper_names[0]))

static uintptr_t syscall_4_4_special_wrapper_addrs[SYSCALL_4_4_SPECIAL_WRAPPER_NUM];
static bool syscall_4_4_special_wrappers_ready;

/* Some 4.4 builds can expose compat handlers without a resolved
 * compat_sys_call_table pointer. Mirror syscall_init()'s symbol-based compat
 * detection instead of relying only on that pointer. */
static bool syscall_4_4_compat_layer_present(void)
{
    return kallsyms_lookup_name("__arm64_compat_sys_openat") ||
           kallsyms_lookup_name("compat_sys_call_table") ||
           kallsyms_lookup_name("compat_sys_openat");
}

static int syscall_4_4_resolve_special_wrappers(void)
{
    int found = 0;

    for (unsigned int i = 0; i < SYSCALL_4_4_SPECIAL_WRAPPER_NUM; i++) {
        syscall_4_4_special_wrapper_addrs[i] =
            kallsyms_lookup_name(syscall_4_4_special_wrapper_names[i]);
        if (syscall_4_4_special_wrapper_addrs[i]) {
            found++;
        } else {
            log_boot("4.4 dispatcher: unresolved special wrapper %s\n",
                     syscall_4_4_special_wrapper_names[i]);
        }
    }

    int required = syscall_4_4_compat_layer_present()
        ? (int)SYSCALL_4_4_SPECIAL_WRAPPER_NUM : 1;
    syscall_4_4_special_wrappers_ready =
        syscall_4_4_special_wrapper_addrs[0] != 0 && found >= required;

    return found;
}

static bool syscall_4_4_is_special_wrapper(uintptr_t addr)
{
    if (!addr) return false;

    for (unsigned int i = 0; i < SYSCALL_4_4_SPECIAL_WRAPPER_NUM; i++) {
        if (syscall_4_4_special_wrapper_addrs[i] == addr)
            return true;
    }

    return false;
}


static bool syscall_4_4_is_b(uint32_t insn)
{
    return (insn & KP4_SYSCALL_B_MASK) == KP4_SYSCALL_B;
}

static uintptr_t syscall_4_4_b_target(uintptr_t pc, uint32_t insn)
{
    int64_t imm26 = (int64_t)(insn & 0x03ffffffu);
    if (imm26 & (1LL << 25)) imm26 -= (1LL << 26);

    /* A negative signed left shift is undefined in C. Multiply the signed
     * branch displacement, then use uintptr_t addition so backward branches
     * wrap to the correct address in the kernel's high virtual address range. */
    return pc + (uintptr_t)(imm26 * 4);
}

static bool syscall_4_4_is_str_x0_sp(uint32_t insn)
{
    /* The destination must be pt_regs->regs[0], at offset zero from SP. */
    return insn == KP4_SYSCALL_STR_X0_SP;
}

/*
 * Emit:
 *
 *   adrp x16, target@page
 *   add  x16, x16, target@pageoff
 *   br   x16
 *
 * This reaches any target within +/-4 GiB of the patch site. KP memory and the
 * kernel image are expected to be in the same 48-bit kernel VA region; if the
 * runtime layout violates that assumption we leave the original syscall path
 * untouched rather than installing a truncated branch.
 */
static bool syscall_4_4_make_branch(uintptr_t pc, uintptr_t target, uint32_t out[3])
{
    int64_t pc_page = (int64_t)(pc & ~0xffful);
    int64_t target_page = (int64_t)(target & ~0xffful);
    int64_t delta_pages = (target_page - pc_page) >> 12;

    if (delta_pages < -(1LL << 20) || delta_pages > ((1LL << 20) - 1)) return false;

    uint32_t imm21 = (uint32_t)(delta_pages & 0x1fffff);
    uint32_t immlo = imm21 & 0x3;
    uint32_t immhi = (imm21 >> 2) & 0x7ffff;
    uint32_t pageoff = (uint32_t)(target & 0xfff);

    out[0] = 0x90000010u | (immlo << 29) | (immhi << 5);
    out[1] = 0x91000210u | (pageoff << 10);
    out[2] = 0xd61f0200u; /* br x16 */
    return true;
}

static int syscall_4_4_find_sites(uintptr_t el0_svc, uintptr_t *fast, uintptr_t *trace)
{
    uintptr_t ret_fast = syscall_4_4_fast_return;
    uintptr_t fast_found = 0;
    uintptr_t trace_found = 0;

    for (unsigned long off = 0; off < 0x1000; off += 4) {
        uintptr_t addr = el0_svc + off;
        uint32_t *p = (uint32_t *)addr;
        uint32_t a = p[0];
        uint32_t b = p[1];
        uint32_t c = p[2];

        if (a != KP4_SYSCALL_LDR_X16_SCNO || b != KP4_SYSCALL_BLR_X16) continue;

        if (!fast_found && syscall_4_4_is_b(c)) {
            if (!ret_fast || syscall_4_4_b_target(addr + 8, c) == ret_fast)
                fast_found = addr;
            continue;
        }

        if (!trace_found && syscall_4_4_is_str_x0_sp(c))
            trace_found = addr;
    }

    if (!fast_found || !trace_found) return -ENOENT;
    *fast = fast_found;
    *trace = trace_found;
    return 0;
}

static long syscall_4_4_invoke_original(struct pt_regs *regs, long nr, int is_compat)
{
    uintptr_t addr;

    if (nr < 0) return -ENOSYS;
    if (is_compat) {
#ifdef __NR_compat_syscalls
        if (nr >= __NR_compat_syscalls) return -ENOSYS;
#else
        if (nr >= 460) return -ENOSYS;
#endif
    } else {
#ifdef __NR_syscalls
        if (nr >= __NR_syscalls) return -ENOSYS;
#else
        if (nr >= 460) return -ENOSYS;
#endif
    }

    addr = syscalln_addr((int)nr, is_compat);
    if (!addr) return -ENOSYS;

    /*
     * Linux ARM64 syscall handlers use x0..x5. Passing six arguments is ABI
     * compatible with handlers that consume fewer arguments; unused registers
     * are simply ignored by the callee.
     */
    return ((raw_syscall6_f)addr)(
        (long)regs->regs[0],
        (long)regs->regs[1],
        (long)regs->regs[2],
        (long)regs->regs[3],
        (long)regs->regs[4],
        (long)regs->regs[5]
    );
}

static bool syscall_4_4_nr_is_valid(unsigned long nr, int is_compat)
{
    if (is_compat) {
#ifdef __NR_compat_syscalls
        return nr < (unsigned long)__NR_compat_syscalls;
#else
        return nr < 460;
#endif
    }
#ifdef __NR_syscalls
    return nr < (unsigned long)__NR_syscalls;
#else
    return nr < 460;
#endif
}

static bool syscall_4_4_hook_target_is_special(int nr, int is_compat)
{
    if (kver < VERSION(4, 4, 0) || kver >= VERSION(4, 5, 0)) return false;
    if (!syscall_4_4_special_wrappers_ready) return false;
    if (!syscall_4_4_nr_is_valid((unsigned long)nr, is_compat)) return false;

    return syscall_4_4_is_special_wrapper(syscalln_addr(nr, is_compat));
}

static void __noreturn syscall_4_4_dispatch(struct pt_regs *regs, unsigned long nr, int trace, uintptr_t frame)
{
    hook_fargs8_t fargs;
    int is_compat;
    long ret;
    uintptr_t target;

    if (!regs) {
        ret = -ENOSYS;
        goto resume;
    }

    is_compat = compat_user_mode(regs) ? 1 : 0;
    regs->syscallno = (long)nr;

    /*
     * Do not call pt_regs/argument-repacking wrappers as ordinary C functions.
     * Resume on the untouched kernel stack, restore x0-x7 from pt_regs, and
     * tail-dispatch to the wrapper with the original return continuation.
     */
    /*
     * Invalid syscall numbers must not be used to index either syscall table.
     * The generic invoker returns -ENOSYS for these; the special-wrapper lookup
     * must do the same range check before reading a table entry.
     */
    uintptr_t handler = 0;
    if (syscall_4_4_nr_is_valid(nr, is_compat))
        handler = syscalln_addr((int)nr, is_compat);
    if (syscall_4_4_is_special_wrapper(handler)) {
        target = trace ? kp_syscall_4_4_trace_return : syscall_4_4_fast_return;
        if (!target)
            target = trace ? syscall_4_4_trace_site + 12 : syscall_4_4_fast_return;
        kp_syscall_4_4_resume_special(frame, handler, target, trace ? 1 : 0);
        __builtin_unreachable();
    }

    fargs.chain = 0;
    fargs.skip_origin = 0;
    fargs.ret = 0;
    fargs.arg0 = (uint64_t)regs;
    fargs.arg1 = nr;
    fargs.arg2 = 0;
    fargs.arg3 = 0;
    fargs.arg4 = 0;
    fargs.arg5 = 0;
    fargs.arg6 = 0;
    fargs.arg7 = 0;

    syscall_dispatch_before(&fargs, 0);

    if (fargs.skip_origin && syscall_hook_handler_granular) {
        ret = (long)regs->regs[0];
    } else {
        ret = syscall_4_4_invoke_original(regs, (long)nr, is_compat);
        regs->regs[0] = ret;
    }

    /*
     * Keep the same after-hook semantics as the upstream dispatcher. This is
     * also what lets a before hook use set_syscall_argn() and an after hook
     * rewrite regs->regs[0].
     */
    syscall_dispatch_after(&fargs, 0);
    ret = (long)regs->regs[0];

resume:
    target = trace ? kp_syscall_4_4_trace_return : syscall_4_4_fast_return;
    if (!target)
        target = trace ? syscall_4_4_trace_site + 12 : syscall_4_4_fast_return;

    /* This helper restores SP and x19-x30 before branching to the kernel path. */
    kp_syscall_4_4_resume(frame, ret, target);
    __builtin_unreachable();
}

/*
 * The assembly entry labels are intentionally separate so the return address
 * can be chosen without touching the 4.4 entry stack/register convention.
 */
void __noreturn kp_syscall_4_4_fast_dispatch(struct pt_regs *regs, unsigned long nr, uintptr_t frame)
{
    syscall_4_4_dispatch(regs, nr, 0, frame);
    __builtin_unreachable();
}

void __noreturn kp_syscall_4_4_trace_dispatch(struct pt_regs *regs, unsigned long nr, uintptr_t frame)
{
    syscall_4_4_dispatch(regs, nr, 1, frame);
    __builtin_unreachable();
}

/*
 * Read-only validation for the Linux 4.4 entry-site heuristic. This executes
 * only while the global dispatcher is disabled and never modifies kernel text.
 */
static void syscall_dispatch_4_4_probe(void)
{
    uintptr_t el0_svc = kallsyms_lookup_name_by_suffix("el0_svc");
    uintptr_t ret_fast = kallsyms_lookup_name_by_suffix("ret_fast_syscall");
    uintptr_t fast = 0;
    uintptr_t trace = 0;
    uint32_t fast_patch[3];
    uint32_t trace_patch[3];

    if (!el0_svc || !ret_fast) {
        log_boot("4.4 dispatcher probe: missing entry symbol (el0_svc=%llx ret_fast=%llx)\n",
                 (uint64_t)el0_svc, (uint64_t)ret_fast);
        return;
    }

    syscall_4_4_fast_return = ret_fast;
    /* Keep this startup probe strictly read-only. Wrapper resolution belongs
     * to the experimental dispatcher and is not needed to validate entry sites.
     */
    if (syscall_4_4_find_sites(el0_svc, &fast, &trace)) {
        log_boot("4.4 dispatcher probe: handler-selection sites not found (el0_svc=%llx ret_fast=%llx)\n",
                 (uint64_t)el0_svc, (uint64_t)ret_fast);
        return;
    }

    if (!syscall_4_4_make_branch(fast, (uintptr_t)&kp_syscall_4_4_fast_entry, fast_patch) ||
        !syscall_4_4_make_branch(trace, (uintptr_t)&kp_syscall_4_4_trace_entry, trace_patch)) {
        log_boot("4.4 dispatcher probe: KP veneer outside ADRP range (fast=%llx trace=%llx)\n",
                 (uint64_t)fast, (uint64_t)trace);
        return;
    }

    log_boot("4.4 dispatcher probe: el0_svc=%llx ret_fast=%llx fast=%llx trace=%llx\n",
             (uint64_t)el0_svc, (uint64_t)ret_fast, (uint64_t)fast, (uint64_t)trace);
    log_boot("4.4 dispatcher probe insns: fast=%08x/%08x/%08x trace=%08x/%08x/%08x\n",
             ((uint32_t *)fast)[0], ((uint32_t *)fast)[1], ((uint32_t *)fast)[2],
             ((uint32_t *)trace)[0], ((uint32_t *)trace)[1], ((uint32_t *)trace)[2]);
}

static int syscall_dispatch_4_4_init(void)
{
    uintptr_t el0_svc;
    uintptr_t fast;
    uintptr_t trace;
    uint32_t fast_patch[3];
    uint32_t trace_patch[3];

    if (syscall_4_4_legacy_slot_hooks_seen) {
        log_boot("4.4 dispatcher: legacy syscall-table hooks already registered; refuse backend switch\n");
        return -EBUSY;
    }

    el0_svc = kallsyms_lookup_name_by_suffix("el0_svc");
    syscall_4_4_fast_return = kallsyms_lookup_name_by_suffix("ret_fast_syscall");
    int special_wrappers = syscall_4_4_resolve_special_wrappers();
    int required_wrappers = syscall_4_4_compat_layer_present()
        ? (int)SYSCALL_4_4_SPECIAL_WRAPPER_NUM : 1;
    if (!syscall_4_4_special_wrapper_addrs[0] ||
        special_wrappers < required_wrappers) {
        log_boot("4.4 dispatcher: required special wrappers unavailable (%d/%d, native rt_sigreturn=%llx); keep per-syscall hooks\n",
                 special_wrappers, required_wrappers,
                 (uint64_t)syscall_4_4_special_wrapper_addrs[0]);
        return -ENOENT;
    }
    if (!el0_svc || !syscall_4_4_fast_return) {
        log_boot("4.4 dispatcher: missing el0_svc/ret_fast_syscall\\n");
        return -ENOENT;
    }

    kp_syscall_4_4_trace_return = 0;
    if (!syscall_4_4_find_sites(el0_svc, &fast, &trace)) {
        /* The trace return is immediately after the original STR X0 instruction. */
        kp_syscall_4_4_trace_return = trace + 12;
    } else {
        log_boot("4.4 dispatcher: syscall dispatch sites not found near el0_svc\\n");
        return -ENOENT;
    }

    syscall_4_4_fast_site = fast;
    syscall_4_4_trace_site = trace;

    if (!syscall_4_4_make_branch(fast, (uintptr_t)&kp_syscall_4_4_fast_entry, fast_patch) ||
        !syscall_4_4_make_branch(trace, (uintptr_t)&kp_syscall_4_4_trace_entry, trace_patch)) {
        log_boot("4.4 dispatcher: KP entry outside ADRP range\\n");
        return -ERANGE;
    }

    for (int i = 0; i < 3; i++) {
        syscall_4_4_fast_backup[i] = ((uint32_t *)fast)[i];
        syscall_4_4_trace_backup[i] = ((uint32_t *)trace)[i];
    }

    void *fast_addrs[3] = {(void *)fast, (void *)(fast + 4), (void *)(fast + 8)};
    void *trace_addrs[3] = {(void *)trace, (void *)(trace + 4), (void *)(trace + 8)};

    int rc = hotpatch(fast_addrs, fast_patch, 3);
    if (rc) {
        log_boot("4.4 dispatcher: fast site patch rc=%d\\n", rc);
        return rc;
    }

    rc = hotpatch(trace_addrs, trace_patch, 3);
    if (rc) {
        /* Roll back the fast site if the trace site could not be patched. */
        hotpatch(fast_addrs, syscall_4_4_fast_backup, 3);
        log_boot("4.4 dispatcher: trace site patch rc=%d, fast site restored\\n", rc);
        syscall_4_4_fast_site = 0;
        syscall_4_4_trace_site = 0;
        return rc;
    }

    syscall_hook_handler_granular = 1;
    syscall_hook_barrier();
    syscall_hook_global = 1;

    log_boot("4.4 dispatcher: fast=%llx trace=%llx ret_fast=%llx trace_ret=%llx, global syscall hook enabled\\n",
             fast, trace, syscall_4_4_fast_return, kp_syscall_4_4_trace_return);
    return 0;
}

void syscall_dispatch_init(void)
{
    if (syscall_hook_global) return;

    /*
     * Keep the experimental entry-site dispatcher disabled on Linux 4.4 while
     * validating the XZP 4.4.302 path. The probe is read-only; syscall hooks
     * continue to use the legacy per-syscall path.
     */
    if (kver >= VERSION(4, 4, 0) && kver < VERSION(4, 5, 0)) {
        log_boot("4.4 global syscall dispatcher disabled; keep per-syscall hooks pending runtime validation\n");
        syscall_dispatch_4_4_probe();
        return;
    }

    if (!has_syscall_wrapper) {
        log_boot("syscall dispatcher: no syscall wrapper, keep per-syscall hooks\n");
        return;
    }

    /*
     * Prefer invoke_syscall: it runs after syscall_trace_enter (seccomp/ptrace)
     * and before syscall_trace_exit, i.e. at the same granularity as the old
     * per-syscall hooks. Hooking there lets skip_origin skip only the real
     * handler while el0_svc_common still performs its entry/exit work. Fall back
     * to el0_svc_common, which is coarser and cannot honour skip_origin.
     * GCC clones (LTO/constprop/isra) get a trailing '.' suffix; the helper
     * requires that separator, so el0_svc_common_compat is not matched.
     */
    uintptr_t addr = 0;
    const char *name = 0;
    int granular = 0;

    addr = kallsyms_lookup_name_by_suffix("invoke_syscall");
    if (addr) {
        name = "invoke_syscall";
        granular = 1;
    }

    if (!addr) {
        addr = kallsyms_lookup_name_by_suffix("el0_svc_common");
        if (addr) {
            name = "el0_svc_common";
            uint32_t *insn = (uint32_t *)addr;
            if (insn[1] != 0xa9bd7bfd) {
                log_boot("Shadow Call Stack detected, bypass union syscall hook\n");
                return;
            } else {
                log_boot("Shadow Call Stack not detected, proceed with union syscall hook\n");
            }
        }
    }

    if (!addr) {
        log_boot("syscall dispatcher: no invoke_syscall/el0_svc_common, keep per-syscall hooks\n");
        return;
    }

    hook_err_t err = hook_wrap8((void *)addr, syscall_dispatch_before, syscall_dispatch_after, 0);
    if (err) {
        log_boot("syscall dispatcher: hook %s error %d, keep per-syscall hooks\n", name, err);
        return;
    }

    syscall_hook_handler_granular = granular;
    syscall_hook_barrier();
    syscall_hook_global = 1;
    log_boot("syscall dispatcher: hooked %s at %llx (skip_origin %s), global syscall hook enabled\n",
             name, (uint64_t)addr, granular ? "supported" : "unsupported");
}
KP_EXPORT_SYMBOL(syscall_dispatch_init);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global) return syscall_hook_add(nr, 0, before, after, udata, 0, 0);
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln);

void unhook_syscalln(int nr, void *before, void *after)
{
    if (syscall_hook_global) return syscall_hook_remove(nr, 0, before, after);
    if (sys_call_table) return fp_unwrap_syscalln(nr, 0, before, after);
    return inline_unwrap_syscalln(nr, 0, before, after);
}
KP_EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global) return syscall_hook_add(nr, 1, before, after, udata, 0, 0);
    if (compat_sys_call_table) return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_compat_syscalln);

/* Like hook_syscalln but the callback may set skip_origin to suppress the real
 * syscall. Honoured only when the dispatcher is hooked at invoke_syscall; if it
 * is hooked at el0_svc_common (or not at all) this falls back to the per-syscall
 * mechanism, which implements skip_origin at handler granularity. */
hook_err_t hook_syscalln_override(int nr, int narg, void *before, void *after, void *udata)
{
    /* bypass_gate: the magic supercall authenticates with its own key, so it must
     * still be dispatched for a uid that is not on the su allow list. */
    if (syscall_hook_global && syscall_hook_handler_granular)
        return syscall_hook_add(nr, 0, before, after, udata, 1, 1);
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln_override);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (syscall_hook_global) return syscall_hook_remove(nr, 1, before, after);
    if (compat_sys_call_table) return fp_unwrap_syscalln(nr, 1, before, after);
    return inline_unwrap_syscalln(nr, 1, before, after);
}
KP_EXPORT_SYMBOL(unhook_compat_syscalln);

/* Original per-syscall mechanism, kept for callbacks that need skip_origin
 * (the magic supercall) and as the fallback when el0_svc_common is unavailable. */
hook_err_t hook_syscalln_legacy(int nr, int narg, void *before, void *after, void *udata)
{
    if (sys_call_table) return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln_legacy);

void syscall_init()
{
    for (int i = 0; i < sizeof(syscall_name_table) / sizeof(syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    for (int i = 0; i < sizeof(compat_syscall_name_table) / sizeof(compat_syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&compat_syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name("sys_call_table");
    log_boot("sys_call_table addr: %llx\n", sys_call_table);

    compat_sys_call_table = (typeof(compat_sys_call_table))kallsyms_lookup_name("compat_sys_call_table");
    log_boot("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (kallsyms_lookup_name("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (kallsyms_lookup_name("compat_sys_call_table") || kallsyms_lookup_name("compat_sys_openat")) {
            has_config_compat = 1;
        }
        if (kallsyms_lookup_name("__arm64_sys_openat")) {
            has_syscall_wrapper = 1;
        }
    }

    log_boot("syscall config_compat: %d\n", has_config_compat);
    log_boot("syscall has_wrapper: %d\n", has_syscall_wrapper);
}
