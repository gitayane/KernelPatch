/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <userd.h>
#include <symbol.h>
#include <kallsyms.h>
#include <uapi/linux/limits.h>
#include <predata.h>
#include <kstorage.h>
#include <selinux_hide.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
extern int android_is_safe_mode;
#endif
const char sucompat_file[] = "/data/adb/ap/sucompat";
static const char *current_su_path = 0;

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;
static void su_register_path_probe_hooks(void);
static void su_unregister_path_probe_hooks(void);
static int su_hook_getname_flags(void);
static int su_hook_security_inode_getattr(void);
static int su_hook_security_file_open(void);
static int su_syscall_gate(void);

/*
 * Shared path-probe hooks. The normal path is getname_flags +
 * security_inode_getattr, matching upstream KernelPatch. The old
 * per-syscall probes remain as a fallback when a 4.4/LTO symbol cannot
 * be resolved or hooked safely.
 */
static unsigned long su_getname_flags_addr;
static unsigned long su_security_inode_getattr_addr;
static unsigned long su_security_file_open_addr;
static bool su_getname_flags_hooked;
static bool su_security_inode_getattr_hooked;
static bool su_security_file_open_hooked;
static bool su_legacy_fstatat_hooked;
static bool su_legacy_faccessat_hooked;
static bool su_legacy_compat_fstatat64_hooked;
static bool su_legacy_compat_faccessat_hooked;

static bool su_path_probe_hooks_any_registered(void)
{
    return su_getname_flags_hooked || su_security_inode_getattr_hooked ||
           su_security_file_open_hooked || su_legacy_fstatat_hooked ||
           su_legacy_faccessat_hooked || su_legacy_compat_fstatat64_hooked ||
           su_legacy_compat_faccessat_hooked;
}

static bool su_hook_result_is_registered(hook_err_t rc)
{
    /* A duplicate means the same callback is already present in this hook chain. */
    return rc == HOOK_NO_ERR || rc == -HOOK_DUPLICATED;
}

long kp_control_feature_sc(const char __user *uname, int state)
{
    char name[64];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0)
        return -EINVAL;

    if (!strcmp(name, "selinux_hide")) {
        return selinux_hide_control(state);
    }

    if (!strcmp(name, "sucompat_extra") || !strcmp(name, "path_probe")) {
        if (state < 0)
            /* Query: report whether at least one path-probe hook is registered. */
            return su_path_probe_hooks_any_registered() ? 1 : 0;
        if (state)
            su_register_path_probe_hooks();
        else
            su_unregister_path_probe_hooks();
        logkfi("sucompat_extra %s via supercall\n",
               state ? "enabled" : "disabled");
        return 0;
    }

    /* Unknown feature name. */
    return -ENOENT;
}
KP_EXPORT_SYMBOL(kp_control_feature_sc);

/*
 * is_su_allow_uid() walks the kstorage hash under RCU. It runs on every
 * fstatat/faccessat (the su-path probe) and in every su-gated callback, so that
 * walk is a measurable per-call cost and a timing fingerprint for those syscalls.
 * Memoise the answer per uid in a lockless direct-mapped table, keyed by
 * kstorage_generation() which every list write bumps. An entry stamped with the
 * current generation can only have been produced by a lookup that already
 * observed the new list; a stale rendezvous just misses and re-queries, never
 * returns a stale answer. Only the membership bit is cached: profiles/scontext
 * are still read live where they are needed.
 */
#define SU_ALLOW_CACHE_N 256
/* Entries never expire by time; they are invalidated by kstorage_generation().
 * 31 generation bits put wrap at ~2.1e9 writes, so an entry can never survive
 * long enough to alias the current generation. */
#define SU_ALLOW_GEN_BITS 31
#define SU_ALLOW_GEN_MASK ((1u << SU_ALLOW_GEN_BITS) - 1)
static u64 su_allow_cache[SU_ALLOW_CACHE_N];

static int is_su_allow_uid_slow(uid_t uid)
{
    int rc = 0;
    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks) || ks->dlen <= 0) goto out;

    struct su_profile *profile = (struct su_profile *)ks->data;
    rc = profile->uid == uid;

out:
    rcu_read_unlock();
    return rc;
}

int is_su_allow_uid(uid_t uid)
{
    u32 gen = kstorage_generation();
    u32 slot = (uid * 2654435761u) & (SU_ALLOW_CACHE_N - 1);
    u64 e = __atomic_load_n(&su_allow_cache[slot], __ATOMIC_RELAXED);

    if ((u32)(e >> 32) == (u32)uid && (u32)((e >> 1) & SU_ALLOW_GEN_MASK) == (gen & SU_ALLOW_GEN_MASK))
        return (int)(e & 1);

    int granted = is_su_allow_uid_slow(uid) ? 1 : 0;
    u64 ne = ((u64)(u32)uid << 32) | ((u64)(gen & SU_ALLOW_GEN_MASK) << 1) | (u64)(u32)granted;
    __atomic_store_n(&su_allow_cache[slot], ne, __ATOMIC_RELAXED);
    return granted;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";

    struct su_profile profile = {
        .uid = uid,
        .to_uid = to_uid,
    };

    /*
     * scontext is supplied by kernel-side callers and may be a short string
     * literal. Copy only its actual bytes plus the terminator; the previous
     * fixed-size memcpy could read beyond the source object. The zero-initialized
     * profile keeps the unused tail deterministic for storage and comparisons.
     */
    size_t sctx_len = strnlen(scontext, sizeof(profile.scontext));
    if (sctx_len >= sizeof(profile.scontext)) return -E2BIG;
    memcpy(profile.scontext, scontext, sctx_len + 1);

    int rc = write_kstorage(su_kstorage_gid, uid, &profile, 0, sizeof(profile), false);
    logkfd("uid: %d, to_uid: %d, rc: %d\n", uid, to_uid, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid)
{
    return remove_kstorage(su_kstorage_gid, uid);
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    return kstorage_group_size(su_kstorage_gid);
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

static int allow_uids_cb(struct kstorage *kstorage, void *udata)
{
    struct
    {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } *up = (typeof(up))udata;

    if (up->idx >= up->out_num) {
        return -ENOBUFS;
    }

    struct su_profile *profile = (struct su_profile *)kstorage->data;

    if (up->is_user) {
        int cprc = compat_copy_to_user(up->out_uids + up->idx, &profile->uid, sizeof(uid_t));
        if (cprc <= 0) {
            logkfd("compat_copy_to_user error: %d", cprc);
            return cprc;
        }
    } else {
        up->out_uids[up->idx] = profile->uid;
    }

    up->idx++;

    return 0;
}

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    struct
    {
        int iu;
        uid_t *up;
        int idx;
        int out_num;
    } udata = { is_user, out_uids, 0, out_num };

    on_each_kstorage_elem(su_kstorage_gid, allow_uids_cb, &udata);

    return udata.idx;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *out_profile)
{
    int rc = 0;

    if (!out_profile) return -EINVAL;

    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks)) {
        rc = -ENOENT;
        goto out;
    }

    /*
     * Treat a malformed or stale record as absent. The lookup is protected by
     * RCU, but grant/revoke operations can race with a caller that previously
     * observed the UID as allowed; never copy a partial profile or accept a
     * record whose embedded UID no longer matches the lookup key.
     */
    if (ks->dlen < sizeof(struct su_profile)) {
        rc = -EINVAL;
        goto out;
    }

    const struct su_profile *profile = (const struct su_profile *)ks->data;
    if (profile->uid != uid) {
        rc = -ENOENT;
        goto out;
    }

    if (is_user) {
        rc = compat_copy_to_user(out_profile, (void *)profile, sizeof(*profile));
        if (rc <= 0) {
            logkfd("compat_copy_to_user error: %d", rc);
            goto out;
        }
    } else {
        memcpy(out_profile, profile, sizeof(*profile));
    }

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uid_profile);

// no free, no lock
int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    if (IS_ERR(path)) return PTR_ERR(path);
    current_su_path = path;
    logkfd("%s\n", current_su_path);
    dsb(ish);
    return 0;
}
KP_EXPORT_SYMBOL(su_reset_path);

const char *su_get_path()
{
    if (!current_su_path) current_su_path = default_su_path;
    return current_su_path;
}
KP_EXPORT_SYMBOL(su_get_path);

static void handle_before_execve(char **__user u_filename_p, char **__user uargv, void *udata)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid) && !is_trusted_manager_uid(uid)) return;

    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

#ifdef ANDROID
    // Match the configured su path (default /system/bin/kp) and the legacy
    // /system/bin/su that shells and detectors also exec. execve does not go
    // through getname_flags, so this before-hook is the only place to redirect
    // a real exec of /system/bin/su to sh/apd.
    if (strcmp(filename, current_su_path) && strcmp(filename, legacy_su_path)) {
        if (!strcmp(SUPERCMD, filename)) {
            void handle_supercmd(char **__user u_filename_p, char **__user uargv);
            handle_supercmd(u_filename_p, uargv);
        }
        return;
    }
#else
    if (strcmp(filename, current_su_path)) {
        if (!strcmp(SUPERCMD, filename)) {
            void handle_supercmd(char **__user u_filename_p, char **__user uargv);
            handle_supercmd(u_filename_p, uargv);
        }
        return;
    }
#endif
    {
        uid_t uid = current_uid();
        struct su_profile profile = { .to_uid = 0 };
        if (is_trusted_manager_uid(uid)) {
            strncpy(profile.scontext, all_allow_sctx, sizeof(profile.scontext) - 1);
            profile.scontext[sizeof(profile.scontext) - 1] = '\0';
        } else if (su_allow_uid_profile(0, uid, &profile)) {
            return;
        }

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

#ifdef ANDROID
        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
#endif
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = (char *__user)uptr;
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\n", uid, to_uid, sctx, uptr);
#ifdef ANDROID
        } else {
            filp_close(filp, 0);

            // command
            uint64_t sp = 0;
            sp = current_user_stack_pointer();
            sp -= sizeof(apd_path);
            sp &= 0xFFFFFFFFFFFFFFF8;
            int cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                *u_filename_p = (char *)sp;
            }

            // argv
            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
                if (argv_cplen <= 0) {
                    sp = sp ?: current_user_stack_pointer();
                    sp -= sizeof(legacy_su_path);
                    sp &= 0xFFFFFFFFFFFFFFF8;
                    argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                    if (argv_cplen > 0) {
                        int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                        if (rc < 0) { // todo: modify entire argv
                            logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, sctx,
                                   rc);
                        }
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
#endif // ANDROID
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2107
// COMPAT_SYSCALL_DEFINE3(execve, const char __user *, filename,
// 	const compat_uptr_t __user *, argv,
// 	const compat_uptr_t __user *, envp)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)

static void before_execve(hook_fargs3_t *args, void *udata)
{
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    handle_before_execve((char **)arg0p, (char **)arg1p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2114
// COMPAT_SYSCALL_DEFINE5(execveat, int, fd,
// 		       const char __user *, filename,
// 		       const compat_uptr_t __user *, argv,
// 		       const compat_uptr_t __user *, envp,
// 		       int,  flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
__maybe_unused static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve((char **)arg1p, (char **)arg2p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L431
// SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
// 		struct stat __user *, statbuf, int, flag)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L492
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L497
// SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode, int, flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L661
// SYSCALL_DEFINE5(statx,
// 		int, dfd, const char __user *, filename, unsigned, flags,
// 		unsigned int, mask,
// 		struct statx __user *, buffer)
/* Evaluated once per syscall by the dispatcher (syscall_hook_set_gate). Only
 * root / su-allow / trusted-manager callers reach the callbacks at all, which is
 * what lets su_handler_arg1_ufilename_before and friends drop their own root
 * checks: for everyone else the dispatcher runs no callback, on any syscall, so
 * there is no per-syscall signature and no cross-syscall inconsistency. */
static int su_syscall_gate(void)
{
    uid_t uid = current_uid();
    return uid == 0 || is_su_allow_uid(uid) || is_trusted_manager_uid(uid);
}

__maybe_unused static void su_handler_arg1_ufilename_before(hook_fargs6_t *args, void *udata)
{
    uid_t uid = current_uid();

    /* In global-dispatcher mode the dispatcher already gated this callback on the
     * caller's uid (su_syscall_gate), so the check would be redundant; the legacy
     * per-syscall fallback has no gate, so it must stay there. udata == 1 marks a
     * gated registration. */
    if (!udata && uid != 0 && !is_su_allow_uid(uid) && !is_trusted_manager_uid(uid)) return;

    char __user **u_filename_p = (char __user **)syscall_argn_p(args, 1);

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return;

#ifdef ANDROID
    if (strcmp(filename, current_su_path) && strcmp(filename, legacy_su_path)) return;
#else
    if (strcmp(filename, current_su_path)) return;
#endif
    {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) {
            *u_filename_p = uptr;
        } else {
            logkfi("su uid: %d, cp stack error: %d\n", uid, uptr);
        }
    }
}

#ifdef ANDROID
/*
 * A path that cannot identify a real su binary. /system is read-only for app
 * UIDs, so an untrusted caller cannot create this sentinel to defeat the hide.
 * Keep it shorter than both default aliases so the common path can be rewritten
 * in-place without allocating another struct filename.
 */
static const char hidden_su_path[] = "/system/.kp";
#endif

static void after_getname_flags(hook_fargs3_t *args, void *udata)
{
    struct filename *fn = (struct filename *)args->ret;
    if (IS_ERR_OR_NULL(fn)) return;

    const char *name = fn->name;
    if (!name) return;

#ifdef ANDROID
    /*
     * The VFS hook must hide a real su file from ungranted callers as well as
     * presenting a shell-compatible alias to granted callers. Do the cheap path
     * comparison first, so unrelated path lookups do not walk the SU allowlist.
     * This hook also covers execve path resolution, which the globally gated
     * syscall callbacks intentionally skip for ungranted UIDs.
     */
    if (strcmp(name, su_get_path()) && strcmp(name, legacy_su_path)) return;

    uid_t uid = current_uid();
    const char *target_path =
        (is_su_allow_uid(uid) || is_trusted_manager_uid(uid))
            ? sh_path : hidden_su_path;
#else
    if (strcmp(name, su_get_path())) return;

    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid) && !is_trusted_manager_uid(uid)) return;
    const char *target_path = sh_path;
#endif

    if (strlen(target_path) <= strlen(name)) {
        strcpy((char *)name, target_path);
        return;
    }

    if (kfunc(getname_kernel) && kfunc(putname)) {
        struct filename *nf = kfunc(getname_kernel)(target_path);
        if (!IS_ERR_OR_NULL(nf)) {
            kfunc(putname)(fn);
            args->ret = (uint64_t)nf;
            return;
        }
    }

    logkfi("uid: %d, cannot redirect su path to %s\n", uid, target_path);
}

// Use d_path(), not dentry_path_raw(): the latter omits the mountpoint, so a file
// mounted at /system/bin/su is represented as /bin/su and will not match the
// absolute Android alias. d_path() receives struct path and returns the mount-aware
// pathname for both getattr and file-open hooks.
typedef char *(*su_d_path_t)(const struct path *path, char *buf, int buflen);
static su_d_path_t su_d_path = 0;

static bool su_is_target_dentry_path(const char *path)
{
    if (!path || !path[0]) return false;
#ifdef ANDROID
    return !strcmp(path, su_get_path()) || !strcmp(path, legacy_su_path);
#else
    return !strcmp(path, su_get_path());
#endif
}

static void after_security_inode_getattr(hook_fargs1_t *args, void *udata)
{
    if ((long)args->ret < 0) return; // already an error, nothing to do

    uid_t uid = current_uid();
    bool granted = is_su_allow_uid(uid) || is_trusted_manager_uid(uid);

    const struct path *path = (const struct path *)args->arg0;
    if (!path || !su_d_path) return;

    char buf[PATH_MAX];
    char *p = su_d_path(path, buf, sizeof(buf));
    if (IS_ERR_OR_NULL(p) || !su_is_target_dentry_path(p)) return;

    // Hide the real su file from unprivileged callers; keep it visible to granted ones.
    if (!granted) {
        args->ret = (uint64_t)-ENOENT;
        logkfi("uid: %d, hide real su file: %s\n", uid, p);
    } else {
        logkfi("uid: %d, show real su file: %s\n", uid, p);
    }
}

/*
 * The small kernel shim headers intentionally forward-declare struct file.
 * On Linux 4.4, struct file starts with a union of llist_node and rcu_head,
 * both pointer-sized pairs on the supported 32/64-bit layouts; f_path follows
 * that 2-pointer-sized prefix. Mirror only this stable prefix rather than
 * inventing the remainder of struct file.
 */
struct su_file_path_layout {
    uintptr_t f_u[2];
    struct {
        void *mnt;
        void *dentry;
    } f_path;
};

/* Post-LSM open hook: resolve the path from the opened file to catch aliases
 * such as dot-dot components or symlinks that did not match getname_flags. */
static void after_security_file_open(hook_fargs2_t *args, void *udata)
{
    if ((long)args->ret < 0) return;

    struct file *file = (struct file *)args->arg0;
    if (!file || !su_d_path) return;

    struct su_file_path_layout *layout = (struct su_file_path_layout *)file;
    const struct path *path = (const struct path *)&layout->f_path;

    char buf[PATH_MAX];
    char *p = su_d_path(path, buf, sizeof(buf));
    if (IS_ERR_OR_NULL(p) || !su_is_target_dentry_path(p)) return;

    uid_t uid = current_uid();
    if (is_su_allow_uid(uid) || is_trusted_manager_uid(uid)) return;

    args->ret = (uint64_t)-ENOENT;
    logkfi("uid: %d, deny open of real su file: %s\n", uid, p);
}

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    long ids[len];
    int cnt = list_kstorage_ids(exclude_kstorage_gid, ids, len, false);
    for (int i = 0; i < len; i++) {
        uids[i] = (uid_t)ids[i];
    }
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

int su_compat_init()
{
    current_su_path = default_su_path;

    su_kstorage_gid = try_alloc_kstroage_group();
    if (su_kstorage_gid != KSTORAGE_SU_LIST_GROUP) return -ENOMEM;

    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

#ifdef ANDROID
    // default shell
    if (!all_allow_sctx[0]) {
        strcpy(all_allow_sctx, ALL_ALLOW_SCONTEXT_MAGISK);
    }
    su_add_allow_uid(2000, 0, all_allow_sctx);
    su_add_allow_uid(0, 0, all_allow_sctx);
#endif

    /* Gate every syscall-hook callback on the caller's uid, once per syscall, in
     * the dispatcher. Installed before the hooks below so none of them ever runs
     * for an unprivileged process. */
    syscall_hook_set_gate(su_syscall_gate);

    hook_err_t rc = HOOK_NO_ERR;

    uint8_t su_config = patch_config->patch_su_config;
    bool enable = !!(su_config & PATCH_CONFIG_SU_ENABLE);
    bool wrap = !!(su_config & PATCH_CONFIG_SU_HOOK_NO_WRAP);
    log_boot("su config: %x, enable: %d, wrap: %d\n", su_config, enable, wrap);

    // if (!enable) return;

    rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    /* Android init may execute commands through execveat().  Keep the
     * SUPERCMD/su redirection on both entry points; otherwise /system/bin/
     * truncate is executed literally and every apd bootstrap command exits
     * with status 1. */
    rc = hook_syscalln(__NR_execveat, 5, before_execveat, 0, (void *)0);
    log_boot("hook __NR_execveat rc: %d\n", rc);

    // __NR_execve 11
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    // __NR_execveat 387 on arm64 compat
    rc = hook_compat_syscalln(387, 5, before_execveat, 0, (void *)1);
    log_boot("hook 32 __NR_execveat rc: %d\n", rc);

    su_register_path_probe_hooks();

    return 0;
}
static int su_hook_getname_flags(void)
{
    unsigned long addr = kallsyms_lookup_name_by_suffix("getname_flags");
    if (!addr) {
        log_boot("getname_flags not found (including compiler suffixes)\n");
        return -HOOK_BAD_ADDRESS;
    }

    hook_err_t rc = hook_wrap3((void *)addr, 0, after_getname_flags, (void *)0);
    if (rc) {
        log_boot("hook getname_flags @ %llx rc: %d\n", addr, rc);
        return rc;
    }

    su_getname_flags_addr = addr;
    su_getname_flags_hooked = true;
    log_boot("hook getname_flags @ %llx rc: 0\n", addr);
    return 0;
}

static int su_hook_security_file_open(void)
{
    /*
     * This shim models the Linux 4.4 struct file prefix. Newer kernels may
     * reorder struct file (some builds enable __randomize_layout), so never
     * dereference this layout there. Keep the resolved-open backstop scoped to
     * the XZP 4.4 target; other kernels retain the upstream path/getattr hooks.
     */
    if (kver < VERSION(4, 4, 0) || kver >= VERSION(4, 5, 0)) {
        log_boot("security_file_open SU path check skipped: file layout shim is Linux 4.4-specific (kver=%x)\n",
                 kver);
        return -EOPNOTSUPP;
    }

    /*
     * security_file_open sees the resolved file path, so it complements
     * getname_flags (which only sees the original spelling) and catches path
     * aliases such as dot-dot components or symlinks to a real su binary.
     */
    if (!su_d_path) {
        unsigned long d_path_addr = kallsyms_lookup_name_by_suffix("d_path");
        if (!d_path_addr) {
            log_boot("d_path not found for security_file_open\n");
            return -HOOK_BAD_ADDRESS;
        }
        su_d_path = (su_d_path_t)d_path_addr;
    }

    unsigned long addr = kallsyms_lookup_name_by_suffix("security_file_open");
    if (!addr) {
        log_boot("security_file_open not found (including compiler suffixes)\n");
        return -HOOK_BAD_ADDRESS;
    }

    hook_err_t rc = hook_wrap2((void *)addr, 0, after_security_file_open, (void *)0);
    if (rc) {
        log_boot("hook security_file_open @ %llx rc: %d\n", addr, rc);
        return rc;
    }

    su_security_file_open_addr = addr;
    su_security_file_open_hooked = true;
    log_boot("hook security_file_open @ %llx, d_path @ %llx rc: 0\n",
             addr, (uint64_t)su_d_path);
    return 0;
}

static int su_hook_security_inode_getattr(void)
{
    unsigned long d_path_addr = kallsyms_lookup_name_by_suffix("d_path");
    if (!d_path_addr) {
        log_boot("d_path not found (including compiler suffixes)\n");
        return -HOOK_BAD_ADDRESS;
    }

    su_d_path = (su_d_path_t)d_path_addr;

    unsigned long getattr_addr = kallsyms_lookup_name_by_suffix("security_inode_getattr");
    if (!getattr_addr) {
        log_boot("security_inode_getattr not found (including compiler suffixes)\n");
        return -HOOK_BAD_ADDRESS;
    }

    hook_err_t rc = hook_wrap1((void *)getattr_addr, 0, after_security_inode_getattr, (void *)0);
    if (rc) {
        log_boot("hook security_inode_getattr @ %llx rc: %d\n", getattr_addr, rc);
        return rc;
    }

    su_security_inode_getattr_addr = getattr_addr;
    su_security_inode_getattr_hooked = true;
    log_boot("hook security_inode_getattr @ %llx, d_path @ %llx rc: 0\n",
             getattr_addr, d_path_addr);
    return 0;
}

/*
 * Remove the legacy per-syscall fallback once the shared path hooks are ready.
 * Registration can be retried after a partial hook failure; without this cleanup,
 * a later successful retry would leave both mechanisms active until an explicit
 * disable, adding redundant callbacks and making registration state misleading.
 */
static void su_unregister_legacy_path_probe_hooks(void)
{
    if (su_legacy_fstatat_hooked) {
        unhook_syscalln(__NR3264_fstatat, su_handler_arg1_ufilename_before, 0);
        su_legacy_fstatat_hooked = false;
    }
    if (su_legacy_faccessat_hooked) {
        unhook_syscalln(__NR_faccessat, su_handler_arg1_ufilename_before, 0);
        su_legacy_faccessat_hooked = false;
    }
    if (su_legacy_compat_fstatat64_hooked) {
        unhook_compat_syscalln(327, su_handler_arg1_ufilename_before, 0);
        su_legacy_compat_fstatat64_hooked = false;
    }
    if (su_legacy_compat_faccessat_hooked) {
        unhook_compat_syscalln(334, su_handler_arg1_ufilename_before, 0);
        su_legacy_compat_faccessat_hooked = false;
    }
}

static void su_register_path_probe_hooks(void)
{
#ifdef ANDROID
    if (unlikely(android_is_safe_mode)) return;
#endif
    hook_err_t rc;

    /*
     * Prefer the shared upstream path-observation hooks. On this 4.4 kernel
     * getname_flags() and security_inode_getattr() are real VFS entry points,
     * and d_path() lets the getattr/open hooks identify the resolved absolute path.
     *
     * If either hook cannot be resolved/installed, keep the legacy syscall
     * probes below as a conservative fallback rather than silently disabling
     * path compatibility.
     */
    if (!su_getname_flags_hooked)
        su_hook_getname_flags();
    if (!su_security_inode_getattr_hooked)
        su_hook_security_inode_getattr();
    if (!su_security_file_open_hooked)
        su_hook_security_file_open();

    log_boot("su path concealment hooks: getname_flags=%d inode_getattr=%d file_open=%d\n",
             su_getname_flags_hooked, su_security_inode_getattr_hooked,
             su_security_file_open_hooked);

    /*
     * On the Linux 4.4 target, require security_file_open as well as the
     * metadata hooks before declaring shared path concealment complete. It
     * observes the resolved path for file opens, closing the symlink/dot-dot
     * alias gap that getname_flags alone cannot see.
     *
     * The struct file layout shim is intentionally limited to Linux 4.4;
     * kernels outside that range retain the getname_flags/getattr behavior.
     */
    bool resolved_open_required =
        kver >= VERSION(4, 4, 0) && kver < VERSION(4, 5, 0);
    bool shared_hooks_ready =
        su_getname_flags_hooked && su_security_inode_getattr_hooked &&
        (!resolved_open_required || su_security_file_open_hooked);

    if (shared_hooks_ready) {
        su_unregister_legacy_path_probe_hooks();
        log_boot("shared path probes enabled: getname_flags=%d inode_getattr=%d file_open=%d; legacy fstatat/faccessat probes skipped\n",
                 su_getname_flags_hooked, su_security_inode_getattr_hooked,
                 su_security_file_open_hooked);
        return;
    }

    if (resolved_open_required && !su_security_file_open_hooked) {
        log_boot("WARNING: resolved-open SU alias concealment unavailable; retaining legacy fstatat/faccessat probes\n");
    } else {
        log_boot("shared path probes incomplete; retaining legacy fstatat/faccessat probes\n");
    }

    /* Legacy per-syscall fallback. */
    void *gated = syscall_hook_global_enabled() ? (void *)1 : (void *)0;

    if (!su_legacy_fstatat_hooked) {
        rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, 0, gated);
        su_legacy_fstatat_hooked = su_hook_result_is_registered(rc);
        log_boot("legacy hook __NR3264_fstatat rc: %d registered=%d\n", rc,
                 su_legacy_fstatat_hooked);
    }

    if (!su_legacy_faccessat_hooked) {
        rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, 0, gated);
        su_legacy_faccessat_hooked = su_hook_result_is_registered(rc);
        log_boot("legacy hook __NR_faccessat rc: %d registered=%d\n", rc,
                 su_legacy_faccessat_hooked);
    }

    /* 32-bit compat probes: fstatat64(327) / faccessat(334). */
    if (!su_legacy_compat_fstatat64_hooked) {
        rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, 0, gated);
        su_legacy_compat_fstatat64_hooked = su_hook_result_is_registered(rc);
        log_boot("legacy hook 32 __NR_fstatat64 rc: %d registered=%d\n", rc,
                 su_legacy_compat_fstatat64_hooked);
    }

    if (!su_legacy_compat_faccessat_hooked) {
        rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, 0, gated);
        su_legacy_compat_faccessat_hooked = su_hook_result_is_registered(rc);
        log_boot("legacy hook 32 __NR_faccessat rc: %d registered=%d\n", rc,
                 su_legacy_compat_faccessat_hooked);
    }

}

static void su_unregister_path_probe_hooks(void)
{
    su_unregister_legacy_path_probe_hooks();

    if (su_security_file_open_hooked) {
        hook_unwrap((void *)su_security_file_open_addr, 0, after_security_file_open);
        su_security_file_open_addr = 0;
        su_security_file_open_hooked = false;
    }

    if (su_security_inode_getattr_hooked) {
        hook_unwrap((void *)su_security_inode_getattr_addr, 0, after_security_inode_getattr);
        su_security_inode_getattr_addr = 0;
        su_security_inode_getattr_hooked = false;
    }

    if (su_getname_flags_hooked) {
        hook_unwrap((void *)su_getname_flags_addr, 0, after_getname_flags);
        su_getname_flags_addr = 0;
        su_getname_flags_hooked = false;
    }

    /*
     * Keep the resolved d_path address cached. hook_unwrap() removes callbacks
     * but does not wait for already-running callbacks to drain; clearing this
     * pointer here could race with an in-flight callback that is about to call
     * d_path(). The kernel symbol remains valid while KernelPatch is resident.
     */
}

void sucompat_init()
{
    return;
    struct file *file = filp_open(sucompat_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
        log_boot("failed to open sucompat file: %ld\n", PTR_ERR(file));
        return;
    }
    filp_close(file, NULL);
    su_register_path_probe_hooks(); 
}
