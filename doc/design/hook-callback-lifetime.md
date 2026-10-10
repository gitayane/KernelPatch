# Hook callback lifetime and KPM unload design

Status: design note only; no runtime behavior is changed by this document.

Base revision: `0f0cdf17f2f6111bc82641613e98d996503b1036` on
`work/xzp-4.4-stack-restore`.

## Problem statement

The Linux 4.4 global syscall dispatcher copies callback pointers and userdata
into a per-syscall stack snapshot. Reusing that snapshot for before/after
callbacks keeps the callback set stable, but a concurrent unhook can remove a
slot while an older snapshot still contains its function pointer. KPM unload
runs the module exit callback and then frees the module's executable allocation.
There is no explicit protocol connecting these events.

The generic inline-hook transit functions (for example `_transit8()`) also
read callback arrays while those arrays may be modified. Fixing only the
Linux 4.4 syscall backend is therefore insufficient for a general KPM unload
guarantee.

## Required invariants

1. A callback may be entered only after its registration has been validated
   and an execution reference has been acquired.
2. Unregistration prevents future callback entries, including entries through
   snapshots or chains created before unregistration.
3. An execution reference is released after each individual callback returns,
   not after the entire syscall. A syscall handler can sleep, so a module
   reference must not be held across the original syscall.
4. Module executable memory is not freed while any callback from that module
   is executing.
5. Callback pairing semantics are explicit. If a before callback has run, its
   corresponding after callback must either run while the callback remains
   pinned, or the API must explicitly define a safe cancellation rule.
6. Unhook/unload from inside the same callback must not wait synchronously for
   its own execution reference. This case needs a defined rejection or deferred
   teardown path rather than a busy loop.
7. No sleep/wait operation may occur while holding a spinlock, under an RCU
   read-side critical section, or with preemption/interrupt state incompatible
   with sleeping.

## Proposed architecture (not implemented)

### A. Registration records and callback ownership

Represent each registration with a stable record containing:
- callback pointers and userdata;
- a monotonically changing generation/state;
- the owning KPM module, if the callback address falls within that module's
  executable range;
- per-callback in-flight counts (or an equivalent stable reference object).

Do not infer that a copied function pointer is safe merely because its slot was
valid when the snapshot was created. Every callback entry must validate the
record/generation and acquire its in-flight reference atomically with respect
to unregistration.

Owner detection must be explicit and checked against the actual executable
range; callbacks in core KP code have no KPM owner. If a callback cannot be
associated safely with an owner, unload must not assume it is protected.

### B. Dispatcher snapshot

A syscall snapshot should retain stable registration handles and generations,
not only raw function pointers. Before each callback:
1. acquire/validate the registration reference under a short non-sleeping lock;
2. drop the lock;
3. invoke the callback;
4. release the reference and signal waiters if the count reaches zero.

The reference must not span the original syscall. The before/after pairing rule
needs special care if unregistration happens while the original syscall runs.
The implementation must choose and document one policy before coding:
- keep an independent reference for the paired after callback, or
- cancel the after callback safely and release the pair reservation.
The former is easier to reason about but requires the module unload path to
wait for pair reservations as well as actively executing callback bodies.

### C. Unregistration and slot reuse

Unregistration should mark a registration as draining/dead under the registry
lock, advance its generation, and prevent new reference acquisition. It must
not immediately recycle storage while snapshots still refer to it. Reuse only
after all active references and snapshot/pair reservations are gone, or use a
separately allocated stable registration object with deferred reclamation.

Avoid holding a spinlock while waiting. Avoid relying on RCU alone: syscall
callbacks and the original syscall can sleep, so an RCU read-side section must
not be stretched across the full dispatch.

### D. KPM unload ordering

A safe unload sequence needs a module-level state transition:
1. atomically mark the module as unloading so no new registrations owned by it
   can be added;
2. call the module exit callback to unregister hooks;
3. wait for all callback executions and paired reservations owned by that
   module to drain using a wait/wakeup primitive verified to exist in this
   KP runtime;
4. only then unlink/free module metadata and release executable memory.

The current `unload_module()` holds `rcu_read_lock()` while unlinking the module,
calling its exit callback, and freeing it. That is not a sufficient callback
lifetime protocol and must be redesigned separately. The list/module-control
locking problem must be addressed without calling arbitrary module callbacks
while holding a lock that those callbacks can re-enter.

### E. Generic hook chains

The same lifetime model must cover inline/FP hook chains (including
`_transit0()`, `_transit4()`, and `_transit8()`) or the project must explicitly
scope the first implementation to syscall hooks and prevent unloading modules
that register unsupported hook types. A syscall-only fix must not be described
as a general KPM unload fix.

## Implementation phases

1. **Inventory and API contract:** enumerate all callback registration APIs and
   unregistration paths; determine how KPM callback addresses map to module
   executable ranges; locate a safe wait/wakeup primitive and module-list lock.
2. **Core lifetime primitive:** implement a stable registration/reference object
   with non-sleeping acquire/release and safe deferred reclamation.
3. **Syscall dispatcher integration:** convert Linux 4.4 snapshots and generic
   syscall dispatch to stable handles; preserve before/after semantics and
   release execution references around each callback.
4. **Unload integration:** implement module draining and wait outside spinlocks
   and RCU critical sections; define self-unload/self-unhook behavior.
5. **Generic hook-chain integration:** protect callback array reads and writes
   with the same ownership/lifetime contract.
6. **Validation:** compile all supported configurations; run CI; add stress tests
   for concurrent hook/unhook, callback registration during dispatch, callback
   self-unhook, module unload racing with a sleeping original syscall, and
   repeated slot reuse. Inspect generated assembly/stack use for the 4.4 path.
7. **Device test:** only after the above passes, test on the XZP with a recovery
   path. Do not treat CI success alone as proof of unload-race safety.

## Explicit non-goals for the first patch

- No global busy-wait loop.
- No waiting while holding a spinlock or RCU read lock.
- No module-wide reference held across the original syscall.
- No claim that snapshot consistency alone makes module unload safe.
- No merge into `main`, release, or device flash until the implementation and
  stress validation are complete.


## Audit findings (2026-10-10)

The first source inventory is complete. These findings narrow the implementation
plan; they do not change runtime behavior.

### Callback registration surfaces

| Surface | Registration / removal API | Runtime storage / dispatch |
|---|---|---|
| Global syscall dispatcher | `syscall_hook_add()` / `syscall_hook_remove()`, exported wrappers in `kernel/patch/common/syscall.c` | Static `syscall_hooks[64]`; Linux 4.4 path snapshots up to 16 raw callback/userdata tuples per syscall |
| Inline hook chain | `hook_wrap()` / `hook_unwrap_remove()`; lower-level `hook_chain_add()` / `hook_chain_remove()` | `hook_chain_t` arrays in `kernel/base/hook.c`; `_transit0/4/8/12()` read states, callback pointers, and userdata separately |
| Function-pointer hook chain | `fp_hook_wrap()` / `fp_hook_unwrap()` | `fp_hook_chain_t` arrays in `kernel/base/fphook.c`; `_fp_transit0/4/8/12()` have the same lifetime race |
| Direct inline replacement | `hook()` / `unhook()` family | Replaces the target directly; the public header already warns that simultaneous module hooks can make unload abnormal. This API cannot be made unload-safe merely by protecting callback records. |

The generic inline and FP transit paths do not take a stable callback snapshot:
they check `states[i]`, then separately read the callback and userdata, invoke
before callbacks, call the origin, and separately reread states/callbacks for
after callbacks. A concurrent removal can therefore affect both pointer
consistency and before/after pairing. The same pattern is present in the 0-, 4-,
8-, and 12-argument transit variants.

### KPM ownership and module operations

- `struct module` currently has executable allocation bounds (`start`,
  `size`, `text_size`, `ro_size`) but no unloading state, active-call count,
  wait object, or callback-registration list.
- `unload_module()` currently unlinks the module, calls its exit callback, and
  frees module arguments, control arguments, executable memory, and metadata
  while inside `rcu_read_lock()`. Its own source comment still says
  `todo: lock`.
- `module_control0()`, `module_control1()`, and
  `notify_modules_event()` invoke arbitrary module callbacks while holding an
  RCU read lock. A new unload lock must not be held across these callbacks if
  they can re-enter module APIs.
- `find_module()` walks the module list without acquiring `module_lock`.
  `module_lock` is initialized, but the current code does not use it to
  serialize list lookup, insertion, removal, or concurrent control calls.
- Owner detection by checking a callback address against a module's executable
  range is possible in principle, but a registration record needs to retain a
  stable owner identity; it must not repeatedly dereference a possibly freed
  `struct module` to discover ownership.

### Synchronization primitives available in this tree

The KP-private include tree exposes its spinlock wrapper
(`kp_private_spin_lock/unlock`) and a minimal `atomic_t` type in
`kernel/include/ktypes.h`. The checked-in `kernel/linux/include/linux`
subset contains `rcupdate.h`, `sched.h`, and `spinlock.h`, but no
`wait.h` or `completion.h` in that subset. Therefore the audit has **not**
established a supported sleepable wait/wakeup API for this runtime. We must not
invent `wait_event()`, `completion`, or refcount helpers based on assumptions;
the next implementation step must either verify which target-kernel symbols
can safely be resolved in this environment or introduce a small, reviewed
wait/wakeup abstraction.

### Implementation consequence

Do not start by adding a counter to `syscall_hooks[]` alone. A counter in a
reusable slot still races with slot reuse and cannot protect generic inline/FP
chains. The smallest coherent runtime change needs:

1. a stable callback-registration object and an atomic state/ref acquisition
   rule shared by syscall, inline-chain, and FP-chain dispatch;
2. explicit callback owner tracking, plus a module unloading state that blocks
   new registrations;
3. a verified wait/wakeup mechanism and a documented rule for self-unhook and
   self-unload;
4. module-list serialization and references for control/event callbacks, so
   `unload_module()` cannot free module code while those entry points execute.

Until these four pieces are grounded, the correct result is to keep this branch
design-only rather than land a partial counter/RCU fix that could still execute
freed KPM code.


### Follow-up: sleep/wakeup API verification

A deeper read of the checked-in compatibility headers refined the earlier result:

- `kernel/linux/include/linux/sched.h` declares
  `schedule_timeout_uninterruptible()` and `wake_up_process()`.
- `kernel/linux/arch/arm64/include/asm/current.h` provides a target-layout-aware
  `current` accessor.
- However, the available compatibility declarations do not expose the normal
  `set_current_state()` / `__set_current_state()` helpers or the
  `TASK_UNINTERRUPTIBLE` state definitions, and this tree does not include the
  usual wait-queue API. Merely calling `schedule_timeout_uninterruptible()`
  is not a correct wait protocol unless the current task state is prepared
  correctly. A hand-written task-state update based on guessed offsets would be
  unsafe, especially because this project supports kernels with different
  task layouts.

The safe options still to verify are:

1. whether KP's target-symbol resolver can safely expose the actual task-state
   helpers and their constants for this build; or
2. whether a bounded, explicit sleep/poll abstraction can be implemented using
   supported scheduler interfaces without depending on private task offsets.

The implementation must also avoid sleeping while holding a spinlock, during
atomic/interrupt context, or from a callback that is attempting to drain itself.
No scheduler code has been changed in this commit.


### Follow-up: what symbol resolution can and cannot provide

The resolver in `kernel/patch/include/ksyms.h` resolves named addresses through
`kallsyms_lookup_name_by_suffix()`; the `kfunc` declarations are function
pointer slots populated by the symbol-matching path. This can discover a real
function symbol if the target kernel exposes it under a matching name. It
cannot discover a C preprocessor macro or an enum/constant such as
`TASK_UNINTERRUPTIBLE`: those have no runtime symbol address to resolve.

Consequently, the resolver is not a way to recover `set_current_state()` or
task-state constants if the target compiler emitted them as inline operations
or compile-time values. Nor should a guessed `task_struct` state offset be
introduced as a substitute.

The compatibility header declares `schedule_timeout_uninterruptible()` and
`wake_up_process()`, but the declaration alone does not prove that the exact
target kernel exports a callable symbol with that name, or that its calling
contract is suitable for every caller. Before a wait abstraction uses it, the
implementation must verify the actual target symbol and semantics for the
supported 4.4.302 build, and restrict sleeping to a context known to permit it.
A timed sleep/poll loop could be considered only in the process-context unload
path, outside locks and RCU sections, with self-unload explicitly rejected;
it is not a general callback-side wait primitive.

**Decision:** do not add scheduler symbol declarations or task-state offsets
just to make a counter-based drain compile. The next runtime patch should first
introduce stable registration records and owner tracking with nonblocking
reference acquisition/release; module draining should be wired in only after a
target-verified wait strategy and callback-context contract are established.


### Follow-up: concrete registry protocol before runtime integration

The first runtime change must not put references in the existing fixed hook slots
and then free/reuse those slots immediately. A dispatcher may already have
copied a slot index, so slot-local counters alone do not identify the same
registration after reuse. The implementation should use stable registration
objects whose addresses remain valid until all readers that could have observed
them have left the registry's read-side protocol.

The minimum record contract is:

```c
struct kp_hook_registration {
    /* immutable after publication */
    void *before;
    void *after;
    void *userdata;
    struct module *owner; /* pinned by module-level lifetime protocol */
    unsigned long generation;

    /* protected by registry lock */
    unsigned int state;   /* NEW, LIVE, DRAINING, DEAD */
    unsigned int active;  /* callback bodies currently executing */
    unsigned int reserved;/* dispatch/pair snapshots retaining this record */
    struct list_head registry_node;
    struct list_head owner_node;
};
```

This is a contract sketch, not a header to copy verbatim: field widths,
atomic operations, allocator choice, and list types must match the actual KP
headers. In particular, `owner` cannot be a raw pointer whose module metadata
may be freed while a registration is still reachable.

Required transition rules:

1. Allocate and fully initialize a record before publication. Publish it as
   LIVE while holding the registry lock, and reject registration if its owner
   has entered UNLOADING.
2. A dispatcher reserves the record under the same lock used by removal before
   retaining it in a snapshot. The reservation prevents reclamation; it does
   not by itself authorize callback entry.
3. Immediately before invoking a callback, under the registry lock verify
   LIVE (or a specifically documented paired-after state), validate generation,
   and increment `active`. Drop the lock before calling module code.
4. After return, decrement `active` under the lock. Release the snapshot
   reservation independently when the dispatcher can no longer use the record.
5. Removal marks DRAINING under the lock, preventing fresh reservations and
   ordinary callback entry. It then waits for `active == 0` and
   `reserved == 0` outside the lock and outside RCU. Only then may it unlink
   the record from owner/global lists and reclaim it.
6. A before/after pair must reserve both callbacks' lifetime before the origin
   executes, but must not keep an executing-callback reference over the origin
   syscall. The after policy must be explicit if removal races with the origin.
7. Synchronous removal from the same active callback must return a defined
   error or defer reclamation; it must not wait for its own `active` reference.
8. The module must remain allocated while any registration or control/event
   invocation refers to it. A module reference alone is insufficient unless
   every callback entry path participates in the same protocol.

The current APIs expose no single primitive that safely waits for a condition
in all callback contexts. Therefore this protocol is split deliberately:
registry reservation/entry/exit are nonblocking and lock-bounded; draining is
a process-context operation with a separately verified wait implementation.
The unload API must reject contexts that cannot sleep, and must reject or defer
self-unload. Do not silently turn the drain into a spin loop.

### Scope gate for the first runtime patch

The first implementation must either convert all three callback-dispatch
families (syscall, inline chain, FP chain) and module control/event entry paths
together, or introduce an explicit capability/ownership registry that makes
unload fail safely when a module has registered an unsupported hook type.
Direct replacement hooks (`hook()/unhook()`) require their own ownership
tracking and teardown contract; they must not be implied safe by the callback
registry. A partial syscall-only conversion without an unload restriction is
not an acceptable safety fix.

### Follow-up: module address ownership and publication audit (2026-10-11)

The module loader's current layout makes callback-owner detection feasible for
normal KPM function pointers, but only as a registration-time operation:

- `move_module()` allocates `mod->start` for `mod->size` bytes and relocates
  allocated ELF sections into that allocation. `mod->text_size` marks the
  executable portion; `mod->ro_size` marks the end of the read-only portion.
- A callback function must be in the executable interval
  `[start, start + text_size)`, not merely anywhere in `[start, start + size)`.
  A userdata pointer is not evidence of callback ownership: KPMs may pass
  kernel-owned or separately allocated userdata.
- Before doing pointer-range arithmetic, validate non-null `start`, nonzero
  `text_size`, and overflow-safe bounds. A callback pointer outside all
  registered KPM text ranges is core/external code or unknown; it must not be
  silently assigned to whichever module is being loaded or unloaded.
- The resolved owner must be retained through a stable module reference/state
  protocol. Looking up the owner again from a callback address after unload
  has started is unsafe because the module allocation can be freed or reused.

The module-list publication path is also not serialized as a whole. The loader
checks `find_module(info->info.name)` before allocating and linking the new
module, while `find_module()` itself traverses `modules.list` without taking
the declared `module_lock`. Two concurrent loads can therefore both pass the
duplicate-name check. Fixing only `unload_module()` would leave this race and
could make any module-owner registry inconsistent.

This yields two prerequisites for a runtime patch:

1. Make module lookup/duplicate-check/publication/removal a single coherent
   list-locking protocol, while never invoking `init`, `exit`, `ctl0`,
   `ctl1`, or event callbacks under the list lock.
2. Add owner references at registration time using the executable text range,
   and make registration fail closed if the callback owner is ambiguous or
   already unloading. Do not infer ownership from `userdata` or from a
   broad module allocation range.

This audit is still design-only. It does not change the module list, callback
registration, or unload behavior.


### Follow-up: initialization and control-call lifetime audit (2026-10-11)

Two additional ordering problems must be handled before owner tracking can be
implemented correctly.

**A KPM can register hooks before it is discoverable in the module list.**
In `load_module_ex()`, the loader relocates the module, calls `mod->init()`,
and only after successful return adds `mod->list` to `modules.list`. A KPM
init function can call exported hook APIs during that interval. Therefore,
resolving callback ownership only by scanning the published module list will
fail to find the module that is currently initializing. Treating that callback
as core/unknown would either lose the owner association or force an unsafe
fallback.

The implementation needs an explicit LOADING/INITIALIZING module registry or
an equivalent registration context that is visible to hook registration before
`mod->init()` runs. That state must participate in duplicate-name exclusion
and owner resolution, but it must not make a half-initialized KPM appear as a
normal loaded module to control/event callers. If init fails after registering
hooks, the failure path must drain/unregister those registrations before
freeing `mod->start`; calling `mod->exit()` alone cannot be assumed to remove
every hook unless the API contract enforces that behavior.

**Module control paths have their own shared-state race.** `module_control0()`
frees and replaces `mod->ctl_args` before calling `ctl0`, while the current
module-list lock is not used to serialize control calls or protect the module
from concurrent unload. Two simultaneous control calls can race on
`ctl_args`, and an unload can free the module while a control/event callback
is active. The lifetime protocol must pin the module across each control/event
callback, and `ctl_args` must either be per-call storage or protected by a
separate serialization rule. Do not solve this by holding the module-list
spinlock while invoking arbitrary KPM code.

Updated minimum module states: `LOADING` (owner resolution allowed, normal
control/event lookup disallowed), `LIVE` (normal operations allowed),
`UNLOADING` (new registrations and normal invocations rejected), and
`DEAD` (eligible for reclamation only after every module/callback reference
has drained). State publication and duplicate-name exclusion need one coherent
locking protocol; callback execution remains outside that lock.

These findings further rule out a narrow fix to `unload_module()` or to the
syscall hook table alone. The initialization path, all hook families, control
calls, event iteration, and module-list publication must agree on the same
owner/lifetime contract.
