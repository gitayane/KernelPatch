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
