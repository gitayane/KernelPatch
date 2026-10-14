/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Linux 4.4 ARM64 syscall-dispatch entry veneers. */

    .text
    .align 2

    .global kp_syscall_4_4_fast_entry
    .type kp_syscall_4_4_fast_entry, %function
kp_syscall_4_4_fast_entry:
    /* Preserve the exception-entry callee-saved register state below pt_regs. */
    sub sp, sp, #96
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    add x0, sp, #96
    mov x1, x26
    mov x2, sp
    b kp_syscall_4_4_fast_dispatch
    .size kp_syscall_4_4_fast_entry, .-kp_syscall_4_4_fast_entry

    .global kp_syscall_4_4_trace_entry
    .type kp_syscall_4_4_trace_entry, %function
kp_syscall_4_4_trace_entry:
    /* Keep the same frame layout as the fast path. */
    sub sp, sp, #96
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    add x0, sp, #96
    mov x1, x26
    mov x2, sp
    b kp_syscall_4_4_trace_dispatch
    .size kp_syscall_4_4_trace_entry, .-kp_syscall_4_4_trace_entry


/*
 * Pass through syscalls which have no registered KP callback. Restore the
 * original pt_regs stack/register convention, then perform the same table
 * lookup and handler call that the overwritten entry sequence performed.
 */
    .global kp_syscall_4_4_passthrough_fast
    .type kp_syscall_4_4_passthrough_fast, %function
kp_syscall_4_4_passthrough_fast:
    mov x9, x0
    ldp x19, x20, [x9, #0]
    ldp x21, x22, [x9, #16]
    ldp x23, x24, [x9, #32]
    ldp x25, x26, [x9, #48]
    ldp x27, x28, [x9, #64]
    ldp x29, x30, [x9, #80]
    add sp, x9, #96
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldr x16, [x27, x26, lsl #3]
    blr x16
    adrp x16, syscall_4_4_fast_return
    ldr x16, [x16, :lo12:syscall_4_4_fast_return]
    br x16
    .size kp_syscall_4_4_passthrough_fast, .-kp_syscall_4_4_passthrough_fast

    .global kp_syscall_4_4_passthrough_trace
    .type kp_syscall_4_4_passthrough_trace, %function
kp_syscall_4_4_passthrough_trace:
    mov x9, x0
    ldp x19, x20, [x9, #0]
    ldp x21, x22, [x9, #16]
    ldp x23, x24, [x9, #32]
    ldp x25, x26, [x9, #48]
    ldp x27, x28, [x9, #64]
    ldp x29, x30, [x9, #80]
    add sp, x9, #96
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldr x16, [x27, x26, lsl #3]
    blr x16
    str x0, [sp, #0]
    adrp x16, kp_syscall_4_4_trace_return
    ldr x16, [x16, :lo12:kp_syscall_4_4_trace_return]
    br x16
    .size kp_syscall_4_4_passthrough_trace, .-kp_syscall_4_4_passthrough_trace

/*
 * Resume the original 4.4 entry path after the C dispatcher has completed.
 * x0=frame below pt_regs, x1=return value, x2=continuation address.
 * Restore the original kernel callee-saved registers and the pt_regs SP before
 * branching; calling ret_fast_syscall/its trace continuation on the C stack is
 * unsafe because those paths expect SP to point at pt_regs.
 */
    .global kp_syscall_4_4_resume
    .type kp_syscall_4_4_resume, %function
kp_syscall_4_4_resume:
    mov x9, x0
    mov x10, x1
    mov x11, x2
    ldp x19, x20, [x9, #0]
    ldp x21, x22, [x9, #16]
    ldp x23, x24, [x9, #32]
    ldp x25, x26, [x9, #48]
    ldp x27, x28, [x9, #64]
    ldp x29, x30, [x9, #80]
    add sp, x9, #96
    mov x0, x10
    br x11
    .size kp_syscall_4_4_resume, .-kp_syscall_4_4_resume


/*
 * Tail-dispatch syscall-table wrappers that require the original pt_regs stack
 * (e.g. rt_sigreturn and AArch32 ABI-repacking wrappers).
 *
 * x0=frame below pt_regs, x1=original wrapper, x2=normal continuation,
 * x3=non-zero for the __sys_trace path. Restore x0-x7 and the original stack.
 * In the trace path, return through a tiny trampoline that performs the STR
 * that the overwritten entry instruction would have performed before continuing
 * at the original __sys_trace return path.
 */
    .global kp_syscall_4_4_resume_special
    .type kp_syscall_4_4_resume_special, %function
kp_syscall_4_4_resume_special:
    mov x9, x0
    mov x10, x1
    mov x11, x2
    mov x12, x3
    ldp x19, x20, [x9, #0]
    ldp x21, x22, [x9, #16]
    ldp x23, x24, [x9, #32]
    ldp x25, x26, [x9, #48]
    ldp x27, x28, [x9, #64]
    ldp x29, x30, [x9, #80]
    add x13, x9, #96
    ldp x0, x1, [x13, #0]
    ldp x2, x3, [x13, #16]
    ldp x4, x5, [x13, #32]
    ldp x6, x7, [x13, #48]
    add sp, x9, #96
    cbz x12, 1f
    adr x30, kp_syscall_4_4_special_trace_return
    br x10
1:
    mov x30, x11
    br x10
kp_syscall_4_4_special_trace_return:
    /* Mirror the original STR X0,[SP] at the patched trace site. */
    str x0, [sp, #0]
    /*
     * Do not read the saved frame below pt_regs after the handler returns:
     * the handler's downward-growing stack may have reused that memory.
     * The wrapper preserves x19-x28 by ABI except for intentional x27 changes
     * (sigreturn clears x27), which must remain intact here.
     */
    adrp x10, kp_syscall_4_4_trace_return
    ldr x10, [x10, :lo12:kp_syscall_4_4_trace_return]
    /* Original BLR would leave LR at the STR instruction (continuation - 4). */
    sub x30, x10, #4
    br x10
    .size kp_syscall_4_4_resume_special, .-kp_syscall_4_4_resume_special
