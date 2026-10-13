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
 * x0=frame below pt_regs, x1=original wrapper address, x2=normal continuation.
 * Restore the state that the original LDR/BLR sequence would have presented,
 * especially SP=pt_regs and x0-x7. The wrapper returns directly to the supplied
 * continuation, so the C dispatcher is deliberately bypassed for these entries.
 */
    .global kp_syscall_4_4_resume_special
    .type kp_syscall_4_4_resume_special, %function
kp_syscall_4_4_resume_special:
    mov x9, x0
    mov x10, x1
    mov x11, x2
    ldp x19, x20, [x9, #0]
    ldp x21, x22, [x9, #16]
    ldp x23, x24, [x9, #32]
    ldp x25, x26, [x9, #48]
    ldp x27, x28, [x9, #64]
    ldp x29, x30, [x9, #80]
    add x12, x9, #96
    ldp x0, x1, [x12, #0]
    ldp x2, x3, [x12, #16]
    ldp x4, x5, [x12, #32]
    ldp x6, x7, [x12, #48]
    add sp, x9, #96
    mov x30, x11
    br x10
    .size kp_syscall_4_4_resume_special, .-kp_syscall_4_4_resume_special
