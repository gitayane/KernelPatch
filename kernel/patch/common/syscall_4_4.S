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
