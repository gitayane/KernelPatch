/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Linux 4.4 ARM64 syscall-dispatch entry veneers. */

    .text
    .align 2

    .global kp_syscall_4_4_fast_entry
    .type kp_syscall_4_4_fast_entry, %function
kp_syscall_4_4_fast_entry:
    mov x0, sp
    mov x1, x26
    b kp_syscall_4_4_fast_dispatch
    .size kp_syscall_4_4_fast_entry, .-kp_syscall_4_4_fast_entry

    .global kp_syscall_4_4_trace_entry
    .type kp_syscall_4_4_trace_entry, %function
kp_syscall_4_4_trace_entry:
    mov x0, sp
    mov x1, x26
    b kp_syscall_4_4_trace_dispatch
    .size kp_syscall_4_4_trace_entry, .-kp_syscall_4_4_trace_entry

    .global kp_syscall_4_4_exit
    .type kp_syscall_4_4_exit, %function
/*
 * Leave the C dispatcher stack and resume the original kernel entry path.
 * x0 = pt_regs at the original exception-entry SP
 * x1 = syscall return value
 * x2 = continuation address
 *
 * Do not rely on compiler sibling-call optimization here: the syscall return
 * path must restore SP to the pt_regs frame before entering ret_fast_syscall
 * or the trace continuation.
 */
kp_syscall_4_4_exit:
    mov sp, x0
    mov x0, x1
    br x2
    .size kp_syscall_4_4_exit, .-kp_syscall_4_4_exit
