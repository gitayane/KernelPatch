/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Linux 4.4 ARM64 syscall-dispatch entry veneers. */

    .text
    .align 2

/*
 * The original syscall entry keeps its pt_regs frame at SP. The dispatcher
 * never returns through the C ABI, so preserve the callee-saved registers
 * that a normal syscall handler would preserve for the entry assembly.
 *
 * Save x19-x29 in a 96-byte aligned frame below pt_regs. C receives the
 * original pt_regs pointer (SP + 96). The exit trampoline restores the saved
 * registers before putting SP back at pt_regs and continuing the kernel path.
 */
    .macro kp_syscall_4_4_save
    sub sp, sp, #96
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    str x29, [sp, #80]
    .endm

    .global kp_syscall_4_4_fast_entry
    .type kp_syscall_4_4_fast_entry, %function
kp_syscall_4_4_fast_entry:
    kp_syscall_4_4_save
    add x0, sp, #96
    ldr x1, [x0, #S_ORIG_X0]
    /* The syscall number is saved in pt_regs; do not trust x26 after C calls. */
    ldr x1, [x0, #S_SYSCALLNO]
    b kp_syscall_4_4_fast_dispatch
    .size kp_syscall_4_4_fast_entry, .-kp_syscall_4_4_fast_entry

    .global kp_syscall_4_4_trace_entry
    .type kp_syscall_4_4_trace_entry, %function
kp_syscall_4_4_trace_entry:
    kp_syscall_4_4_save
    add x0, sp, #96
    ldr x1, [x0, #S_SYSCALLNO]
    b kp_syscall_4_4_trace_dispatch
    .size kp_syscall_4_4_trace_entry, .-kp_syscall_4_4_trace_entry

    .global kp_syscall_4_4_exit
    .type kp_syscall_4_4_exit, %function
/*
 * x0 = original pt_regs pointer
 * x1 = syscall return value
 * x2 = continuation address
 */
kp_syscall_4_4_exit:
    sub x3, x0, #96
    ldp x19, x20, [x3, #0]
    ldp x21, x22, [x3, #16]
    ldp x23, x24, [x3, #32]
    ldp x25, x26, [x3, #48]
    ldp x27, x28, [x3, #64]
    ldr x29, [x3, #80]
    mov sp, x0
    mov x0, x1
    br x2
    .size kp_syscall_4_4_exit, .-kp_syscall_4_4_exit
