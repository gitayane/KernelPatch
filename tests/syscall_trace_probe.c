// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Targeted Linux 4.4 ARM64 syscall-trace regression probe.
 *
 * The parent uses PTRACE_SYSCALL so the child takes the slow/traced syscall
 * entry path. First issue the value observed in the XZP crash log (0xf0002),
 * then an unimplemented/out-of-range syscall. On ARM32 compat, 0xf0002 is the
 * ARM-private cacheflush syscall; zero-length arguments make that probe safe.
 *
 * This only invokes user-visible syscalls. It does not read or write kernel
 * text, load a module, or alter device configuration.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__arm__) && !defined(__aarch64__)
#define PROBE_ABI "arm32-compat"
#define UNIMPLEMENTED_NR 0x000f0006L
#else
#define PROBE_ABI "arm64-native"
#define UNIMPLEMENTED_NR 0x7fffffffL
#endif

#define OBSERVED_NR 0x000f0002L
#define MAX_SYSCALL_STOPS 100000UL
#define TIMEOUT_SECONDS 30U
#define EXPECTED_SIGNAL_HANDLERS 3

static volatile sig_atomic_t timeout_expired;
static volatile sig_atomic_t signal_handler_runs;

static void on_alarm(int signo)
{
    (void)signo;
    timeout_expired = 1;
}

static void on_usr1(int signo)
{
    if (signo == SIGUSR1)
        signal_handler_runs++;
}

static void child_probe(void)
{
    long pid_result;
    int pid_errno;
    long observed_result;
    int observed_errno;
    long unsupported_result;
    int unsupported_errno;
    int raised_signals = 0;
    int ok;
    struct sigaction sa = {0};

    sa.sa_handler = on_usr1;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, (struct sigaction *)0) == -1) {
        dprintf(STDERR_FILENO, "PROBE_ERROR sigaction errno=%d\n", errno);
        _exit(92);
    }

    if (ptrace(PTRACE_TRACEME, 0, (void *)0, (void *)0) == -1) {
        dprintf(STDERR_FILENO, "PROBE_ERROR PTRACE_TRACEME errno=%d\n", errno);
        _exit(90);
    }

    if (raise(SIGSTOP) != 0) {
        dprintf(STDERR_FILENO, "PROBE_ERROR SIGSTOP errno=%d\n", errno);
        _exit(91);
    }

    errno = 0;
    pid_result = syscall(SYS_getpid);
    pid_errno = errno;

    /*
     * Exercise signal delivery and the userspace signal-return trampoline while
     * ptrace continues to stop at syscall boundaries. Returning from each
     * handler enters the kernel's rt_sigreturn special-wrapper path.
     */
    for (int i = 0; i < EXPECTED_SIGNAL_HANDLERS; i++) {
        if (raise(SIGUSR1) != 0) {
            dprintf(STDERR_FILENO,
                    "PROBE_ERROR raise SIGUSR1 iteration=%d errno=%d\n",
                    i, errno);
            _exit(93);
        }
        raised_signals++;
    }

    /*
     * Keep all three arguments explicit and zero. On ARM32 compat this is the
     * zero-length __ARM_NR_compat_cacheflush probe; it cannot flush a non-empty
     * user range. On AArch64 this is simply an out-of-range syscall number.
     */
    errno = 0;
    observed_result = syscall(OBSERVED_NR, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL);
    observed_errno = errno;

    /*
     * For ARM32, 0xf0006 is in the ARM-private reserved range and should
     * return ENOSYS when not implemented. For AArch64, use a very large
     * number that is outside the native syscall table.
     */
    errno = 0;
    unsupported_result = syscall(UNIMPLEMENTED_NR, 0UL, 0UL, 0UL,
                                 0UL, 0UL, 0UL);
    unsupported_errno = errno;

    ok = (pid_result > 0 && pid_errno == 0) &&
         (unsupported_result == -1 && unsupported_errno == ENOSYS) &&
         (raised_signals == EXPECTED_SIGNAL_HANDLERS) &&
         (signal_handler_runs == EXPECTED_SIGNAL_HANDLERS);

#if defined(__arm__) && !defined(__aarch64__)
    /*
     * compat cacheflush is implemented on this kernel. With a zero address
     * and zero length, it may reject the invalid range with EFAULT; ENOSYS is
     * also acceptable on kernels that do not expose this private syscall.
     * The regression condition is that the traced call returns normally.
     */
    ok = ok && ((observed_result == 0 && observed_errno == 0) ||
                (observed_result == -1 &&
                 (observed_errno == EFAULT || observed_errno == ENOSYS)));
#else
    ok = ok && (observed_result == -1 && observed_errno == ENOSYS);
#endif

    dprintf(STDOUT_FILENO,
            "CHILD_RESULT abi=%s getpid=%ld errno=%d "
            "signals_raised=%d signal_handlers=%d "
            "observed_0xf0002=%ld errno=%d "
            "unimplemented_0x%lx=%ld errno=%d expected=%d\n",
            PROBE_ABI, pid_result, pid_errno, raised_signals,
            (int)signal_handler_runs, observed_result, observed_errno,
            (unsigned long)UNIMPLEMENTED_NR, unsupported_result,
            unsupported_errno, ok);
    _exit(ok ? 0 : 1);
}

int main(void)
{
    pid_t child;
    int status = 0;
    int options_set = 0;
    unsigned long syscall_stops = 0;
    unsigned long signal_delivery_stops = 0;
    int exit_code = 2;

    signal(SIGALRM, on_alarm);
    alarm(TIMEOUT_SECONDS);

    child = fork();
    if (child < 0) {
        dprintf(STDERR_FILENO, "PROBE_ERROR fork errno=%d\n", errno);
        return 2;
    }
    if (child == 0)
        child_probe();

    for (;;) {
        pid_t waited;

        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR && !timeout_expired);

        if (timeout_expired) {
            dprintf(STDERR_FILENO, "PROBE_FAIL timeout after %u seconds\n",
                    TIMEOUT_SECONDS);
            kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            exit_code = 124;
            break;
        }

        if (waited < 0) {
            dprintf(STDERR_FILENO, "PROBE_ERROR waitpid errno=%d\n", errno);
            kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            exit_code = 2;
            break;
        }

        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            break;
        }

        if (WIFSIGNALED(status)) {
            dprintf(STDERR_FILENO, "PROBE_FAIL child killed by signal=%d\n",
                    WTERMSIG(status));
            exit_code = 128 + WTERMSIG(status);
            break;
        }

        if (!WIFSTOPPED(status)) {
            dprintf(STDERR_FILENO, "PROBE_FAIL unexpected wait status=0x%x\n",
                    status);
            kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            exit_code = 2;
            break;
        }

        int signal_to_deliver = 0;
        {
            int sig = WSTOPSIG(status);

            if (!options_set) {
                if (sig != SIGSTOP) {
                    dprintf(STDERR_FILENO,
                            "PROBE_FAIL expected initial SIGSTOP, got=%d\n",
                            sig);
                    kill(child, SIGKILL);
                    (void)waitpid(child, &status, 0);
                    exit_code = 2;
                    break;
                }
                if (ptrace(PTRACE_SETOPTIONS, child, (void *)0,
                           (void *)(long)PTRACE_O_TRACESYSGOOD) == -1) {
                    dprintf(STDERR_FILENO,
                            "PROBE_ERROR PTRACE_SETOPTIONS errno=%d\n", errno);
                    kill(child, SIGKILL);
                    (void)waitpid(child, &status, 0);
                    exit_code = 2;
                    break;
                }
                options_set = 1;
            } else if (sig == (SIGTRAP | 0x80)) {
                syscall_stops++;
                if (syscall_stops > MAX_SYSCALL_STOPS) {
                    dprintf(STDERR_FILENO,
                            "PROBE_FAIL exceeded syscall-stop limit\n");
                    kill(child, SIGKILL);
                    (void)waitpid(child, &status, 0);
                    exit_code = 2;
                    break;
                }
            } else if (sig == SIGUSR1) {
                /*
                 * Forward the signal at the ptrace delivery stop so the
                 * handler runs and returns through rt_sigreturn.
                 */
                signal_to_deliver = sig;
                signal_delivery_stops++;
            } else {
                dprintf(STDERR_FILENO,
                        "PROBE_FAIL unexpected child stop signal=%d\n", sig);
                kill(child, SIGKILL);
                (void)waitpid(child, &status, 0);
                exit_code = 2;
                break;
            }
        }

        if (ptrace(PTRACE_SYSCALL, child, (void *)0,
                   (void *)(long)signal_to_deliver) == -1) {
            dprintf(STDERR_FILENO, "PROBE_ERROR PTRACE_SYSCALL errno=%d\n",
                    errno);
            kill(child, SIGKILL);
            (void)waitpid(child, &status, 0);
            exit_code = 2;
            break;
        }
    }

    alarm(0);
    if (exit_code == 0 && syscall_stops >= 6 &&
        signal_delivery_stops == EXPECTED_SIGNAL_HANDLERS) {
        dprintf(STDOUT_FILENO,
                "PROBE_PASS abi=%s ptrace_syscall_stops=%lu "
                "signal_delivery_stops=%lu child_exit=0\n",
                PROBE_ABI, syscall_stops, signal_delivery_stops);
        return 0;
    }

    dprintf(STDERR_FILENO,
            "PROBE_FAIL abi=%s ptrace_syscall_stops=%lu "
            "signal_delivery_stops=%lu child_exit=%d\n",
            PROBE_ABI, syscall_stops, signal_delivery_stops, exit_code);
    return exit_code == 0 ? 2 : exit_code;
}
