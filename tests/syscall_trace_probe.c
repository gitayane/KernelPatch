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
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
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
#define EXPECTED_SIGNAL_DELIVERY_STOPS (EXPECTED_SIGNAL_HANDLERS + 2)

static volatile sig_atomic_t timeout_expired;
static volatile sig_atomic_t signal_handler_runs;

struct restart_state {
    volatile sig_atomic_t stage;
};

struct passthrough_result {
    long open_result;
    int open_errno;
    long write_result;
    int write_errno;
    long read_result;
    int read_errno;
    long close_result;
    int close_errno;
    int mmap_ok;
    int mmap_errno;
    int mprotect_ro_result;
    int mprotect_ro_errno;
    int mprotect_rw_result;
    int mprotect_rw_errno;
    int memory_ok;
    int munmap_result;
    int munmap_errno;
};

/*
 * Exercise representative ordinary syscalls while ptrace forces the traced
 * entry path: file descriptor operations plus mmap/mprotect/munmap. These hit
 * multiple argument registers and check that unhooked calls preserve the
 * original syscall ABI and return values through the dispatcher pass-through.
 */
static int exercise_passthrough(struct passthrough_result *out)
{
    static const char payload = 'K';
    char received = 0;
    int fd;
    void *mapping;
    volatile uint32_t *word;
    const size_t page_size = 4096;
    const uint32_t first_value = 0x13579bdfu;
    const uint32_t second_value = 0x2468ace0u;
    int ok = 1;

    errno = 0;
    fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    out->open_result = fd;
    out->open_errno = errno;
    if (fd < 0) return 0;

    errno = 0;
    out->write_result = write(fd, &payload, 1);
    out->write_errno = errno;
    if (out->write_result != 1) ok = 0;

    errno = 0;
    out->read_result = read(fd, &received, 1);
    out->read_errno = errno;
    if (out->read_result != 0) ok = 0;

    errno = 0;
    out->close_result = close(fd);
    out->close_errno = errno;
    if (out->close_result != 0) ok = 0;

    errno = 0;
    mapping = mmap((void *)0, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    out->mmap_errno = errno;
    if (mapping == MAP_FAILED) {
        out->mmap_ok = 0;
        return 0;
    }
    out->mmap_ok = 1;

    word = (volatile uint32_t *)mapping;
    *word = first_value;

    errno = 0;
    out->mprotect_ro_result = mprotect(mapping, page_size, PROT_READ);
    out->mprotect_ro_errno = errno;
    if (out->mprotect_ro_result != 0) {
        ok = 0;
    } else if (*word != first_value) {
        ok = 0;
    }

    errno = 0;
    out->mprotect_rw_result =
        mprotect(mapping, page_size, PROT_READ | PROT_WRITE);
    out->mprotect_rw_errno = errno;
    if (out->mprotect_rw_result != 0) {
        ok = 0;
    } else {
        *word = second_value;
        if (*word != second_value) ok = 0;
    }
    out->memory_ok = (*word == second_value);

    errno = 0;
    out->munmap_result = munmap(mapping, page_size);
    out->munmap_errno = errno;
    if (out->munmap_result != 0) ok = 0;

    return ok && out->memory_ok;
}

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

static void child_probe(int restart_read_fd, struct restart_state *restart)
{
    long pid_result;
    int pid_errno;
    long observed_result;
    int observed_errno;
    long unsupported_result;
    int unsupported_errno;
    int raised_signals = 0;
    int passthrough_ok;
    struct passthrough_result passthrough = {0};
    int ok;
    long interrupted_read_result;
    int interrupted_read_errno;
    int interrupted_read_ok;
    long restart_read_result;
    int restart_read_errno;
    int restart_read_ok;
    char interrupted_byte = 0;
    char restart_byte = 0;
    struct sigaction sa = {0};

    sa.sa_handler = on_usr1;
    sa.sa_flags = 0;
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

    passthrough_ok = exercise_passthrough(&passthrough);

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
     * First check the non-restarting case. The tracer interrupts this blocked
     * read with SIGUSR1 while the handler has no SA_RESTART flag. The expected
     * result is -1/EINTR; the tracer must not write data for this first read.
     */
    restart->stage = 1;
    errno = 0;
    interrupted_read_result = (long)read(restart_read_fd, &interrupted_byte, 1);
    interrupted_read_errno = errno;
    restart->stage = 2;
    interrupted_read_ok = (interrupted_read_result == -1 &&
                           interrupted_read_errno == EINTR);

    /* Now repeat with SA_RESTART; the tracer supplies one byte after delivery. */
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, (struct sigaction *)0) == -1) {
        dprintf(STDERR_FILENO,
                "PROBE_ERROR enable SA_RESTART errno=%d\n", errno);
        _exit(94);
    }
    restart->stage = 3;
    errno = 0;
    restart_read_result = (long)read(restart_read_fd, &restart_byte, 1);
    restart_read_errno = errno;
    restart->stage = 4;
    restart_read_ok = (restart_read_result == 1 && restart_read_errno == 0 &&
                       restart_byte == 'R');

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
         passthrough_ok && interrupted_read_ok && restart_read_ok &&
         (raised_signals == EXPECTED_SIGNAL_HANDLERS) &&
         (signal_handler_runs == EXPECTED_SIGNAL_DELIVERY_STOPS);

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
            "passthrough_ok=%d open=%ld/%d write=%ld/%d read=%ld/%d "
            "close=%ld/%d mmap=%d/%d mprotect_ro=%d/%d "
            "mprotect_rw=%d/%d memory=%d munmap=%d/%d "
            "signals_raised=%d signal_handlers=%d "
            "interrupt_read_ok=%d interrupt_read=%ld/%d interrupt_byte=%u "
            "restart_read_ok=%d restart_read=%ld/%d restart_byte=%u "
            "observed_0xf0002=%ld errno=%d "
            "unimplemented_0x%lx=%ld errno=%d expected=%d\n",
            PROBE_ABI, pid_result, pid_errno, passthrough_ok,
            passthrough.open_result, passthrough.open_errno,
            passthrough.write_result, passthrough.write_errno,
            passthrough.read_result, passthrough.read_errno,
            passthrough.close_result, passthrough.close_errno,
            passthrough.mmap_ok, passthrough.mmap_errno,
            passthrough.mprotect_ro_result, passthrough.mprotect_ro_errno,
            passthrough.mprotect_rw_result, passthrough.mprotect_rw_errno,
            passthrough.memory_ok, passthrough.munmap_result,
            passthrough.munmap_errno, raised_signals,
            (int)signal_handler_runs, interrupted_read_ok,
            interrupted_read_result, interrupted_read_errno,
            (unsigned int)(unsigned char)interrupted_byte,
            restart_read_ok, restart_read_result, restart_read_errno,
            (unsigned int)(unsigned char)restart_byte,
            observed_result, observed_errno,
            (unsigned long)UNIMPLEMENTED_NR, unsupported_result,
            unsupported_errno, ok);
    _exit(ok ? 0 : 1);
}

int main(void)
{
    pid_t child;
    int restart_pipe[2] = {-1, -1};
    struct restart_state *restart = MAP_FAILED;
    int interrupted_signal_sent = 0;
    int restart_signal_sent = 0;
    int restart_byte_written = 0;
    int status = 0;
    int options_set = 0;
    unsigned long syscall_stops = 0;
    unsigned long signal_delivery_stops = 0;
    int exit_code = 2;

    signal(SIGALRM, on_alarm);

    if (pipe(restart_pipe) == -1) {
        dprintf(STDERR_FILENO, "PROBE_ERROR pipe errno=%d\n", errno);
        return 2;
    }
    restart = mmap((void *)0, sizeof(*restart), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (restart == MAP_FAILED) {
        dprintf(STDERR_FILENO, "PROBE_ERROR shared mmap errno=%d\n", errno);
        close(restart_pipe[0]);
        close(restart_pipe[1]);
        return 2;
    }
    restart->stage = 0;
    alarm(TIMEOUT_SECONDS);

    child = fork();
    if (child < 0) {
        dprintf(STDERR_FILENO, "PROBE_ERROR fork errno=%d\n", errno);
        return 2;
    }
    if (child == 0) {
        close(restart_pipe[1]);
        child_probe(restart_pipe[0], restart);
    }
    close(restart_pipe[0]);
    restart_pipe[0] = -1;

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
        int trigger_read_signal = 0;
        int trigger_read_stage = 0;
        int deliver_restart_data = 0;
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
                if (restart->stage == 1 && !interrupted_signal_sent) {
                    trigger_read_signal = 1;
                    trigger_read_stage = 1;
                } else if (restart->stage == 3 && !restart_signal_sent) {
                    trigger_read_signal = 1;
                    trigger_read_stage = 3;
                }
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
                if (restart->stage == 3 && restart_signal_sent &&
                    !restart_byte_written)
                    deliver_restart_data = 1;
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

        if (trigger_read_signal) {
            /* Give the child time to enter and block in read(2). */
            usleep(50000);
            if (kill(child, SIGUSR1) == -1) {
                dprintf(STDERR_FILENO,
                        "PROBE_ERROR kill SIGUSR1 errno=%d\n", errno);
                kill(child, SIGKILL);
                (void)waitpid(child, &status, 0);
                exit_code = 2;
                break;
            }
            if (trigger_read_stage == 1)
                interrupted_signal_sent = 1;
            else if (trigger_read_stage == 3)
                restart_signal_sent = 1;
        }

        if (deliver_restart_data) {
            ssize_t written;
            do {
                written = write(restart_pipe[1], "R", 1);
            } while (written == -1 && errno == EINTR);
            if (written != 1) {
                dprintf(STDERR_FILENO,
                        "PROBE_ERROR write restart byte result=%ld errno=%d\n",
                        (long)written, errno);
                kill(child, SIGKILL);
                (void)waitpid(child, &status, 0);
                exit_code = 2;
                break;
            }
            restart_byte_written = 1;
            close(restart_pipe[1]);
            restart_pipe[1] = -1;
        }
    }

    alarm(0);
    if (exit_code == 0 && syscall_stops >= 6 &&
        signal_delivery_stops == EXPECTED_SIGNAL_DELIVERY_STOPS &&
        interrupted_signal_sent && restart_signal_sent &&
        restart_byte_written && restart->stage == 4) {
        dprintf(STDOUT_FILENO,
                "PROBE_PASS abi=%s ptrace_syscall_stops=%lu "
                "signal_delivery_stops=%lu child_exit=0\n",
                PROBE_ABI, syscall_stops, signal_delivery_stops);
        return 0;
    }

    if (restart_pipe[0] >= 0) close(restart_pipe[0]);
    if (restart_pipe[1] >= 0) close(restart_pipe[1]);
    if (restart != MAP_FAILED) munmap(restart, sizeof(*restart));

    dprintf(STDERR_FILENO,
            "PROBE_FAIL abi=%s ptrace_syscall_stops=%lu "
            "signal_delivery_stops=%lu child_exit=%d\n",
            PROBE_ABI, syscall_stops, signal_delivery_stops, exit_code);
    return exit_code == 0 ? 2 : exit_code;
}
