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
#include <string.h>
#include <pthread.h>
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
#define PROBE_EXEC_PATH "/data/local/tmp/syscall_trace_probe_arm32"
#else
#define PROBE_ABI "arm64-native"
#define UNIMPLEMENTED_NR 0x7fffffffL
#define PROBE_EXEC_PATH "/data/local/tmp/syscall_trace_probe_arm64"
#endif

#define OBSERVED_NR 0x000f0002L
#define MAX_SYSCALL_STOPS 100000UL
#define TIMEOUT_SECONDS 30U
#define EXPECTED_SIGNAL_HANDLERS 3
#define EXPECTED_SIGNAL_DELIVERY_STOPS (EXPECTED_SIGNAL_HANDLERS + 2)
#define PARALLEL_THREADS 4
#define PARALLEL_ITERATIONS 24
#define PARALLEL_TRACE_CHILDREN 3
#define PARALLEL_TRACE_ITERATIONS 12
#define PARALLEL_TRACE_MIN_STOPS 100UL
#define PARALLEL_TRACE_SIGNALS 2

static volatile sig_atomic_t timeout_expired;
static volatile sig_atomic_t signal_handler_runs;
static volatile sig_atomic_t traced_signal_handler_runs;

struct restart_state {
    volatile sig_atomic_t stage;
};

struct parallel_worker {
    int index;
    int completed;
    int failed;
};

struct parallel_result {
    int ok;
    int threads_started;
    int threads_joined;
    int iterations_completed;
    int failures;
};

struct traced_child_state {
    pid_t pid;
    int index;
    int options_set;
    int done;
    int exit_code;
    int interrupt_signal_sent;
    int restart_signal_sent;
    int restart_byte_written;
    int exec_events;
    unsigned long syscall_stops;
    unsigned long signal_delivery_stops;
};

struct traced_child_stage {
    volatile sig_atomic_t stage;
    volatile sig_atomic_t interrupt_read_ok;
    volatile sig_atomic_t restart_read_ok;
};

struct traced_parallel_result {
    int ok;
    int children_started;
    int children_completed;
    int failures;
    int interrupt_reads_ok;
    int restart_reads_ok;
    int exec_events;
    unsigned long syscall_stops;
    unsigned long signal_delivery_stops;
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

/*
 * Run independent syscall workloads concurrently in worker threads while the
 * process leader remains under PTRACE_SYSCALL. The workers are intentionally
 * not individually ptrace-attached: this exercises normal entry dispatch
 * under task concurrency, while the leader continues to exercise the traced
 * slow path. Any worker-local error makes the aggregate check fail.
 */
static void *parallel_worker_main(void *opaque)
{
    struct parallel_worker *worker = (struct parallel_worker *)opaque;
    static const char payload = 'T';
    const size_t page_size = 4096;
    int i;

    for (i = 0; i < PARALLEL_ITERATIONS; i++) {
        int fd = -1;
        void *mapping = MAP_FAILED;
        volatile uint32_t *word;
        uint32_t value = 0x51000000u |
                         ((uint32_t)(worker->index + 1) << 8) |
                         (uint32_t)(i + 1);

        if (syscall(SYS_gettid) <= 0 || syscall(SYS_getpid) != getpid()) {
            worker->failed = 1;
            break;
        }

        fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            worker->failed = 1;
            break;
        }
        if (write(fd, &payload, 1) != 1) worker->failed = 1;
        {
            char byte = 0;
            if (read(fd, &byte, 1) != 0) worker->failed = 1;
        }
        if (close(fd) != 0) worker->failed = 1;
        if (worker->failed) break;

        mapping = mmap((void *)0, page_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            worker->failed = 1;
            break;
        }
        word = (volatile uint32_t *)mapping;
        *word = value;
        if (mprotect(mapping, page_size, PROT_READ) != 0 ||
            *word != value) {
            worker->failed = 1;
        }
        if (mprotect(mapping, page_size, PROT_READ | PROT_WRITE) != 0) {
            worker->failed = 1;
        } else {
            *word = ~value;
            if (*word != ~value) worker->failed = 1;
        }
        if (munmap(mapping, page_size) != 0) worker->failed = 1;
        if (worker->failed) break;

        worker->completed++;
    }

    return (void *)0;
}

static int exercise_parallel(struct parallel_result *out)
{
    pthread_t threads[PARALLEL_THREADS];
    struct parallel_worker workers[PARALLEL_THREADS] = {{0}};
    int i;
    int create_failed = 0;

    for (i = 0; i < PARALLEL_THREADS; i++) {
        workers[i].index = i;
        if (pthread_create(&threads[i], (const pthread_attr_t *)0,
                           parallel_worker_main, &workers[i]) != 0) {
            create_failed = 1;
            break;
        }
        out->threads_started++;
    }

    for (i = 0; i < out->threads_started; i++) {
        if (pthread_join(threads[i], (void **)0) == 0) {
            out->threads_joined++;
        } else {
            create_failed = 1;
        }
        out->iterations_completed += workers[i].completed;
        if (workers[i].failed) out->failures++;
    }

    out->ok = !create_failed &&
              out->threads_started == PARALLEL_THREADS &&
              out->threads_joined == PARALLEL_THREADS &&
              out->iterations_completed ==
                  PARALLEL_THREADS * PARALLEL_ITERATIONS &&
              out->failures == 0;
    return out->ok;
}

/*
 * Unlike the pthread stress above, each worker process explicitly uses
 * PTRACE_TRACEME and is resumed with PTRACE_SYSCALL. The parent services
 * several tracees with waitpid(__WALL), interleaving their syscall stops.
 */
static void on_traced_usr1(int signo)
{
    if (signo == SIGUSR1)
        traced_signal_handler_runs++;
}

static int traced_exec_child_main(void)
{
    static const char payload = 'E';
    const size_t page_size = 4096;
    long pid = syscall(SYS_getpid);
    long tid = syscall(SYS_gettid);
    int fd;
    char byte = 0;
    void *mapping;
    volatile uint32_t *word;

    if (pid <= 0 || tid <= 0)
        return 121;
    fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return 122;
    if (write(fd, &payload, 1) != 1 ||
        read(fd, &byte, 1) != 0 || close(fd) != 0)
        return 123;

    mapping = mmap((void *)0, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 124;
    word = (volatile uint32_t *)mapping;
    *word = 0x45584543u;
    if (mprotect(mapping, page_size, PROT_READ) != 0 ||
        *word != 0x45584543u) {
        (void)munmap(mapping, page_size);
        return 125;
    }
    if (munmap(mapping, page_size) != 0)
        return 126;

    dprintf(STDOUT_FILENO,
            "TRACED_EXEC_CHILD_PASS abi=%s getpid=%ld gettid=%ld file_ops=1 memory=1\n",
            PROBE_ABI, pid, tid);
    return 0;
}

static void traced_worker_child(int restart_read_fd,
                                  struct traced_child_stage *stage)
{
    static const char payload = 'P';
    const size_t page_size = 4096;
    struct sigaction sa = {0};
    long interrupt_result;
    int interrupt_errno;
    long restart_result;
    int restart_errno;
    char interrupt_byte = 0;
    char restart_byte = 0;
    int i;

    sa.sa_handler = on_traced_usr1;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, (struct sigaction *)0) == -1)
        _exit(100);

    if (ptrace(PTRACE_TRACEME, 0, (void *)0, (void *)0) == -1)
        _exit(101);
    if (raise(SIGSTOP) != 0)
        _exit(102);

    for (i = 0; i < PARALLEL_TRACE_SIGNALS; i++) {
        if (raise(SIGUSR1) != 0)
            _exit(110);
    }
    if (traced_signal_handler_runs != PARALLEL_TRACE_SIGNALS)
        _exit(111);

    /* Without SA_RESTART, a traced signal must interrupt the blocked read. */
    stage->stage = 1;
    errno = 0;
    interrupt_result = (long)read(restart_read_fd, &interrupt_byte, 1);
    interrupt_errno = errno;
    stage->interrupt_read_ok =
        (interrupt_result == -1 && interrupt_errno == EINTR);
    stage->stage = 2;

    /* With SA_RESTART, the second blocked read must resume after the handler. */
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGUSR1, &sa, (struct sigaction *)0) == -1)
        _exit(112);
    stage->stage = 3;
    errno = 0;
    restart_result = (long)read(restart_read_fd, &restart_byte, 1);
    restart_errno = errno;
    stage->restart_read_ok =
        (restart_result == 1 && restart_errno == 0 && restart_byte == 'R');
    stage->stage = 4;
    if (close(restart_read_fd) != 0)
        _exit(113);
    if (!stage->interrupt_read_ok || !stage->restart_read_ok)
        _exit(114);
    if (traced_signal_handler_runs != PARALLEL_TRACE_SIGNALS + 2)
        _exit(115);

    for (i = 0; i < PARALLEL_TRACE_ITERATIONS; i++) {
        long tid = syscall(SYS_gettid);
        long pid = syscall(SYS_getpid);
        int fd;
        char byte = 0;
        void *mapping;
        volatile uint32_t *word;
        uint32_t value = 0x63000000u | (uint32_t)(i + 1);

        if (tid <= 0 || pid <= 0)
            _exit(103);

        fd = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            _exit(104);
        if (write(fd, &payload, 1) != 1 ||
            read(fd, &byte, 1) != 0 || close(fd) != 0)
            _exit(105);

        mapping = mmap((void *)0, page_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED)
            _exit(106);
        word = (volatile uint32_t *)mapping;
        *word = value;
        if (mprotect(mapping, page_size, PROT_READ) != 0 ||
            *word != value) {
            (void)munmap(mapping, page_size);
            _exit(107);
        }
        if (mprotect(mapping, page_size, PROT_READ | PROT_WRITE) != 0) {
            (void)munmap(mapping, page_size);
            _exit(108);
        }
        *word = ~value;
        if (*word != ~value || munmap(mapping, page_size) != 0)
            _exit(109);
    }

    {
        char *const exec_argv[] = {
            (char *)"syscall_trace_probe", (char *)"--trace-exec-child",
            (char *)0
        };
        char *const exec_envp[] = {
            (char *)"PATH=/system/bin", (char *)0
        };
        execve(PROBE_EXEC_PATH, exec_argv, exec_envp);
        _exit(116);
    }
}

static int exercise_parallel_traced_children(
    struct traced_parallel_result *out)
{
    struct traced_child_state children[PARALLEL_TRACE_CHILDREN] = {{0}};
    int restart_pipes[PARALLEL_TRACE_CHILDREN][2];
    struct traced_child_stage *stages;
    int i;
    int j;

    for (i = 0; i < PARALLEL_TRACE_CHILDREN; i++) {
        restart_pipes[i][0] = -1;
        restart_pipes[i][1] = -1;
    }
    stages = mmap((void *)0,
                  sizeof(*stages) * PARALLEL_TRACE_CHILDREN,
                  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (stages == MAP_FAILED) {
        out->failures++;
        return 0;
    }
    for (i = 0; i < PARALLEL_TRACE_CHILDREN; i++) {
        if (pipe(restart_pipes[i]) == -1) {
            out->failures++;
            goto cleanup;
        }
    }

    for (i = 0; i < PARALLEL_TRACE_CHILDREN; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            for (j = 0; j < PARALLEL_TRACE_CHILDREN; j++) {
                if (j != i && restart_pipes[j][0] >= 0)
                    close(restart_pipes[j][0]);
                if (restart_pipes[j][1] >= 0)
                    close(restart_pipes[j][1]);
            }
            traced_worker_child(restart_pipes[i][0], &stages[i]);
        }
        if (pid < 0) {
            out->failures++;
            break;
        }
        children[i].pid = pid;
        children[i].index = i;
        out->children_started++;
    }
    for (i = 0; i < PARALLEL_TRACE_CHILDREN; i++) {
        if (restart_pipes[i][0] >= 0) {
            close(restart_pipes[i][0]);
            restart_pipes[i][0] = -1;
        }
    }

    while (out->children_completed < out->children_started) {
        int status = 0;
        pid_t waited;

        do {
            waited = waitpid(-1, &status, __WALL);
        } while (waited < 0 && errno == EINTR && !timeout_expired);

        if (timeout_expired || waited < 0) {
            out->failures++;
            for (i = 0; i < out->children_started; i++) {
                if (!children[i].done) {
                    (void)kill(children[i].pid, SIGKILL);
                    (void)ptrace(PTRACE_CONT, children[i].pid, (void *)0,
                                 (void *)(long)SIGKILL);
                }
            }
            for (i = 0; i < out->children_started; i++) {
                if (!children[i].done) {
                    do {
                        waited = waitpid(children[i].pid, &status, __WALL);
                    } while (waited < 0 && errno == EINTR);
                    if (waited == children[i].pid) {
                        children[i].done = 1;
                        out->children_completed++;
                    }
                }
            }
            break;
        }

        {
            struct traced_child_state *state = (struct traced_child_state *)0;
            int sig;
            int resume_signal = 0;
            int trigger_read_signal = 0;
            int trigger_read_stage = 0;
            for (i = 0; i < out->children_started; i++) {
                if (children[i].pid == waited) {
                    state = &children[i];
                    break;
                }
            }
            if (state == (struct traced_child_state *)0) {
                out->failures++;
                continue;
            }

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                state->done = 1;
                out->children_completed++;
                state->exit_code = WIFEXITED(status) ?
                                   WEXITSTATUS(status) :
                                   128 + WTERMSIG(status);
                if (state->exit_code != 0 ||
                    state->syscall_stops < PARALLEL_TRACE_MIN_STOPS ||
                    state->signal_delivery_stops != PARALLEL_TRACE_SIGNALS + 2 ||
                    state->exec_events != 1 ||
                    stages[state->index].stage != 4 ||
                    !stages[state->index].interrupt_read_ok ||
                    !stages[state->index].restart_read_ok)
                    out->failures++;
                if (stages[state->index].interrupt_read_ok)
                    out->interrupt_reads_ok++;
                if (stages[state->index].restart_read_ok)
                    out->restart_reads_ok++;
                if (state->exec_events == 1)
                    out->exec_events++;
                if (restart_pipes[state->index][1] >= 0) {
                    close(restart_pipes[state->index][1]);
                    restart_pipes[state->index][1] = -1;
                }
                continue;
            }

            if (!WIFSTOPPED(status)) {
                out->failures++;
                (void)kill(state->pid, SIGKILL);
                (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                             (void *)(long)SIGKILL);
                continue;
            }

            sig = WSTOPSIG(status);
            if (!state->options_set) {
                if (sig != SIGSTOP ||
                    ptrace(PTRACE_SETOPTIONS, state->pid, (void *)0,
                           (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC)) == -1) {
                    out->failures++;
                    (void)kill(state->pid, SIGKILL);
                    (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                                 (void *)(long)SIGKILL);
                    continue;
                }
                state->options_set = 1;
            } else if (sig == SIGTRAP &&
                       ((unsigned int)status >> 16) == PTRACE_EVENT_EXEC) {
                state->exec_events++;
            } else if (sig == (SIGTRAP | 0x80)) {
                state->syscall_stops++;
                out->syscall_stops++;
                if (stages[state->index].stage == 1 &&
                    !state->interrupt_signal_sent) {
                    trigger_read_signal = 1;
                    trigger_read_stage = 1;
                } else if (stages[state->index].stage == 3 &&
                           !state->restart_signal_sent) {
                    trigger_read_signal = 1;
                    trigger_read_stage = 3;
                }
                if (out->syscall_stops > MAX_SYSCALL_STOPS) {
                    out->failures++;
                    (void)kill(state->pid, SIGKILL);
                    (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                                 (void *)(long)SIGKILL);
                    continue;
                }
            } else if (sig == SIGUSR1) {
                state->signal_delivery_stops++;
                out->signal_delivery_stops++;
                resume_signal = SIGUSR1;
                if (stages[state->index].stage == 3 &&
                    !state->restart_byte_written) {
                    ssize_t written;
                    do {
                        written = write(restart_pipes[state->index][1], "R", 1);
                    } while (written == -1 && errno == EINTR);
                    if (written != 1) {
                        out->failures++;
                        (void)kill(state->pid, SIGKILL);
                        (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                                     (void *)(long)SIGKILL);
                        continue;
                    }
                    state->restart_byte_written = 1;
                    close(restart_pipes[state->index][1]);
                    restart_pipes[state->index][1] = -1;
                }
            } else {
                out->failures++;
                (void)kill(state->pid, SIGKILL);
                (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                             (void *)(long)SIGKILL);
                continue;
            }

            if (ptrace(PTRACE_SYSCALL, state->pid, (void *)0,
                       (void *)(long)resume_signal) == -1) {
                out->failures++;
                (void)kill(state->pid, SIGKILL);
                (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                             (void *)(long)SIGKILL);
            } else if (trigger_read_signal) {
                usleep(50000);
                if (kill(state->pid, SIGUSR1) == -1) {
                    out->failures++;
                    (void)kill(state->pid, SIGKILL);
                    (void)ptrace(PTRACE_CONT, state->pid, (void *)0,
                                 (void *)(long)SIGKILL);
                } else if (trigger_read_stage == 1) {
                    state->interrupt_signal_sent = 1;
                } else if (trigger_read_stage == 3) {
                    state->restart_signal_sent = 1;
                }
            }
        }
    }

    out->ok = out->children_started == PARALLEL_TRACE_CHILDREN &&
              out->children_completed == PARALLEL_TRACE_CHILDREN &&
              out->interrupt_reads_ok == PARALLEL_TRACE_CHILDREN &&
              out->restart_reads_ok == PARALLEL_TRACE_CHILDREN &&
              out->exec_events == PARALLEL_TRACE_CHILDREN &&
              out->signal_delivery_stops ==
                  PARALLEL_TRACE_CHILDREN * (PARALLEL_TRACE_SIGNALS + 2) &&
              out->failures == 0;
cleanup:
    for (i = 0; i < PARALLEL_TRACE_CHILDREN; i++) {
        if (restart_pipes[i][0] >= 0)
            close(restart_pipes[i][0]);
        if (restart_pipes[i][1] >= 0)
            close(restart_pipes[i][1]);
    }
    munmap(stages, sizeof(*stages) * PARALLEL_TRACE_CHILDREN);
    return out->ok;
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
    int parallel_ok;
    struct passthrough_result passthrough = {0};
    struct parallel_result parallel = {0};
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
    parallel_ok = exercise_parallel(&parallel);

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
         passthrough_ok && parallel_ok && interrupted_read_ok && restart_read_ok &&
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
            "passthrough_ok=%d parallel_ok=%d parallel_threads=%d/%d "
            "parallel_iterations=%d/%d parallel_failures=%d "
            "open=%ld/%d write=%ld/%d read=%ld/%d "
            "close=%ld/%d mmap=%d/%d mprotect_ro=%d/%d "
            "mprotect_rw=%d/%d memory=%d munmap=%d/%d "
            "signals_raised=%d signal_handlers=%d "
            "interrupt_read_ok=%d interrupt_read=%ld/%d interrupt_byte=%u "
            "restart_read_ok=%d restart_read=%ld/%d restart_byte=%u "
            "observed_0xf0002=%ld errno=%d "
            "unimplemented_0x%lx=%ld errno=%d expected=%d\n",
            PROBE_ABI, pid_result, pid_errno, passthrough_ok,
            parallel_ok, parallel.threads_joined, parallel.threads_started,
            parallel.iterations_completed,
            PARALLEL_THREADS * PARALLEL_ITERATIONS, parallel.failures,
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

int main(int argc, char **argv)
{
    pid_t child;
    if (argc == 2 && strcmp(argv[1], "--trace-exec-child") == 0)
        return traced_exec_child_main();
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
    struct traced_parallel_result traced_parallel = {0};
    int traced_parallel_ok = 0;

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
                           (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC)) == -1) {
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

    if (exit_code == 0 && !timeout_expired)
        traced_parallel_ok = exercise_parallel_traced_children(&traced_parallel);

    alarm(0);
    if (exit_code == 0 && syscall_stops >= 6 &&
        signal_delivery_stops == EXPECTED_SIGNAL_DELIVERY_STOPS &&
        interrupted_signal_sent && restart_signal_sent &&
        restart_byte_written && restart->stage == 4 && traced_parallel_ok) {
        dprintf(STDOUT_FILENO,
                "PROBE_PASS abi=%s ptrace_syscall_stops=%lu "
                "signal_delivery_stops=%lu child_exit=0 "
                "multi_trace_children=%d/%d multi_trace_syscall_stops=%lu "
                "multi_trace_exec_events=%d/%d "
                "multi_trace_signal_stops=%lu multi_trace_interrupt_reads=%d/%d "
                "multi_trace_restart_reads=%d/%d multi_trace_failures=%d\n",
                PROBE_ABI, syscall_stops, signal_delivery_stops,
                traced_parallel.children_completed,
                traced_parallel.children_started,
                traced_parallel.syscall_stops,
                traced_parallel.exec_events, PARALLEL_TRACE_CHILDREN,
                traced_parallel.signal_delivery_stops,
                traced_parallel.interrupt_reads_ok, PARALLEL_TRACE_CHILDREN,
                traced_parallel.restart_reads_ok, PARALLEL_TRACE_CHILDREN,
                traced_parallel.failures);
        return 0;
    }

    if (restart_pipe[0] >= 0) close(restart_pipe[0]);
    if (restart_pipe[1] >= 0) close(restart_pipe[1]);
    if (restart != MAP_FAILED) munmap(restart, sizeof(*restart));

    dprintf(STDERR_FILENO,
            "PROBE_FAIL abi=%s ptrace_syscall_stops=%lu "
            "signal_delivery_stops=%lu child_exit=%d "
            "multi_trace_children=%d/%d multi_trace_syscall_stops=%lu "
            "multi_trace_exec_events=%d/%d "
            "multi_trace_signal_stops=%lu multi_trace_interrupt_reads=%d/%d "
                "multi_trace_restart_reads=%d/%d multi_trace_failures=%d\n",
            PROBE_ABI, syscall_stops, signal_delivery_stops, exit_code,
            traced_parallel.children_completed, traced_parallel.children_started,
            traced_parallel.syscall_stops,
            traced_parallel.exec_events, PARALLEL_TRACE_CHILDREN,
            traced_parallel.signal_delivery_stops,
            traced_parallel.interrupt_reads_ok, PARALLEL_TRACE_CHILDREN,
            traced_parallel.restart_reads_ok, PARALLEL_TRACE_CHILDREN,
            traced_parallel.failures);
    return exit_code == 0 ? 2 : exit_code;
}
