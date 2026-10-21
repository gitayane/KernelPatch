/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KernelPatch path-probe control/query helper for native ARM64 Termux.
 *
 * Build and run interactively:
 *   clang -Wall -Wextra -O2 tests/android/kp-path-probe-control.c -o kp-path-probe-control
 *   ./kp-path-probe-control query
 *
 * Operations: query | disable | enable
 * The SuperKey is read with terminal echo disabled; do not pass it in argv.
 *
 * Keep KP_VERSION_CODE in sync with the repository's version file when testing
 * a different KernelPatch version. This branch currently targets 0.13.9.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/syscall.h>

#define KP_SUPERCALL_NR 45L
#define KP_VERSION_CODE ((0U << 16) | (13U << 8) | 9U)
#define KP_SUPERCALL_MAGIC 0x1158UL
#define KP_CONTROL_FEATURE 0x1046UL
#define SUPERKEY_BUFFER_SIZE 128

static void wipe_secret(char *p, size_t n)
{
    volatile char *v = (volatile char *)p;
    while (n--) {
        *v++ = 0;
    }
}

static int read_superkey(char *key, size_t size)
{
    struct termios oldt;
    struct termios newt;

    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &oldt) != 0) {
        fprintf(stderr, "ERROR: run interactively so the SuperKey is not echoed.\n");
        return -1;
    }

    newt = oldt;
    newt.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) {
        fprintf(stderr, "ERROR: cannot disable terminal echo.\n");
        return -1;
    }

    fprintf(stderr, "KernelPatch SuperKey (input hidden): ");
    fflush(stderr);
    char *got = fgets(key, (int)size, stdin);

    /* Restore the terminal before handling any input/error path. */
    int restore_rc = tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
    fputc('\n', stderr);

    if (restore_rc != 0) {
        fprintf(stderr, "ERROR: could not restore terminal settings.\n");
        wipe_secret(key, size);
        return -1;
    }
    if (!got) {
        fprintf(stderr, "ERROR: no key was read.\n");
        wipe_secret(key, size);
        return -1;
    }

    key[strcspn(key, "\r\n")] = '\0';
    if (key[0] == '\0') {
        fprintf(stderr, "ERROR: empty key.\n");
        wipe_secret(key, size);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
#if !defined(__aarch64__) || !defined(__LP64__)
    fprintf(stderr, "ERROR: build this for native 64-bit ARM Termux.\n");
    return 2;
#endif

    if (argc != 2) {
        fprintf(stderr, "Usage: %s query|disable|enable|trace-query|trace-off|trace-on\\n", argv[0]);
        return 2;
    }

    int state;
    int trace_op = 0;
    const char *feature_name = "path_probe";
    if (!strcmp(argv[1], "query")) {
        state = -1;
    } else if (!strcmp(argv[1], "disable")) {
        state = 0;
    } else if (!strcmp(argv[1], "enable")) {
        state = 1;
    } else if (!strcmp(argv[1], "trace-query")) {
        state = -1;
        trace_op = 1;
        feature_name = "path_probe_trace";
    } else if (!strcmp(argv[1], "trace-off")) {
        state = 0;
        trace_op = 1;
        feature_name = "path_probe_trace";
    } else if (!strcmp(argv[1], "trace-on")) {
        state = 1;
        trace_op = 1;
        feature_name = "path_probe_trace";
    } else {
        fprintf(stderr, "Unknown operation: %s\\n", argv[1]);
        return 2;
    }

    char key[SUPERKEY_BUFFER_SIZE] = {0};
    if (read_superkey(key, sizeof(key)) != 0) {
        wipe_secret(key, sizeof(key));
        return 2;
    }

    const uint64_t version_cmd =
        ((uint64_t)KP_VERSION_CODE << 32) |
        ((uint64_t)KP_SUPERCALL_MAGIC << 16) |
        KP_CONTROL_FEATURE;

    errno = 0;
    long ret = syscall(KP_SUPERCALL_NR, key, (long)version_cmd,
                       feature_name, (long)state);
    int saved_errno = errno;
    wipe_secret(key, sizeof(key));

    if (ret == -1) {
        fprintf(stderr, "operation=%s syscall_error=%d (%s)\n",
                argv[1], saved_errno, strerror(saved_errno));
        return 1;
    }

    printf("operation=%s state=%d return=%ld\n", argv[1], state, ret);

    if (state == -1) {
        if (trace_op) {
            if (ret == 0) {
                puts("PATH_PROBE_TRACE_STATE=0 (disabled)");
            } else if (ret == 1) {
                puts("PATH_PROBE_TRACE_STATE=1 (enabled)");
            } else {
                puts("WARNING: unexpected trace query result");
                return 1;
            }
        } else if (ret == 0) {
            puts("PATH_PROBE_STATE=0 (no tracked hooks)");
        } else if (ret == 1) {
            puts("PATH_PROBE_STATE=1 (required shared hook coverage ready)");
        } else if (ret == 2) {
            puts("PATH_PROBE_STATE=2 (partial/degraded hooks; inspect dmesg)");
        } else {
            puts("WARNING: unexpected query result");
            return 1;
        }
    } else if (ret != 0) {
        fprintf(stderr, "ERROR: %s did not complete successfully (return=%ld).\n",
                argv[1], ret);
        return 1;
    }

    return 0;
}
