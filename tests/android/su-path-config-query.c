/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Query KernelPatch's current SU path without changing hook state.
 * Build and run interactively in native ARM64 Termux:
 *   clang -Wall -Wextra -O2 su-path-config-query.c -o su-path-config-query
 *   ./su-path-config-query
 *
 * Never pass the SuperKey in argv or print/store it. This is a control-plane
 * query using SUPERCALL_SU_GET_PATH, not a path-hiding bypass.
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
#define KP_SU_GET_PATH 0x1110UL
#define SUPERKEY_BUFFER_SIZE 128
#define PATH_BUFFER_SIZE 256

static void wipe_secret(char *p, size_t n)
{
    volatile char *v = (volatile char *)p;
    while (n--) *v++ = 0;
}

static int read_superkey(char *key, size_t size)
{
    struct termios oldt, newt;
    int have_tty = isatty(STDIN_FILENO);
    int changed = 0;

    if (!have_tty || tcgetattr(STDIN_FILENO, &oldt) != 0) {
        fprintf(stderr, "ERROR: run interactively so the SuperKey is not echoed.\n");
        return -1;
    }

    newt = oldt;
    newt.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) {
        fprintf(stderr, "ERROR: cannot disable terminal echo.\n");
        return -1;
    }
    changed = 1;
    fprintf(stderr, "KernelPatch SuperKey (input hidden): ");
    fflush(stderr);

    char *got = fgets(key, (int)size, stdin);
    if (changed) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        fputc('\n', stderr);
    }
    if (!got) {
        fprintf(stderr, "ERROR: no key was read.\n");
        return -1;
    }

    key[strcspn(key, "\r\n")] = '\0';
    if (!key[0]) {
        fprintf(stderr, "ERROR: empty key.\n");
        return -1;
    }
    return 0;
}

int main(void)
{
#if !defined(__aarch64__) || !defined(__LP64__)
    fprintf(stderr, "ERROR: build for native 64-bit ARM Termux.\n");
    return 2;
#endif

    char key[SUPERKEY_BUFFER_SIZE] = {0};
    char path[PATH_BUFFER_SIZE] = {0};

    if (read_superkey(key, sizeof(key)) != 0) {
        wipe_secret(key, sizeof(key));
        return 2;
    }

    const uint64_t version_cmd =
        ((uint64_t)KP_VERSION_CODE << 32) |
        ((uint64_t)KP_SUPERCALL_MAGIC << 16) |
        KP_SU_GET_PATH;

    errno = 0;
    long ret = syscall(KP_SUPERCALL_NR, key, (long)version_cmd,
                       path, (long)sizeof(path));
    int saved_errno = errno;
    wipe_secret(key, sizeof(key));

    if (ret == -1) {
        fprintf(stderr, "operation=get-path syscall_error=%d (%s)\n",
                saved_errno, strerror(saved_errno));
        return 1;
    }

    path[sizeof(path) - 1] = '\0';
    if (!path[0]) {
        fprintf(stderr, "ERROR: SuperCall returned %ld but no path was copied.\n", ret);
        return 1;
    }

    printf("operation=get-path return=%ld\n", ret);
    printf("ACTIVE_SU_PATH=%s\n", path);
    if (strcmp(path, "/system/bin/kp") != 0 &&
        strcmp(path, "/system/bin/su") != 0) {
        puts("WARNING: active path is not one of the expected Android SU aliases.");
    }
    return 0;
}
