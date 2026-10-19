#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Device-side SU path-concealment regression probe.
# Run from an UNROOTED Termux session:
#   sh tests/android/su-path-hide-probe.sh
#
# Precondition: while adb shell is allowed to use root, verify that
# /system/bin/su -v succeeds. Do not run this script through su or adb shell.

TOYBOX=/system/bin/toybox
TARGET=/system/bin/su
PASS_COUNT=0
FAIL_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "PASS: $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "FAIL: $1"
}

uid="$(id -u 2>/dev/null)"
if [ "$uid" = "0" ]; then
    echo "ERROR: run this probe as the ordinary Termux app UID, not root."
    exit 2
fi

if [ ! -x "$TOYBOX" ]; then
    echo "ERROR: Android Toybox is unavailable at $TOYBOX"
    exit 2
fi

if [ -z "$TMPDIR" ]; then
    TMPDIR="$HOME"
fi
test_dir="$TMPDIR/kp-su-hide-probe-$$"
if ! mkdir "$test_dir" 2>/dev/null; then
    echo "ERROR: cannot create a private test directory: $test_dir"
    exit 2
fi
trap 'rm -rf "$test_dir"' 0

probe_hidden() {
    label="$1"
    path="$2"
    echo
    echo "[$label] $path"

    # Follow symlinks so this tests the target's metadata, not the link itself.
    "$TOYBOX" stat -L -c '%n %s' "$path" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "$label: stat does not expose the file"
    else
        fail "$label: stat succeeded (file metadata is visible)"
    fi

    "$TOYBOX" test -e "$path" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -eq 1 ]; then
        pass "$label: test -e reports missing"
    else
        fail "$label: test -e returned $rc (expected 1)"
    fi

    "$TOYBOX" test -x "$path" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -eq 1 ]; then
        pass "$label: test -x reports non-executable"
    else
        fail "$label: test -x returned $rc (expected 1)"
    fi

    "$TOYBOX" cat "$path" >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "$label: file open/read is denied"
    else
        fail "$label: file open/read succeeded"
    fi

    ( "$path" -v ) >/dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        pass "$label: execution is denied"
    else
        fail "$label: execution unexpectedly succeeded"
    fi
}

probe_hidden "direct path" "$TARGET"
probe_hidden "dot-dot alias" "/system/bin/../bin/su"
probe_hidden "duplicate-slash alias" "//system//bin/su"

if ln -s "$TARGET" "$test_dir/su-link" 2>/dev/null; then
    probe_hidden "symlink alias" "$test_dir/su-link"

    # Follow a second symlink hop to catch chained-alias regressions.
    if ln -s "$test_dir/su-link" "$test_dir/su-link-chain" 2>/dev/null; then
        probe_hidden "chained symlink alias" "$test_dir/su-link-chain"
    else
        fail "could not create chained symlink in Termux private storage"
    fi
else
    fail "could not create symlink in Termux private storage"
fi

echo
echo "RESULT: PASS=$PASS_COUNT FAIL=$FAIL_COUNT UID=$uid"
if [ "$FAIL_COUNT" -eq 0 ]; then
    exit 0
fi
exit 1
