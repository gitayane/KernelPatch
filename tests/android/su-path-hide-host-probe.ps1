# SPDX-License-Identifier: GPL-2.0-or-later
#
# Host-side positive control for tests/android/su-path-hide-probe.sh.
# Run from Windows PowerShell while path_probe is enabled:
#   .\tests\android\su-path-hide-host-probe.ps1 -Serial CB512EEFAC
#
# The ordinary Termux probe checks that an untrusted UID cannot see or use the
# virtual aliases. Those negative checks can also pass when the path is absent
# without a working hook. This script provides the complementary positive
# control: an authorized root caller should resolve both KernelPatch SU aliases
# to the same inode metadata as /system/bin/sh via getname_flags.
#
# This script only performs stat calls; it does not disable or enable hooks.

param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Serial
)

$ErrorActionPreference = 'Stop'
Get-Command adb -ErrorAction Stop | Out-Null

function Get-RootStat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # The format contains no spaces or shell metacharacters, so it stays
    # unquoted in the remote command and survives PowerShell/adb shell parsing.
    $remoteCommand = "/system/bin/toybox stat -L -c %d:%i:%s:%a $Path"
    # Remote stat failures are expected test results, not PowerShell script
    # exceptions. Temporarily prevent native stderr from terminating the script
    # so it can report the adb exit code and continue checking the other alias.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & adb -s $Serial shell su -c $remoteCommand 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    $text = (($output | ForEach-Object { "$_" }) -join "`n").Trim()

    return [pscustomobject]@{
        Path     = $Path
        ExitCode = $exitCode
        Output   = $text
    }
}

$reference = Get-RootStat -Path '/system/bin/sh'
if ($reference.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($reference.Output)) {
    Write-Host "FAIL: root positive-control stat failed for /system/bin/sh (exit=$($reference.ExitCode))."
    Write-Host $reference.Output
    exit 1
}

$failed = $false
foreach ($alias in @('/system/bin/kp', '/system/bin/su')) {
    $actual = Get-RootStat -Path $alias

    if ($actual.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($actual.Output)) {
        Write-Host "FAIL: authorized lookup of $alias did not resolve (exit=$($actual.ExitCode))."
        Write-Host $actual.Output
        $failed = $true
        continue
    }

    if ($actual.Output -ne $reference.Output) {
        Write-Host "FAIL: $alias does not resolve to the same metadata as /system/bin/sh."
        Write-Host "  alias: $($actual.Output)"
        Write-Host "  shell: $($reference.Output)"
        $failed = $true
        continue
    }

    Write-Host "PASS: authorized lookup of $alias resolves to /system/bin/sh metadata ($($actual.Output))."
}

if ($failed) {
    exit 1
}

Write-Host 'RESULT: PASS=2 FAIL=0 (authorized positive controls only)'
exit 0
