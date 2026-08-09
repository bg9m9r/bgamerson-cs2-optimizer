#Requires -Version 5.1

# NOTE: deliberately NOT '#Requires -RunAsAdministrator'. That directive aborts
# before the param block is even parsed, dumping a raw ParentContainsErrorRecord
# exception at the user - the single most common way to "crash" this script is
# simply double-clicking it unelevated. Spec 1.2.1 asks for an elevation check
# that fails fast WITH A CLEAR MESSAGE, so the check is done in code below,
# where it can also offer to relaunch elevated.

<#
.SYNOPSIS
    One-shot, idempotent, detection-driven Windows 11 optimizer for competitive
    CS2 on FACEIT.

.DESCRIPTION
    Implements cs2-win11-optimization-spec.md. Every tweak is gated on a
    predicate over a detected hardware/software profile; a tweak whose
    preconditions are not met is skipped and logged with the reason, never
    applied blindly. Unknown hardware means skip, not guess.

    Nothing here disables Secure Boot, TPM, VBS or IOMMU. On a machine with a
    kernel anti-cheat installed those are dependencies, not optimization
    targets.

.PARAMETER Tier
    Cumulative. Aggressive includes Safe; Experimental includes both.

.PARAMETER DryRun
    Runs the full pipeline with every mutation chokepoint recording instead of
    writing, then emits the manifest that WOULD have been written. This
    deliberately goes further than spec 1.5.5 (which stops after the detection
    report) - detection is the part that is already safe, so stopping there
    exercises the wrong half.

.PARAMETER Rollback
    Replays a prior run's manifest in reverse.

.PARAMETER VerifyOnly
    Re-runs the verification pass against the last manifest without applying
    anything. This is how reboot-deferred changes (MMAgent, HwSchMode,
    HiberbootEnabled, pagefile, bcdedit) ever get a real PASS.

.PARAMETER CaptureProfile
    Writes the detected profile to a JSON file and exits. Attach it to bug
    reports; it doubles as a test fixture.

.PARAMETER ProfileFrom
    Loads a previously captured profile instead of probing hardware. Test
    injection - implies -DryRun.

.PARAMETER SkipRecovery
    Skips the belt-and-braces recovery artifacts: no System Restore point, and
    no per-key .reg exports. Implies -SkipRestorePoint.

    The change manifest and the append-and-flush journal are STILL written, so
    -Rollback continues to work exactly as before. That is deliberate: rollback
    is value-level from the manifest, and the .reg exports were never the undo
    mechanism - re-importing an exported key restores values deleted elsewhere
    and does not delete values added since.

    What you actually give up: the ability to recover if the manifest itself is
    lost or corrupted, and the coarse whole-system undo of a restore point.
    Worth it if you want a fast, quiet run; not worth it on a first run.

.EXAMPLE
    .\Optimize-CS2.ps1 -DryRun
    .\Optimize-CS2.ps1 -Tier Safe
    .\Optimize-CS2.ps1 -Tier Aggressive -Sections 7
    .\Optimize-CS2.ps1 -Rollback

.NOTES
    BGamerson's CS2 Optimizer Script
    https://github.com/bg9m9r/bgamerson-cs2-optimizer

    Copyright (c) 2026 BGamerson. Released under the MIT License.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. This script
    modifies system configuration. Review the -DryRun output before applying
    anything, and use it at your own risk.

    This notice lives in the script itself because the built file is designed to
    be downloaded and carried around on its own, with no LICENSE or README
    beside it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Safe', 'Aggressive', 'Experimental')]
    [string]$Tier = 'Aggressive',

    [switch]$DryRun,
    [switch]$Rollback,
    [string]$ManifestPath = "$env:ProgramData\cs2-opt\manifest.json",
    [switch]$RemoveApps,
    [switch]$RemoveOneDrive,
    [switch]$BitLockerAcknowledged,
    [switch]$SkipRestorePoint,
    [switch]$SkipRecovery,
    [switch]$NoReboot,

    # --- additive (spec 1.1 contract preserved) ------------------------------
    [switch]$VerifyOnly,
    [string]$CaptureProfile,
    [string]$ProfileFrom,
    [string[]]$Sections,
    [string[]]$ExcludeSections,
    [switch]$AllowNetworkRestart,

    # Suppress the UAC self-relaunch when unelevated: print the message and
    # exit 2 instead. For CI and scripted callers that must never pop a prompt.
    [switch]$NoElevate
)

# StrictMode 3.0 rather than Latest: 3.0 still catches uninitialised variables
# and out-of-bounds indexing, but keeps property access on a hashtable
# non-fatal. That is what lets the detector "Unknown skeleton" pattern work -
# $p.CPU.HasVCache on a failed CPU detection must return $null, not throw.
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# '#Requires -Version 5.1' does NOT exclude PowerShell 7 - 7.x satisfies ">= 5.1".
# Under PS7 the Appx, DISM, MMAgent, NetAdapter, Defender, BitLocker,
# ScheduledTasks, Storage and PnpDevice modules all load through
# WindowsCompatibility implicit remoting, which returns deserialized objects
# (properties only, no methods), changes -ErrorAction semantics, and adds
# seconds per call. Chasing -UseWindowsPowerShell per module is a permanent
# maintenance tax for zero user benefit.
if ($PSVersionTable.PSEdition -eq 'Core') {
    # A clean message and exit, not a throw - a throw paints a red exception
    # block with a stack trace, which reads as a crash rather than as guidance.
    Write-Host ''
    Write-Host "  This script must run under Windows PowerShell 5.1, not PowerShell $($PSVersionTable.PSVersion)." -ForegroundColor Yellow
    Write-Host '  (Under PowerShell 7 the Appx/NetAdapter/Defender/ScheduledTasks modules load' -ForegroundColor Gray
    Write-Host '  through compatibility remoting and behave differently.)' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Re-run with:' -ForegroundColor Gray
    Write-Host "    powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ForegroundColor Cyan
    Write-Host ''
    exit 1
}

# --- elevation ---------------------------------------------------------------
# Everything meaningful here needs admin: HKLM writes, powercfg, Get-Tpm,
# Confirm-SecureBootUEFI, Get-MMAgent, scheduled tasks. Even -DryRun needs it,
# because unelevated detection would return Unknown for the security fields and
# produce a report that does not describe the machine.
$script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                     ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $script:IsElevated) {
    if ($NoElevate) {
        Write-Host ''
        Write-Host '  Administrator rights are required. Re-run from an elevated PowerShell,' -ForegroundColor Yellow
        Write-Host '  or run without -NoElevate to get a UAC prompt.' -ForegroundColor Yellow
        Write-Host ''
        exit 2
    }

    Write-Host ''
    Write-Host '  Administrator rights are required - requesting elevation (UAC prompt)...' -ForegroundColor Yellow

    # Rebuild the exact invocation for the elevated copy. -NoExit keeps the new
    # window open afterwards, because when this is launched by double-click the
    # elevated console would otherwise vanish along with all of its output.
    $relaunchArgs = New-Object System.Collections.ArrayList
    foreach ($a in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File')) { [void]$relaunchArgs.Add($a) }
    [void]$relaunchArgs.Add('"{0}"' -f $PSCommandPath)

    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        $value = $kv.Value
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { [void]$relaunchArgs.Add('-' + $kv.Key) }
        }
        elseif ($value -is [System.Array]) {
            [void]$relaunchArgs.Add('-' + $kv.Key)
            [void]$relaunchArgs.Add(($value -join ','))
        }
        else {
            [void]$relaunchArgs.Add('-' + $kv.Key)
            [void]$relaunchArgs.Add('"{0}"' -f $value)
        }
    }

    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @($relaunchArgs) | Out-Null
        Write-Host '  Continuing in the elevated window.' -ForegroundColor Gray
        Write-Host ''
        exit 0
    }
    catch {
        # The user clicked No on the UAC prompt (or elevation is policy-blocked).
        Write-Host ''
        Write-Host '  Elevation was declined - nothing was changed.' -ForegroundColor Yellow
        Write-Host '  Re-run from an elevated PowerShell when ready.' -ForegroundColor Gray
        Write-Host ''
        exit 2
    }
}
