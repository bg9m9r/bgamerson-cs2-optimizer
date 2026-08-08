#Requires -Version 5.1
#Requires -RunAsAdministrator

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
    [switch]$AllowNetworkRestart
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
    throw @"
This script must run under Windows PowerShell 5.1, not PowerShell $($PSVersionTable.PSVersion).

Re-run with:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSCommandPath"
"@
}
