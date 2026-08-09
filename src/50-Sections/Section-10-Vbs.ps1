<#
    Section 10 - Virtualization-Based Security: PRESERVE, DO NOT DISABLE.

    This section is REPORT-ONLY on any machine with a kernel anti-cheat.

    Most CS2 optimization guides tell you to disable VBS for the CPU headroom.
    That advice is wrong for any machine running FACEIT AC: FACEIT requires VBS
    in order to support IOMMU, which is the mechanism that neutralizes DMA-card
    cheats. TPM 2.0 and Secure Boot became mandatory for all players on
    25 Nov 2025; IOMMU and VBS have been enforced in expanding waves since
    April 2025.

    So on a FACEIT machine VBS is a DEPENDENCY, not an optimization target, and
    "VBS is not running" is a blocking problem to fix - never a tweak that
    succeeded.
#>

function Invoke-OptSection10 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 10 - VBS / IOMMU compliance (report only)'

    $s = $State.Profile.Security

    if (-not $s.HasKernelAntiCheat) {
        [void](Add-OptDecision -State $State -Id 'S-10-NOAC' -Section '10' -Decision 'NoOp' `
            -Title 'VBS state' -Severity 'Warning' `
            -Reason 'no kernel anti-cheat detected, so disabling VBS is technically available under Experimental. This script still will not do it by default - the DMA-cheat protection is worth more than the CPU headroom, and installing FACEIT later would immediately require it back.')
        return
    }

    # --- Windows 11 itself is now a FACEIT requirement -----------------------
    # Announced Oct 2025: Windows 11 becomes mandatory on FACEIT from
    # 14 Oct 2026, alongside the TPM/Secure Boot mandate (all players since
    # 25 Nov 2025) and the staged IOMMU/VBS enforcement.
    if ((ConvertTo-OptBool -Value $State.Profile.OS.IsWin11) -eq $false) {
        [void](Add-OptFinding -State $State -Id 'S-10-WIN11' -Section '10' `
            -Title 'Windows 10 with FACEIT AC installed' -Severity 'Critical' `
            -Reason 'FACEIT requires Windows 11 from 14 October 2026. This machine is not on Windows 11 - upgrading is a prerequisite for everything else in this report.')
    }

    # --- compliance summary ---
    $compliant = ($s.VbsRunning -eq $true) -and ($s.IommuEnabled -ne $false) -and
                 ($s.SecureBootEnabled -eq $true) -and ($s.TpmReady -eq $true)

    if ($compliant) {
        Write-OptLog -Level Good 'FACEIT security requirements are satisfied: Secure Boot ON, TPM ready, VBS running, IOMMU enabled'
        [void](Add-OptDecision -State $State -Id 'S-10-COMPLIANT' -Section '10' -Decision 'NoOp' `
            -Title 'FACEIT compliance' `
            -Reason "Secure Boot ON, TPM ready, VBS running, IOMMU $(Format-OptTriState $s.IommuEnabled) ($($s.IommuEvidence -join '; ')) - nothing to change")
    }

    if ($s.VbsRunning -eq $false) {
        [void](Add-OptFinding -State $State -Id 'S-10-VBS' -Section '10' `
            -Title 'VBS is not running but FACEIT AC is installed' -Severity 'Critical' `
            -Reason 'Remediation: 1) enable IOMMU in firmware (VT-d on Intel, IOMMU/AMD-Vi plus SVM on AMD); 2) ensure HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity = 1 and RequirePlatformSecurityFeatures = 1 or 3; 3) confirm bcdedit hypervisorlaunchtype is Auto, not Off - a previous "optimization" script is the most common cause; 4) reboot and re-verify.')
    }

    if ($s.IommuEnabled -eq $false) {
        [void](Add-OptFinding -State $State -Id 'S-10-IOMMU' -Section '10' `
            -Title 'IOMMU is not enabled but FACEIT AC is installed' -Severity 'Critical' `
            -Reason 'This is a firmware change, not something a script can do. Enable VT-d (Intel) or IOMMU / AMD-Vi plus SVM (AMD) in BIOS.')
    }
    elseif ($null -eq $s.IommuEnabled) {
        # Indeterminate is NOT a failure. Reporting it as one would send the
        # user into their BIOS for nothing.
        [void](Add-OptDecision -State $State -Id 'S-10-IOMMU-UNKNOWN' -Section '10' -Decision 'Unverified' `
            -Title 'IOMMU state could not be confirmed' `
            -Reason 'no positive signal was available. Check msinfo32 for "Kernel DMA Protection" and the "Virtualization-based security" fields - that is what FACEIT support asks for. This is not being reported as a failure.')
    }

    if ([string]$s.HypervisorLaunchType -match '^Off') {
        [void](Add-OptFinding -State $State -Id 'S-10-HVLAUNCH' -Section '10' `
            -Title 'hypervisorlaunchtype is Off' -Severity 'Critical' `
            -Reason 'This silently prevents VBS from running, so the machine fails the FACEIT check with no obvious cause. Fix with: bcdedit /set hypervisorlaunchtype Auto')
    }

    # --- 10.4: the one place performance is still recoverable ---
    if ($s.HvciRunning -eq $true) {
        [void](Add-OptManual -State $State -Id 'S-10.4' -Section '10.4' `
            -Title 'Memory Integrity (HVCI) - user-confirmed experiment only' `
            -Reason 'left exactly as-is by design' `
            -Detail @'
VBS and HVCI are not the same thing. VBS is the hypervisor-backed security
boundary; HVCI is one service running on top of it, and HVCI carries the larger
share of the CPU cost because it forces code-integrity checks through the
hypervisor.

FACEIT's published requirements name IOMMU and VBS throughout and do not name
HVCI / Memory Integrity. So the likely performance-optimal COMPLIANT
configuration is IOMMU on, VBS on, Memory Integrity off, Credential Guard off.

Treat that as a HYPOTHESIS, not a fact. This script will never auto-disable HVCI
on a FACEIT machine: if a future enforcement wave adds an HVCI check, an
assumption baked into a script becomes a silent lockout.

If you want to test it: turn Memory Integrity off in Windows Security > Device
security > Core isolation, reboot, then LAUNCH THE FACEIT AC CLIENT AND CONFIRM
IT PASSES before queueing a match. Registry equivalent, for reference only:
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 0
'@)
    }

    # --- 10.5: reframe the performance target honestly ---
    [void](Add-OptDecision -State $State -Id 'S-10.5' -Section '10' -Decision 'NoOp' `
        -Title 'Realistic performance ceiling' `
        -Reason 'With VBS mandatory, the levers that actually matter on this machine are section 3.8 (refresh rate), 4.1 (MMCSS), 6 (input), 9 (Defender exclusions) and firmware-level memory tuning - not kernel security teardown. Nothing in this script can recover what VBS costs, and it will not pretend otherwise.')
}
