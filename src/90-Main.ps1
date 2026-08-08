<#
    Main entry point - phase ordering per spec 15, with two deliberate changes:

      - Section 3.8 (display refresh) runs EARLY rather than inside step 7's
        registry block. A display-mode change is the one thing here that can
        black-screen a machine, so it happens while there is minimal other state
        to unwind. CDS_TEST-first makes it near-riskless anyway.

      - Section 4.3 (bcdedit) still runs LAST, because it is boot-affecting.
#>

function Invoke-OptMain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $mutex = $null
    $restoreFrequencyChanged = $false

    try {
        # Two concurrent runs would corrupt the manifest.
        $mutex = New-Object System.Threading.Mutex($false, 'Global\Cs2Opt')
        if (-not $mutex.WaitOne(0)) {
            throw 'Another cs2-opt run is already in progress.'
        }

        Write-OptBanner -State $State
        [void](Start-OptTranscript -State $State)

        # --- phase 1: detection --------------------------------------------
        Write-OptLog -Level Info 'Detecting hardware and software profile...'
        [void](Initialize-OptInterop -State $State)

        if ($State.Parameters['ProfileFrom']) {
            $State.Profile = Import-OptProfile -Path $State.Parameters['ProfileFrom']
            Write-OptLog -Level Info "Profile loaded from $($State.Parameters['ProfileFrom']) (hardware not probed)"
        }
        else {
            $State.Profile = Get-OptProfile -State $State
        }

        if ($State.Parameters['CaptureProfile']) {
            Export-OptProfile -ProfileData $State.Profile -Path $State.Parameters['CaptureProfile']
            Write-OptLog -Level Good "Profile written to $($State.Parameters['CaptureProfile'])"
            return
        }

        # --- rollback / verify-only short circuits ---------------------------
        if ($State.Parameters['Rollback']) {
            $summary = Invoke-OptRollback -State $State -ManifestPath $State.Paths.Manifest -WhatIfOnly:$State.DryRun
            return $summary
        }

        if ($State.Parameters['VerifyOnly']) {
            $manifest = Read-OptManifest -Path $State.Paths.Manifest
            [void](Invoke-OptVerification -State $State -Changes @($manifest.Changes) -PostReboot)
            Write-OptVerificationReport -State $State
            return
        }

        # --- phase 2: gates -------------------------------------------------
        $gates = Resolve-OptGates -ProfileData $State.Profile -Tier $State.Tier -Options $State.Parameters
        Set-OptGateResults -State $State -GateResult $gates

        Write-OptDetectionReport -State $State

        if ($State.Aborted) {
            Write-OptLog -Level Error "ABORTED: $($State.AbortReason)"
            return
        }

        # --- fingerprint / re-run safety -------------------------------------
        if (Test-Path -LiteralPath $State.Paths.Manifest) {
            try {
                $prior = Read-OptManifest -Path $State.Paths.Manifest
                $fp = Test-OptFingerprintMatch -StoredFingerprint $prior.Fingerprint -CurrentFingerprint $State.Profile.Fingerprint
                if ($fp.Status -eq 'Mismatch') {
                    Write-OptLog -Level Warn "Hardware changed since the last run - $($fp.Detail)"
                    Write-OptLog -Level Detail 'Every gate is being re-evaluated from scratch. Previously-applied vendor-specific tweaks may now target absent hardware - consider -Rollback against the old manifest first.'
                }
            }
            catch { }
        }

        # --- phase 3: security preflight (FATAL) ------------------------------
        $pre = Invoke-OptSecurityPreflight -State $State
        if (-not $pre.Passed) {
            Write-OptLog -Level Error "ABORTED: $($State.AbortReason)"
            return
        }

        if ($State.DryRun) {
            Write-OptLog -Level Info 'Dry run: continuing through every section with mutations disabled, to produce the full planned manifest.'
        }

        # --- phase 4: restore point ------------------------------------------
        $skipRecovery = [bool]$State.Parameters['SkipRecovery']
        if ($skipRecovery) {
            Write-OptLog -Level Warn 'Recovery artifacts skipped (-SkipRecovery): no restore point, no .reg exports.'
            Write-OptLog -Level Detail 'The manifest and journal are still written, so -Rollback works exactly as normal.'
            [void](Add-OptDecision -State $State -Id 'S-RECOVERY' -Section '1' -Decision 'Off' `
                -Title 'Recovery artifacts' -Severity 'Warning' `
                -Reason 'skipped at the user request via -SkipRecovery. Value-level rollback from the manifest is unaffected; what is given up is recovery if the manifest itself is lost, and the coarse whole-system undo of a restore point.')
        }
        elseif (-not $State.DryRun -and -not $State.Parameters['SkipRestorePoint']) {
            $restoreFrequencyChanged = New-OptRestorePoint -State $State
        }

        # --- phase 5+: sections ----------------------------------------------
        Invoke-OptSection02 -State $State          # power
        Invoke-OptSection03 -State $State          # GPU, including 3.8 refresh early
        Invoke-OptSection05 -State $State          # memory + storage
        Invoke-OptSection04 -State $State          # scheduler (4.3 bcdedit gated inside)
        Invoke-OptSection06 -State $State          # input
        Invoke-OptSection08 -State $State          # background, telemetry, tasks
        Invoke-OptSection07 -State $State          # network
        Invoke-OptSection09 -State $State          # Defender exclusions
        Invoke-OptSection10 -State $State          # VBS compliance - report only
        Invoke-OptSection13 -State $State          # revert known-harmful tweaks

        Invoke-OptManualChecklists -State $State

        # --- verification ------------------------------------------------------
        [void](Invoke-OptVerification -State $State)
        Write-OptVerificationReport -State $State

        # --- security postflight ----------------------------------------------
        if (-not $State.DryRun) {
            [void](Invoke-OptSecurityPostflight -State $State)
        }

        # --- reports -----------------------------------------------------------
        Write-OptManifest -State $State -Final
        Write-OptMarkdownReport -State $State
        Write-OptRunSummary -State $State
    }
    finally {
        # The restore-point frequency override MUST be undone, or the machine
        # keeps unlimited restore points forever.
        if ($restoreFrequencyChanged) { Restore-OptRestorePointFrequency -State $State }

        Stop-OptTranscript
        if ($mutex) {
            try { $mutex.ReleaseMutex() } catch { }
            $mutex.Dispose()
        }
    }
}

function New-OptRestorePoint {
    <#
        Returns $true when the frequency override was applied and must be undone.

        Windows rate-limits restore points to one per 24 h. On the reference
        machine a point already existed from earlier today, so Checkpoint-Computer
        SILENTLY NO-OPS without this override - and a safety net you believe in
        but do not have is worse than none.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Info 'Creating a system restore point...'

    $srKey = 'SYSTEM\CurrentControlSet\Control\SystemRestore'
    $freqKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $changed = $false

    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
    }
    catch {
        Write-OptLog -Level Warn "Could not enable System Restore: $($_.Exception.Message)"
    }

    $original = Get-OptRegValueSafe -Hive HKLM -SubKey $freqKey -Name 'SystemRestorePointCreationFrequency'
    $State['RestoreFreqOriginal'] = $original

    try {
        $base = Get-OptRegistryHiveKey -Hive 'HKLM'
        $key = $base.CreateSubKey($freqKey)
        $key.SetValue('SystemRestorePointCreationFrequency', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.Dispose(); $base.Dispose()
        $changed = $true
    }
    catch {
        Write-OptLog -Level Warn "Could not set the restore-point frequency override: $($_.Exception.Message)"
    }

    $before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)

    try {
        Checkpoint-Computer -Description 'Pre-CS2-Opt' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
    }
    catch {
        Write-OptLog -Level Warn "Checkpoint-Computer failed: $($_.Exception.Message)"
    }

    # Assert the point actually landed rather than assuming it did.
    $after = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
    $newest = $after | Select-Object -Last 1

    if ($after.Count -gt $before.Count -and $newest -and [string]$newest.Description -eq 'Pre-CS2-Opt') {
        Write-OptLog -Level Good "Restore point created: $($newest.Description)"
    }
    else {
        Write-OptLog -Level Warn 'Restore point was NOT created. Note that System Restore does not cover HKCU, NIC properties, the pagefile, Defender exclusions, or app removals anyway - the manifest is the real undo mechanism.'
        [void](Add-OptDecision -State $State -Id 'S-RESTORE' -Section '1' -Decision 'Failed' `
            -Title 'System restore point' -Severity 'Warning' `
            -Reason 'could not be created - rely on -Rollback and the registry backups instead')
    }

    [void]$srKey  # referenced for clarity; frequency lives under $freqKey
    return $changed
}

function Restore-OptRestorePointFrequency {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $freqKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $original = $State['RestoreFreqOriginal']

    try {
        $base = Get-OptRegistryHiveKey -Hive 'HKLM'
        $key = $base.CreateSubKey($freqKey)
        if ($null -eq $original) {
            # It did not exist before - remove it so the 1440-minute default
            # applies again rather than leaving unlimited restore points on.
            $key.DeleteValue('SystemRestorePointCreationFrequency', $false)
        }
        else {
            $key.SetValue('SystemRestorePointCreationFrequency', [int]$original, [Microsoft.Win32.RegistryValueKind]::DWord)
        }
        $key.Dispose(); $base.Dispose()
    }
    catch {
        Write-OptLog -Level Warn "Could not restore the restore-point frequency setting: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

$OptParameters = @{
    Tier                  = $Tier
    DryRun                = [bool]$DryRun
    Rollback              = [bool]$Rollback
    ManifestPath          = $ManifestPath
    RemoveApps            = [bool]$RemoveApps
    RemoveOneDrive        = [bool]$RemoveOneDrive
    BitLockerAcknowledged = [bool]$BitLockerAcknowledged
    # -SkipRecovery subsumes -SkipRestorePoint, so passing it alone is enough.
    SkipRestorePoint      = ([bool]$SkipRestorePoint -or [bool]$SkipRecovery)
    SkipRecovery          = [bool]$SkipRecovery
    NoReboot              = [bool]$NoReboot
    VerifyOnly            = [bool]$VerifyOnly
    CaptureProfile        = $CaptureProfile
    ProfileFrom           = $ProfileFrom
    Sections              = $Sections
    ExcludeSections       = $ExcludeSections
    AllowNetworkRestart   = [bool]$AllowNetworkRestart
}

# -ProfileFrom means the hardware was not probed, so mutating would be reckless.
if ($ProfileFrom) { $OptParameters['DryRun'] = $true }

$script:Opt = New-OptState -Tier $Tier -Parameters $OptParameters
[void](Initialize-OptPaths -State $script:Opt -ManifestPath $ManifestPath)

Invoke-OptMain -State $script:Opt
