<#
    Section 0 - anti-cheat preflight and postflight.

    These are the ONLY checks in the script that are fatal. Everything else
    degrades to a warning.

    The single most important assertion here is negative: a VBS/IOMMU regression
    is the worst outcome this script can produce (spec 14), so if VBS drops
    between preflight and postflight the run does not merely report it - it
    rolls the security-adjacent changes back and tells the user not to reboot.
#>

function Invoke-OptSecurityPreflight {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 0 - Anti-cheat preflight'

    $s = $State.Profile.Security
    $hasAc = [bool]$s.HasKernelAntiCheat

    $snapshot = [ordered]@{
        SecureBootEnabled       = $s.SecureBootEnabled
        TpmReady                = $s.TpmReady
        VbsStatus               = $s.VbsStatus
        VbsRunning              = $s.VbsRunning
        HvciRunning             = $s.HvciRunning
        SecurityServicesRunning = @($s.SecurityServicesRunning)
        HypervisorLaunchType    = $s.HypervisorLaunchType
        HypervisorIommuPolicy   = $s.HypervisorIommuPolicy
        IommuEnabled            = $s.IommuEnabled
        AntiCheat               = @($s.AntiCheat | ForEach-Object {
                                    @{ Name = $_.Name; DriverRunning = $_.DriverRunning; ServiceEnabled = $_.ServiceEnabled }
                                 })
    }
    $State['SecuritySnapshot'] = $snapshot

    $fatal = New-Object System.Collections.ArrayList

    if ($hasAc) {
        Write-OptLog -Level Info "Kernel anti-cheat detected: $((@($s.AntiCheat | ForEach-Object { $_.Name })) -join ', ') - section 0 checks are FATAL"

        if ($s.SecureBootEnabled -eq $false) { [void]$fatal.Add('Secure Boot is disabled') }
        if ($s.TpmReady -eq $false)          { [void]$fatal.Add('TPM is not present or not ready') }
    }
    else {
        Write-OptLog -Level Info 'No kernel anti-cheat detected - section 0 checks downgraded to warnings'
        # Still never DISABLE Secure Boot or TPM, since one may be installed later.
    }

    foreach ($f in $fatal) {
        [void](Add-OptFinding -State $State -Id 'S-0-FATAL' -Section '0' `
            -Title 'Anti-cheat preflight failure' -Reason $f -Severity 'Critical')
    }

    if ($fatal.Count -gt 0) {
        $State.Aborted = $true
        $State.AbortReason = "anti-cheat preflight failed: $($fatal -join '; ')"
        return @{ Passed = $false; Fatal = @($fatal) }
    }

    Write-OptLog -Level Good ("Secure Boot {0}, TPM {1}, VBS {2}, HVCI {3}, IOMMU {4}" -f `
        (Format-OptTriState $s.SecureBootEnabled), (Format-OptTriState $s.TpmReady),
        (Format-OptTriState $s.VbsRunning), (Format-OptTriState $s.HvciRunning),
        (Format-OptTriState $s.IommuEnabled))

    foreach ($ac in $s.AntiCheat) {
        # Assert PRESENT and NOT DISABLED - never "Running". These services are
        # Stopped/Manual by design and start on demand when the client launches,
        # so a Running assertion would false-fail on every single run.
        $ok = $ac.DriverPresent -or $ac.ServicePresent
        Write-OptLog -Level $(if ($ok) { 'Good' } else { 'Warn' }) `
            ("{0}: drivers [{1}] services [{2}]" -f $ac.Name, (@($ac.DriverStates) -join ' '), (@($ac.ServiceStates) -join ' '))
    }

    return @{ Passed = $true; Fatal = @() }
}

function Invoke-OptSecurityPostflight {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 0 - Anti-cheat postflight'

    $before = $State['SecuritySnapshot']
    if (-not $before) { return @{ Passed = $true; Regressions = @() } }

    # Re-detect rather than trusting the preflight profile.
    $after = Get-OptSecurityInfo -State $State

    $regressions = New-Object System.Collections.ArrayList

    if ($before.SecureBootEnabled -eq $true -and $after.SecureBootEnabled -ne $true) {
        [void]$regressions.Add('Secure Boot is no longer enabled')
    }
    if ($before.TpmReady -eq $true -and $after.TpmReady -ne $true) {
        [void]$regressions.Add('TPM is no longer ready')
    }
    if ($before.VbsRunning -eq $true -and $after.VbsRunning -ne $true) {
        [void]$regressions.Add('VBS is no longer running')
    }
    if ($before.IommuEnabled -eq $true -and $after.IommuEnabled -eq $false) {
        [void]$regressions.Add('IOMMU is no longer enabled')
    }

    foreach ($acBefore in @($before.AntiCheat)) {
        $acAfter = @($after.AntiCheat) | Where-Object { $_.Name -eq $acBefore.Name } | Select-Object -First 1
        if (-not $acAfter) { [void]$regressions.Add("$($acBefore.Name) is no longer detected"); continue }
        if ($acBefore.DriverRunning -and -not $acAfter.DriverRunning) {
            [void]$regressions.Add("$($acBefore.Name) driver is no longer running")
        }
        if ($acBefore.ServiceEnabled -and -not $acAfter.ServiceEnabled) {
            [void]$regressions.Add("$($acBefore.Name) service has been disabled")
        }
    }

    if ($regressions.Count -eq 0) {
        Write-OptLog -Level Good 'No security or anti-cheat regressions - Secure Boot, TPM, VBS, IOMMU and anti-cheat all unchanged'
        return @{ Passed = $true; Regressions = @() }
    }

    foreach ($r in $regressions) {
        [void](Add-OptFinding -State $State -Id 'S-0-REGRESSION' -Section '0' `
            -Title 'SECURITY REGRESSION' -Reason $r -Severity 'Critical')
        Write-OptLog -Level Error $r
    }

    # Act, do not merely report. Reporting the worst outcome the script can
    # produce while leaving the machine in that state is the wrong behaviour.
    Write-OptLog -Level Error 'DO NOT REBOOT until this is resolved.'
    Invoke-OptSecurityAutoRollback -State $State

    return @{ Passed = $false; Regressions = @($regressions) }
}

function Invoke-OptSecurityAutoRollback {
    <#
        Rolls back ONLY the security-adjacent changes, newest first, leaving the
        rest of the run intact.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $pattern = 'hypervisorlaunchtype|DeviceGuard|HypervisorEnforcedCodeIntegrity|EnableVirtualizationBasedSecurity|LsaCfgFlags'

    $suspects = @($State.Changes | Where-Object {
        "$($_.Path)\$($_.Name)" -match $pattern -or [string]$_.Type -eq 'BcdEditValue'
    } | Sort-Object -Property @{ Expression = { [int]$_.Id } } -Descending)

    if ($suspects.Count -eq 0) {
        Write-OptLog -Level Warn 'No security-adjacent changes were made by this run - the regression has another cause (firmware, driver, or another tool).'
        return
    }

    Write-OptLog -Level Warn "Auto-rolling back $($suspects.Count) security-adjacent change(s)..."
    foreach ($c in $suspects) {
        try {
            $r = Invoke-OptRollbackEntry -State $State -Change $c
            Write-OptLog -Level Info "[$($c.Id)] $($r.Result): $($r.Detail)"
        }
        catch {
            Write-OptLog -Level Error "[$($c.Id)] auto-rollback failed: $($_.Exception.Message)"
        }
    }
}
