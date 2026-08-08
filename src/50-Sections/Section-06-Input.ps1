<#
    Section 6 - Input and foreground process priority.
#>

function Invoke-OptSection06 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 6 - Input and process priority'

    Invoke-OptSection61Mouse         -State $State
    Invoke-OptSection62Accessibility -State $State
    Invoke-OptSection63Queues        -State $State
    Invoke-OptSection64Priority      -State $State
}

function Invoke-OptSection61Mouse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Registry FIRST, then the live SPI call. Ordering matters: SPI_SETMOUSE with
    # SPIF_UPDATEINIFILE writes these same values itself, so the pre-change state
    # has to be captured into the manifest before that happens - and the registry
    # values are what persist across logon.
    foreach ($v in @(
        @{ N = 'MouseSpeed';      V = '0' }
        @{ N = 'MouseThreshold1'; V = '0' }
        @{ N = 'MouseThreshold2'; V = '0' }
    )) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\Control Panel\Mouse' -Name $v.N `
            -Type String -Value $v.V -Section '6.1' -Tier 'Safe' `
            -Title "Mouse acceleration off ($($v.N))" | Out-Null
    }

    # Pointer speed slider. 10 is the 6/11 notch - any other value applies a
    # scaling multiplier to raw input.
    $mouse = $State.Profile.Input.Mouse
    if ($mouse -and $null -ne $mouse.Speed -and [int]$mouse.Speed -ne 10) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSensitivity' `
            -Type String -Value '10' -Section '6.1' -Tier 'Safe' `
            -Title 'Pointer speed to 6/11 (no scaling)' | Out-Null
    }

    if (-not (Test-OptSectionEnabled -State $State -Section '6.1')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    # Apply live so no logoff is needed - but only when the elevated identity IS
    # the interactive user. SystemParametersInfo affects the CALLING session, so
    # running it as a different admin would apply to the wrong session while the
    # registry writes went to the right one.
    if (-not $State.TargetUser.IsCurrent) {
        $State.LogoffRequired = $true
        [void](Add-OptDecision -State $State -Id 'S-6.1-SPI' -Section '6.1' -Decision 'NoOp' `
            -Title 'Live mouse setting refresh' -Severity 'Warning' `
            -Reason 'elevated identity is not the interactive user - registry written, but a logoff is required for it to take effect')
        return
    }

    if ($State.Capabilities.Interop -and -not $State.DryRun) {
        $applied = [Cs2Opt.Input.Api]::SetMouse(0, 0, 0)
        [void](Add-OptDecision -State $State -Id 'S-6.1-SPI' -Section '6.1' `
            -Decision $(if ($applied) { 'Applied' } else { 'Failed' }) `
            -Title 'Live mouse setting refresh' `
            -Reason $(if ($applied) { 'Enhance pointer precision disabled without requiring a logoff' } else { 'SystemParametersInfo call failed - logoff required' }))
        if (-not $applied) { $State.LogoffRequired = $true }
    }
}

function Invoke-OptSection62Accessibility {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Stops the sticky-keys popup appearing mid-round from shift-spam.
    foreach ($v in @(
        @{ P = 'HKCU:\Control Panel\Accessibility\StickyKeys';        N = 'Flags'; V = '506' }
        @{ P = 'HKCU:\Control Panel\Accessibility\Keyboard Response'; N = 'Flags'; V = '122' }
        @{ P = 'HKCU:\Control Panel\Accessibility\ToggleKeys';        N = 'Flags'; V = '58'  }
    )) {
        Set-OptRegistryValue -State $State -Path $v.P -Name $v.N -Type String -Value $v.V `
            -Section '6.2' -Tier 'Safe' -Title "Accessibility hotkey off ($(Split-Path -Leaf $v.P))" | Out-Null
    }
}

function Invoke-OptSection63Queues {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Marginal and unmeasured - included for completeness and flagged as such.
    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters' `
        -Name 'MouseDataQueueSize' -Type DWord -Value 50 -Section '6.3' -Tier 'Experimental' `
        -Title 'Mouse data queue size' -RequiresReboot -VerifyMode PostReboot | Out-Null

    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters' `
        -Name 'KeyboardDataQueueSize' -Type DWord -Value 50 -Section '6.3' -Tier 'Experimental' `
        -Title 'Keyboard data queue size' -RequiresReboot -VerifyMode PostReboot | Out-Null

    if (Test-OptTier -State $State -Required 'Experimental') {
        [void](Add-OptDecision -State $State -Id 'S-6.3-NOTE' -Section '6.3' -Decision 'NoOp' `
            -Title 'Device queue size expectations' `
            -Reason 'default is 100; this is unmeasured and expected to show nothing. Included only because it appears on every list.')
    }
}

function Invoke-OptSection64Priority {
    <#
        The anti-cheat-safe way to raise process priority: the kernel applies
        IFEO at process creation, so nothing injects into cs2.exe's address
        space. Never Realtime, and never combined with a -high launch option.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile
    if (-not $p.Games.Cs2Installed) { return }

    $exeName = Split-Path -Leaf ([string]$p.Games.Cs2ExePath)
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exeName\PerfOptions"

    # 3 = High. (1=Idle, 2=Normal, 3=High, 5=BelowNormal, 6=AboveNormal.)
    Set-OptRegistryValue -State $State -Path $key -Name 'CpuPriorityClass' -Type DWord -Value 3 `
        -Section '6.4' -Tier 'Aggressive' -Title 'CS2 process priority (High, via IFEO)' | Out-Null

    Set-OptRegistryValue -State $State -Path $key -Name 'IoPriority' -Type DWord -Value 3 `
        -Section '6.4' -Tier 'Aggressive' -Title 'CS2 I/O priority' | Out-Null

    if ($p.CPU.CcdCount -and [int]$p.CPU.CcdCount -gt 1) {
        [void](Add-OptDecision -State $State -Id 'S-6.4-CCD' -Section '6.4' -Decision 'Manual' `
            -Title 'CCD pinning (multi-CCD part)' `
            -Reason 'CCD0 pinning is a legitimate manual experiment on dual-CCD X3D parts, but it is workload- and BIOS-dependent, so this script reports it rather than implementing it')
    }
}
