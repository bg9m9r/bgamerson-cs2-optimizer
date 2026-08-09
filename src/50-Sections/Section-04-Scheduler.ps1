<#
    Section 4 - MMCSS, priority separation, timer configuration.
#>

function Invoke-OptSection04 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 4 - Scheduler, timers, MMCSS'

    Invoke-OptSection41Mmcss    -State $State
    Invoke-OptSection42Priority -State $State
    Invoke-OptSection43Timers   -State $State
}

function Invoke-OptSection41Mmcss {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    $gamesKey   = "$profileKey\Tasks\Games"

    # SystemResponsiveness: per current Microsoft docs, values below 10 (and
    # above 100) are clamped to 20 and non-multiples of 10 round down - so the
    # popular "set it to 0" advice actually lands you at 20, strictly WORSE
    # than the 10 written here. 10 is the true floor.
    #
    # NetworkThrottlingIndex is the half of this block with a real effect on a
    # high-packet-rate title - and unlike section 7.3 it applies to UDP, which
    # is what CS2 actually uses.
    Set-OptRegistryValue -State $State -Path $profileKey -Name 'SystemResponsiveness' `
        -Type DWord -Value 10 -Section '4.1' -Tier 'Aggressive' `
        -Title 'MMCSS SystemResponsiveness' | Out-Null

    Set-OptRegistryValue -State $State -Path $profileKey -Name 'NetworkThrottlingIndex' `
        -Type DWord -Value 4294967295 -Section '4.1' -Tier 'Aggressive' `
        -Title 'MMCSS NetworkThrottlingIndex (disabled)' | Out-Null

    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'GPU Priority' `
        -Type DWord -Value 8 -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games GPU Priority' | Out-Null
    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'Priority' `
        -Type DWord -Value 6 -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games Priority' | Out-Null
    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'Scheduling Category' `
        -Type String -Value 'High' -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games Scheduling Category' | Out-Null
    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'SFIO Priority' `
        -Type String -Value 'High' -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games SFIO Priority' | Out-Null

    # Honesty, sourced from the same Microsoft page: 'GPU Priority' is
    # documented as "not yet used" and 'SFIO Priority' as "not used". They are
    # written because the spec's table includes them and they are harmless, but
    # the report must not imply they do anything.
    [void](Add-OptDecision -State $State -Id 'S-4.1-UNUSED' -Section '4.1' -Decision 'NoOp' `
        -Title 'MMCSS Games GPU Priority / SFIO Priority expectations' `
        -Reason 'Microsoft documents both fields as currently unused by the scheduler - written for spec compliance, expect no effect from these two. Priority and Scheduling Category are the consumed fields.')
}

function Invoke-OptSection42Priority {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # 0x26 = 38. Honest note for the report: the Win11 desktop default of 2
    # already resolves to short quantum / variable / 3:1, so this makes the
    # existing behaviour explicit rather than changing it. Impact is near-zero.
    # Deliberately NOT 0x2A or 0x18 - those force fixed/long quantums, which is
    # worse for a foreground game.
    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' `
        -Name 'Win32PrioritySeparation' -Type DWord -Value 0x26 -Section '4.2' -Tier 'Aggressive' `
        -Title 'Win32PrioritySeparation' -RequiresReboot -VerifyMode PostReboot | Out-Null

    [void](Add-OptDecision -State $State -Id 'S-4.2-NOTE' -Section '4.2' -Decision 'NoOp' `
        -Title 'Priority separation expectations' `
        -Reason 'Windows 11 already defaults to short/variable/3:1 - this makes it explicit rather than inherited. Expect no measurable change.')
}

function Invoke-OptSection43Timers {
    <#
        Section 4.3 is a CLEANUP step, not an addition.

        Windows 11 22H2+ made timer resolution per-process, so the correct
        action is removing damage left by other optimization scripts, not adding
        anything. On a clean machine every one of these reports "element not
        found", which is the desired state.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '4.3')) {
        [void](Add-OptDecision -State $State -Id 'S-4.3' -Section '4.3' -Decision 'Off' `
            -Title 'bcdedit timer cleanup' -Reason 'section gated off')
        return
    }

    if (-not $State.Capabilities.BcdEdit) {
        [void](Add-OptDecision -State $State -Id 'S-4.3-BCD' -Section '4.3' -Decision 'Off' `
            -Title 'bcdedit timer cleanup' -Severity 'Warning' `
            -Reason 'bcdedit changes are blocked (BitLocker protection is on) - registry-only tweaks still proceed')
        return
    }

    $elements = @('useplatformclock', 'useplatformtick', 'disabledynamictick', 'tscsyncpolicy')

    # Read the current boot configuration once so we know what is actually
    # present. Issuing /deletevalue blindly works, but then the report cannot
    # honestly say what was removed versus what was never there.
    $present = @{}
    $enum = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/enum', '{current}') -ReadOnly
    if ($enum.Success) {
        foreach ($line in (Get-OptCommandLines -Text $enum.StdOut)) {
            foreach ($e in $elements) {
                if ($line -match "^\s*$e\s+(\S+)") { $present[$e] = $Matches[1] }
            }
        }
    }

    foreach ($element in $elements) {
        if (-not $present.Contains($element)) {
            [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'NoOp' `
                -Title "bcdedit $element" -Reason 'not set - already in the desired state')
            continue
        }

        $old = $present[$element]
        $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' `
             -ArgumentList @('/deletevalue', $element) -Purpose "remove $element"

        if ($State.DryRun) {
            $planned = New-OptChangeRecord -State $State -Type 'BcdEditValue' -Section '4.3' -Tier 'Safe' `
                -Path 'bcdedit {current}' -Name $element -Target @{ Element = $element } `
                -OldValue $old -NewValue $null -ExistedBefore $true `
                -RequiresReboot -VerifyMode 'PostReboot'
            [void]$State.Changes.Add($planned)

            [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'Applied' `
                -Title "bcdedit $element" -Reason "would remove (currently '$old')")
            continue
        }

        # "The specified element was not found" on stderr with a non-zero exit
        # is a success condition here, which is exactly why every native call
        # runs through Invoke-OptNativeCommand with a locally relaxed
        # $ErrorActionPreference.
        if (-not $r.Success -and $r.StdErr -notmatch 'element was not found|cannot find') {
            [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'Failed' `
                -Title "bcdedit $element" -Reason $r.StdErr.Trim() -Severity 'Error')
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'BcdEditValue' -Section '4.3' -Tier 'Safe' `
            -Path 'bcdedit {current}' -Name $element `
            -Target @{ Element = $element } `
            -OldValue $old -NewValue $null -ExistedBefore $true `
            -RequiresReboot -VerifyMode 'PostReboot'
        [void](Add-OptChange -State $State -Change $change)

        [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'Applied' `
            -Title "bcdedit $element" -Reason "removed (was '$old') - this is cleanup of a known-harmful tweak")
    }

    # Optional, and honestly flagged: restores pre-22H2 global timer resolution.
    if (Test-OptSectionEnabled -State $State -Section '4.3.GlobalTimer') {
        Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' `
            -Name 'GlobalTimerResolutionRequests' -Type DWord -Value 1 `
            -Section '4.3.GlobalTimer' -Tier 'Experimental' `
            -Title 'GlobalTimerResolutionRequests' -RequiresReboot -VerifyMode PostReboot | Out-Null

        [void](Add-OptDecision -State $State -Id 'S-4.3-GLOBALTIMER-NOTE' -Section '4.3' -Decision 'NoOp' `
            -Title 'GlobalTimerResolutionRequests expectations' `
            -Reason 'measured benefit in CS2 is inconsistent - A/B test this one specifically rather than assuming it helped')
    }

    # Explicitly NOT implemented: HPET forcing/disabling via bcdedit. Leave the
    # firmware HPET setting at its default (spec 4.3).
}
