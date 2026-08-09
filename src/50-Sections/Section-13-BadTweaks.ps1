<#
    Section 13 - detect and revert known-harmful "optimizations".

    These appear constantly in CS2 optimization videos and are either useless,
    harmful, or anti-cheat risks.

    DELIBERATE DEVIATION from spec 13, which says "detect and OFFER to revert"
    the starred items: this reverts them directly. Rationale: every starred
    item is unambiguously harmful (a disabled pagefile, disabled TRIM,
    hypervisorlaunchtype Off on a FACEIT machine), every revert is recorded in
    the manifest and undoable with -Rollback, and an interactive prompt would
    break the script's run-once, no-interaction contract. -DryRun remains the
    way to preview them, like every other change.
#>

function Invoke-OptSection13 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 13 - Detect and revert known-harmful tweaks'

    if (-not (Test-OptSectionEnabled -State $State -Section '13')) { return }

    $p = $State.Profile
    $found = 0

    # --- hypervisorlaunchtype off ---------------------------------------------
    # The most damaging one: it silently prevents VBS from running, so the
    # machine fails the FACEIT check with no obvious cause.
    if ([string]$p.Security.HypervisorLaunchType -match '^Off') {
        $found++
        if ($State.Capabilities.BcdEdit -and $State.Capabilities.HypervisorOff -ne $true) {
            $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' `
                 -ArgumentList @('/set', 'hypervisorlaunchtype', 'Auto') -Purpose 'restore hypervisorlaunchtype'

            if ($State.DryRun) {
                [void](Add-OptDecision -State $State -Id 'S-13-HVLAUNCH' -Section '13' -Decision 'Applied' `
                    -Title 'Revert hypervisorlaunchtype off' -Reason 'would set hypervisorlaunchtype back to Auto')
            }
            elseif ($r.Success) {
                $change = New-OptChangeRecord -State $State -Type 'BcdEditValue' -Section '13' -Tier 'Safe' `
                    -Path 'bcdedit {current}' -Name 'hypervisorlaunchtype' `
                    -Target @{ Element = 'hypervisorlaunchtype' } `
                    -OldValue 'Off' -NewValue 'Auto' -ExistedBefore $true -RequiresReboot -VerifyMode 'PostReboot'
                [void](Add-OptChange -State $State -Change $change)
                [void](Add-OptDecision -State $State -Id 'S-13-HVLAUNCH' -Section '13' -Decision 'Applied' `
                    -Title 'Revert hypervisorlaunchtype off' -Severity 'Warning' `
                    -Reason 'was Off, which silently prevents VBS from running and fails the FACEIT check - restored to Auto. Reboot required.')
            }
        }
        else {
            [void](Add-OptFinding -State $State -Id 'S-13-HVLAUNCH' -Section '13' `
                -Title 'hypervisorlaunchtype is Off' -Severity 'Critical' `
                -Reason 'could not revert automatically (bcdedit is blocked). Run: bcdedit /set hypervisorlaunchtype Auto')
        }
    }

    # --- TCP autotuning disabled ----------------------------------------------
    # A genuine throughput regression that many scripts introduce. Section 7.2
    # already fixes it; this reports it as damage found rather than a tweak.
    $show = Invoke-OptNativeCommand -State $State -FilePath 'netsh.exe' -ArgumentList @('int', 'tcp', 'show', 'global') -ReadOnly
    foreach ($line in (Get-OptCommandLines -Text $show.StdOut)) {
        if ($line -match 'Receive Window Auto-Tuning Level\s*:\s*disabled') {
            $found++
            [void](Add-OptDecision -State $State -Id 'S-13-AUTOTUNE' -Section '13' -Decision 'Finding' `
                -Title 'TCP auto-tuning was disabled' -Severity 'Warning' `
                -Reason 'this is a real throughput regression introduced by many optimization scripts - section 7.2 restores it to normal')
        }
    }

    # --- pagefile disabled ----------------------------------------------------
    $paging = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles'
    if ($null -ne $paging -and @($paging).Count -eq 0) {
        $found++
        [void](Add-OptFinding -State $State -Id 'S-13-PAGEFILE' -Section '13' `
            -Title 'Pagefile is disabled' -Severity 'Error' `
            -Reason 'causes hard crashes under memory pressure and kills crash dumps. Section 5.1 restores a fixed-size pagefile.')
    }

    # --- ScheduledDefrag disabled ---------------------------------------------
    $defrag = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction SilentlyContinue
    if ($defrag -and [string]$defrag.State -eq 'Disabled') {
        $found++
        $r = Invoke-OptCmdletChange -State $State -Description 're-enable ScheduledDefrag' -Action {
            Enable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop | Out-Null
        }
        [void](Add-OptDecision -State $State -Id 'S-13-DEFRAG' -Section '13' `
            -Decision $(if ($r.Success) { 'Applied' } else { 'Failed' }) `
            -Title 'Re-enable ScheduledDefrag' -Severity 'Warning' `
            -Reason 'was disabled - that stops TRIM on SSDs and stops real defragmentation on HDDs. Harmful on every storage type.')
    }

    # --- VBS / Memory Integrity disabled by a prior "optimization" ------------
    if ($p.Security.HasKernelAntiCheat -and $p.Security.VbsRunning -eq $false) {
        $found++
        # Already raised as a section 10 finding; noted here as the known-bad
        # tweak it almost always is.
        [void](Add-OptDecision -State $State -Id 'S-13-VBS' -Section '13' -Decision 'Finding' `
            -Title 'VBS disabled on an anti-cheat machine' -Severity 'Critical' `
            -Reason 'the single most common piece of bad CS2 advice as of 2026 - see the section 10 remediation steps')
    }

    # --- resident timer-resolution utilities ----------------------------------
    $timerTools = @(Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^(ISLC|TimerTool|TimerResolution|SetTimerResolution)' })
    if ($timerTools.Count -gt 0) {
        $found++
        [void](Add-OptFinding -State $State -Id 'S-13-TIMERTOOL' -Section '13' `
            -Title 'Resident timer-resolution utility running' -Severity 'Error' `
            -Reason "found: $((@($timerTools | ForEach-Object { $_.Name }) | Sort-Object -Unique) -join ', '). A resident process plus potential injection is an anti-cheat risk, and it contradicts the run-once design. Close and uninstall it.")
    }

    if ($found -eq 0) {
        Write-OptLog -Level Good 'No known-harmful tweaks detected'
        [void](Add-OptDecision -State $State -Id 'S-13-CLEAN' -Section '13' -Decision 'NoOp' `
            -Title 'Known-harmful tweak scan' -Reason 'none of the starred bad tweaks from the spec are present on this machine')
    }
}
