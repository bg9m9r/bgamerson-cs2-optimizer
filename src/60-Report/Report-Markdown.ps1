<#
    Section 14 markdown report.

    Contains: applied changes by tier, skipped changes and why, the manual
    checklists, security tradeoffs accepted, the reboot flag, and the rollback
    command - all projected from the single decision list.
#>

function Format-OptReportValue {
    <#
        Renders a value for a markdown table cell: short, unambiguous, and safe
        to sit inside backticks.
    #>
    [CmdletBinding()][OutputType([string])]
    param([AllowNull()]$Value)

    if ($null -eq $Value)      { return '(none)' }
    if ($Value -is [byte[]])   { return "$($Value.Length) bytes: " + (($Value | Select-Object -First 8 | ForEach-Object { '{0:X2}' -f $_ }) -join ' ') }
    if ($Value -is [string[]]) { return ($Value -join ' ; ') }
    if ($Value -is [bool])     { return $(if ($Value) { 'True' } else { 'False' }) }

    $s = [string]$Value
    if ([string]::IsNullOrEmpty($s)) { return '(empty)' }
    if ($s.Length -gt 60) { $s = $s.Substring(0, 57) + '...' }
    # A backtick inside a backtick-quoted cell would break the code span.
    return ($s -replace '`', "'")
}

function Format-OptReportCell {
    <#
        Escapes a plain markdown cell. The pipe is the killer: registry paths
        are fine, but multi-string values and command lines can contain one and
        would silently split the row into extra columns.
    #>
    [CmdletBinding()][OutputType([string])]
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text -replace '\|', '\|'
    if ($t.Length -gt 78) { $t = $t.Substring(0, 75) + '...' }
    return $t
}

function Get-OptSectionRationale {
    <#
        What each section does and why, in plain language.

        Kept as a lookup keyed by section number rather than threading a
        rationale string through ~90 call sites. Honest about the items that
        are not expected to do anything measurable - a report that oversells is
        worse than no report.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Section)

    $map = @{
        '2' = @{
            Title = 'Power and CPU'
            Why   = 'Stops Windows from parking cores, downclocking, or powering down devices mid-match. Minimum and maximum processor state go to 100% so the CPU never drops to a low P-state between rounds, USB selective suspend and PCIe link power management are turned off so peripherals and the GPU link stay awake, and Fast Startup is disabled. Fast Startup matters most on a dual-boot machine: it leaves NTFS in a dirty state, so the other OS refuses to mount the partition or mounts it read-only.'
        }
        '3' = @{
            Title = 'GPU and display'
            Why   = 'Hardware-accelerated GPU scheduling is enabled, which the AMD Anti-Lag and NVIDIA Reflex low-latency paths depend on. Game DVR and background recording are switched off (they capture continuously and cost frames), while Game Mode is left ON because on Windows 11 it genuinely suppresses background scheduler interference. For cs2.exe specifically, fullscreen optimizations are disabled so the game gets a true exclusive-fullscreen path, and Auto HDR is turned off because it adds latency and skews colours. Refresh-rate enforcement lives here too - the single highest-value item in the whole script when it fires.'
        }
        '4' = @{
            Title = 'Scheduler, timers and MMCSS'
            Why   = 'The Multimedia Class Scheduler settings raise the priority the OS grants a foreground game for GPU work and disk I/O. NetworkThrottlingIndex is the one with a real, measurable effect: by default Windows throttles non-multimedia network traffic to about 10 packets per millisecond, and disabling that matters for a high-packet-rate title like CS2. Be sceptical of Win32PrioritySeparation - Windows 11 already defaults to the short, variable quantum this sets, so it makes existing behaviour explicit rather than changing it. Section 4.3 only ever REMOVES boot timer settings left behind by other optimization scripts; it never adds any.'
        }
        '5' = @{
            Title = 'Memory and storage'
            Why   = 'A fixed-size pagefile (minimum = maximum) avoids the mid-match stalls that happen when Windows resizes a system-managed one. It is never disabled: CS2 and the FACEIT client both benefit from committed backing store, and disabling it kills crash dumps. It stays on the boot volume because kernel crash dumps require it there. Filesystem settings stop the last-access-time write on every file read and disable legacy 8.3 name generation, and TRIM is explicitly confirmed ON. Steam library folders are excluded from the search indexer so it stops crawling tens of gigabytes of game assets.'
        }
        '6' = @{
            Title = 'Input and process priority'
            Why   = 'Mouse acceleration ("Enhance pointer precision") is turned off and pointer speed set to the 6/11 notch, which is the only setting that applies no scaling multiplier to raw input. The accessibility flags stop the Sticky Keys dialog appearing mid-round when you hold shift. CS2 process priority is raised to High through Image File Execution Options - the anti-cheat-safe way to do it, because the kernel applies it at process creation and nothing is injected into the game. CPU affinity is never pinned on any hardware.'
        }
        '7' = @{
            Title = 'Network'
            Why   = 'Only the adapter carrying the default route is touched. Interrupt moderation batches incoming packets to reduce CPU load, which directly adds latency, so it goes off. The power-saving features - Energy-Efficient Ethernet, Green Ethernet, Gigabit Lite - let the NIC negotiate down or idle the link, and on a multi-gigabit adapter they are the usual reason it settles at 1 Gbps. Flow control lets a switch pause your traffic. TCP auto-tuning is deliberately set back to *normal*: many optimization scripts disable it, which is a genuine throughput regression.'
        }
        '8' = @{
            Title = 'Background load and telemetry'
            Why   = 'Be honest about this one: it buys disk, RAM and boot time - not frames. Scheduled tasks are disabled rather than deleted so they stay reversible, and the compatibility appraiser, customer-experience uploads and error reporting are the ones that wake up and scan. The ETW autologger sessions are the part with a genuinely measurable cost, since they run continuously from boot and write to disk. Defender and anti-cheat trace sessions are deliberately left alone. Windows Update is also stopped from replacing your chosen GPU driver with a generic WHQL one mid-season.'
        }
        '9' = @{
            Title = 'Defender exclusions'
            Why   = 'Real-time scanning of shader-cache writes and VPK reads is a measurable stutter source, because the game touches those files constantly during a match. Excluding the Steam library and the vendor shader-cache directory gets most of the benefit of "disable Defender" with none of the cost - real-time protection stays fully on, which section 0 requires. FACEIT directories are deliberately left scanned.'
        }
        '13' = @{
            Title = 'Reverting harmful tweaks'
            Why   = 'These are not optimizations. They are repairs to damage left behind by other CS2 "optimization" scripts - a disabled pagefile, disabled TCP auto-tuning, a disabled ScheduledDefrag task (which stops TRIM on an SSD), or a hypervisorlaunchtype of Off, which silently prevents VBS from running and makes the machine fail the FACEIT check with no obvious cause.'
        }
    }

    if ($map.ContainsKey($Section)) { return $map[$Section] }
    return @{ Title = "Section $Section"; Why = 'See the spec for the reasoning behind this section.' }
}

function Write-OptMarkdownReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not $State.Paths) { return }

    $p  = $State.Profile
    $sb = New-Object System.Text.StringBuilder
    $add = { param($line) [void]$sb.AppendLine($line) }

    & $add "# CS2 / Windows 11 optimization report"
    & $add ''
    & $add "- **Run**: $($State.RunId)"
    & $add "- **When**: $($State.StartedUtc) (UTC)"
    & $add "- **Tier**: $($State.Tier)$(if ($State.DryRun) { '  **(DRY RUN - nothing was modified)**' })"
    & $add "- **Machine**: $env:COMPUTERNAME"
    & $add ''

    # --- detected profile ---
    & $add '## Detected system'
    & $add ''
    & $add '| | |'
    & $add '|---|---|'
    & $add "| CPU | $(([string]$p.CPU.Name).Trim()) - $($p.CPU.Microarch), $($p.CPU.PhysicalCores)C/$($p.CPU.LogicalCores)T, $($p.CPU.CcdCount) CCD, V-Cache $($p.CPU.HasVCache) |"
    & $add "| GPU | $((@($p.GPU.Adapters | ForEach-Object { $_.Name })) -join ', ') (driver $($p.GPU.Adapters[0].DriverVersion)) |"
    & $add "| Display | $((@($p.Display.Displays | ForEach-Object { "$($_.MonitorName) $($_.Width)x$($_.Height) @ $($_.CurrentRefreshHz)/$($_.MaxRefreshHz) Hz" })) -join '; ') |"
    & $add "| Memory | $([math]::Round(([int]$p.Memory.TotalMB)/1024)) GB $($p.Memory.DdrGeneration) @ $($p.Memory.SpeedMTs) MT/s, commit $($p.Memory.CommitPercentOfRam)% |"
    & $add "| Storage | boot $($p.Storage.BootBusType)/$($p.Storage.BootMediaType), $($p.Storage.BootFreeGB) GB free |"
    & $add "| Network | $($p.Network.ActiveAdapterName) - $($p.Network.ActiveLinkSpeed), driver by $($p.Network.ActiveDriverProvider) |"
    & $add "| Security | Secure Boot $(Format-OptTriState $p.Security.SecureBootEnabled), TPM $(Format-OptTriState $p.Security.TpmReady), VBS $(Format-OptTriState $p.Security.VbsRunning), HVCI $(Format-OptTriState $p.Security.HvciRunning), IOMMU $(Format-OptTriState $p.Security.IommuEnabled) |"
    & $add "| Anti-cheat | $((@($p.Security.AntiCheat | ForEach-Object { $_.Name })) -join ', ') |"
    & $add "| Boot | $($p.Boot.FirmwareType)$(if ($p.Boot.IsDualBoot) { ', dual-boot' }) |"
    & $add ''

    # --- findings first: they matter more than the changes ---
    $findings = @($State.Findings)
    if ($findings.Count -gt 0) {
        & $add '## Findings - fix these'
        & $add ''
        & $add 'These are problems to resolve, **not** optimizations that succeeded.'
        & $add ''
        foreach ($f in $findings) {
            & $add "### [$($f.Severity)] $($f.Title) (section $($f.Section))"
            & $add ''
            & $add $f.Reason
            & $add ''
        }
    }

    # --- every change, with its previous value, grouped and explained ---
    & $add '## Changes'
    & $add ''
    $changes = @($State.Changes)
    if ($changes.Count -eq 0) {
        & $add '_No changes were applied._'
        & $add ''
    }
    else {
        $verb = if ($State.DryRun) { 'would be applied' } else { 'applied' }
        & $add "$($changes.Count) change(s) $verb, grouped by section. Every row shows the value **before** this run next to the value being set, so none of it is a black box."
        & $add ''
        & $add 'A dash under **Was** means the value did not exist beforehand - rolling back deletes it rather than restoring anything.'
        & $add ''

        # Grouped by top-level section so the rationale is stated once per area
        # rather than repeated on every row.
        $groups = $changes | Group-Object { ([string]$_.Section -split '\.')[0] } |
                  Sort-Object { [int]$_.Name }

        foreach ($g in $groups) {
            $rationale = Get-OptSectionRationale -Section $g.Name
            & $add "### Section $($g.Name) - $($rationale.Title)"
            & $add ''
            & $add $rationale.Why
            & $add ''
            & $add '| # | Setting | Location | Was | Now | Reboot |'
            & $add '|---|---|---|---|---|---|'

            foreach ($c in ($g.Group | Sort-Object { [int]$_.Id })) {
                $old = if (-not $c.ExistedBefore) { '_-_' }
                       else { '`' + (Format-OptReportValue (ConvertFrom-OptStorableValue $c.OldValue)) + '`' }
                $new = if ($null -eq $c.NewValue) { '_(removed)_' }
                       else { '`' + (Format-OptReportValue (ConvertFrom-OptStorableValue $c.NewValue)) + '`' }

                & $add ("| {0} | {1} | {2} | {3} | {4} | {5} |" -f `
                    $c.Id,
                    (Format-OptReportCell ([string]$c.Name)),
                    (Format-OptReportCell ([string]$c.Path)),
                    $old, $new,
                    $(if ($c.RequiresReboot) { 'yes' } else { '' }))
            }
            & $add ''
        }
    }

    # --- already correct ---
    $noop = @($State.Decisions | Where-Object { $_.Decision -eq 'NoOp' -and $_.Id -like 'S-*' })
    if ($noop.Count -gt 0) {
        & $add '## Already in the desired state'
        & $add ''
        & $add 'Nothing was written for these, and nothing was recorded for rollback.'
        & $add ''
        & $add '| Section | Item | Reason |'
        & $add '|---|---|---|'
        foreach ($n in $noop) { & $add "| $($n.Section) | $($n.Title) | $($n.Reason -replace '\|', '\|') |" }
        & $add ''
    }

    # --- skipped ---
    $off = @($State.Decisions | Where-Object { $_.Decision -eq 'Off' })
    if ($off.Count -gt 0) {
        & $add '## Skipped, and why'
        & $add ''
        & $add '| Section | Item | Reason |'
        & $add '|---|---|---|'
        foreach ($o in $off) { & $add "| $($o.Section) | $($o.Title) | $($o.Reason -replace '\|', '\|') |" }
        & $add ''
    }

    # --- verification ---
    $verification = @($State.Verification)
    if ($verification.Count -gt 0) {
        & $add '## Verification'
        & $add ''
        $pass = @($verification | Where-Object { $_.Result -eq 'PASS' }).Count
        $fail = @($verification | Where-Object { $_.Result -eq 'FAIL' })
        $defer = @($verification | Where-Object { $_.Result -eq 'DEFERRED' })
        & $add "- PASS: $pass"
        & $add "- FAIL: $($fail.Count)"
        & $add "- Deferred to reboot: $($defer.Count)"
        & $add ''
        if ($fail.Count -gt 0) {
            & $add '| Section | Item | Expected | Actual |'
            & $add '|---|---|---|---|'
            foreach ($f in $fail) { & $add "| $($f.Section) | $($f.Path)\$($f.Name) | $($f.Expected) | $($f.Actual) |" }
            & $add ''
        }
        if ($defer.Count -gt 0) {
            & $add 'Deferred items are **not** verified yet. Re-run with `-VerifyOnly` after rebooting.'
            & $add ''
        }
    }

    # --- manual checklists ---
    $manual = @($State.Manual)
    if ($manual.Count -gt 0) {
        & $add '## Manual checklists'
        & $add ''
        & $add 'These are not safely scriptable - see each note for why.'
        & $add ''
        foreach ($m in $manual) {
            & $add "### $($m.Title) (section $($m.Section))"
            & $add ''
            if ($m.Detail) { & $add '```'; & $add $m.Detail; & $add '```' }
            else { & $add $m.Reason }
            & $add ''
        }
    }

    # --- startup inventory ---
    if ($State['StartupInventory']) {
        & $add '## Startup inventory (report only)'
        & $add ''
        & $add 'Nothing here was disabled: the script cannot distinguish an anti-cheat component or peripheral driver from bloat.'
        & $add ''
        & $add '| Source | Name | Command |'
        & $add '|---|---|---|'
        foreach ($e in @($State['StartupInventory'])) {
            & $add "| $($e.Source) | $($e.Name) | $(([string]$e.Command) -replace '\|', '\|') |"
        }
        & $add ''
    }

    if ($State['AppxCandidates'] -and @($State['AppxCandidates']).Count -gt 0) {
        & $add '## Removable inbox apps (report only)'
        & $add ''
        & $add 'Not removed. Provisioned package removal is not reliably reversible, and this buys disk space and a few background tasks - **not frames**.'
        & $add ''
        foreach ($a in @($State['AppxCandidates'])) { & $add "- $a" }
        & $add ''
    }

    # --- honest measurement guidance ---
    & $add '## Did this actually help?'
    & $add ''
    & $add 'Be honest with the results. On this machine:'
    & $add ''
    & $add '**Genuinely measurable:**'
    & $add ''
    & $add '- NIC link speed (`Get-NetAdapter | Select Name,LinkSpeed`) - check before and after; if section 7.1 changed Green Ethernet / Gigabit Lite / EEE this is the single most verifiable win available.'
    & $add '- Boot time - `Get-WinEvent -LogName Microsoft-Windows-Diagnostics-Performance/Operational -FilterXPath "*[System[EventID=100]]"`. This is where sections 8.1, 8.5, 8.6 and 8.7 actually pay off.'
    & $add '- Idle committed bytes and process count.'
    & $add '- DPC latency (LatencyMon, 60 s idle + 60 s in a demo) around the section 7 and 2.4 changes.'
    & $add '- Frame-time 1% / 0.1% lows from a **fixed demo playback**, three runs, using PresentMon. Never a live match - it is not repeatable.'
    & $add ''
    & $add '**Not measurable - do not go looking:**'
    & $add ''
    & $add '- Section 4.2 priority separation (Windows already defaults to this behaviour).'
    & $add '- Section 6.3 device queue sizes (unmeasured).'
    & $add '- Section 7.3 Nagle (a TCP tweak; CS2 game traffic is UDP).'
    & $add '- Section 5.4 MMAgent - and if it was already in the target state on this machine, there is literally nothing to measure.'
    & $add '- Every telemetry, policy and app item: disk and RAM hygiene, not frame rate.'
    & $add ''
    & $add 'If a frame-time capture shows nothing outside run-to-run variance, **that is the expected result**, not a failed application.'
    & $add ''

    # --- anti-cheat verification ---
    if ($p.Security.HasKernelAntiCheat) {
        & $add '## Before you play'
        & $add ''
        & $add '1. **Reboot** - several changes only settle after one, and you want the anti-cheat evaluating the final state, not an intermediate one.'
        & $add '2. Re-run with `-VerifyOnly` to resolve the reboot-deferred checks.'
        & $add '3. **Launch the FACEIT AC client on its own, without queueing.** It runs its full system check at startup and shows pass/fail - zero ban surface, and it directly tests the thing you care about.'
        & $add '4. Only queue a match once that passes.'
        & $add ''
        & $add 'Keep measurement tooling (HWiNFO, LatencyMon, PresentMon, RTSS) and anti-cheat sessions strictly non-overlapping. Realistically that is the actual risk in this whole exercise - not the registry tweaks.'
        & $add ''
    }

    & $add '## Undo'
    & $add ''
    & $add '```'
    & $add 'Optimize-CS2.ps1 -Rollback'
    & $add '```'
    & $add ''
    # Built by concatenation rather than interpolation: a backtick is both the
    # markdown code fence and PowerShell's escape character, and mixing them in
    # one double-quoted string produces an unterminated string.
    & $add ('Manifest: `' + $State.Paths.Manifest + '`')
    & $add ''
    & $add 'Registry `.reg` exports under the backup folder are a **manual last resort only**. Rollback is value-level from the manifest: re-importing an exported key would restore values deleted elsewhere and would not delete values added since.'
    & $add ''

    try {
        Set-Content -LiteralPath $State.Paths.Report -Value $sb.ToString() -Encoding UTF8 -ErrorAction Stop
        Write-OptLog -Level Good "Report written to $($State.Paths.Report)"
    }
    catch {
        Write-OptLog -Level Warn "Could not write the report: $($_.Exception.Message)"
    }
}
