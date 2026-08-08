<#
    Section 14 markdown report.

    Contains: applied changes by tier, skipped changes and why, the manual
    checklists, security tradeoffs accepted, the reboot flag, and the rollback
    command - all projected from the single decision list.
#>

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

    # --- applied changes by tier ---
    & $add '## Changes'
    & $add ''
    $applied = @($State.Decisions | Where-Object { $_.Decision -eq 'Applied' })
    if ($applied.Count -eq 0) {
        & $add '_No changes were applied._'
        & $add ''
    }
    else {
        & $add "$($applied.Count) change(s)$(if ($State.DryRun) { ' would be applied' } else { ' applied' }):"
        & $add ''
        & $add '| Section | Change | Detail |'
        & $add '|---|---|---|'
        foreach ($a in $applied) {
            & $add "| $($a.Section) | $($a.Title) | $($a.Reason -replace '\|', '\|') |"
        }
        & $add ''
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
