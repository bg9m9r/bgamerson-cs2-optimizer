function Write-OptRunSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SUMMARY'

    $applied = @($State.Decisions | Where-Object { $_.Decision -eq 'Applied' })
    $noop    = @($State.Decisions | Where-Object { $_.Decision -eq 'NoOp' })
    $off     = @($State.Decisions | Where-Object { $_.Decision -eq 'Off' })
    $failed  = @($State.Decisions | Where-Object { $_.Decision -eq 'Failed' })

    if ($State.DryRun) {
        Write-OptLog -Level Info "DRY RUN - $($applied.Count) change(s) would be made. Nothing was modified."
    }
    else {
        Write-OptLog -Level Good "$($State.Changes.Count) change(s) applied and recorded"
    }

    Write-OptLog -Level Plain ("  already correct : {0}" -f $noop.Count)
    Write-OptLog -Level Plain ("  gated off       : {0}" -f $off.Count)
    if ($failed.Count -gt 0) {
        Write-OptLog -Level Warn ("  failed          : {0}" -f $failed.Count)
        foreach ($f in $failed) { Write-OptLog -Level Detail "$($f.Section) $($f.Title): $($f.Reason)" }
    }

    $findings = @($State.Findings)
    if ($findings.Count -gt 0) {
        Write-OptLog -Level Header 'FINDINGS - fix these; they are not tweaks that succeeded'
        foreach ($f in $findings) {
            $lvl = switch ($f.Severity) { 'Critical' { 'Error' } 'Error' { 'Error' } default { 'Warn' } }
            Write-OptLog -Level $lvl "[$($f.Section)] $($f.Title)"
            Write-OptLog -Level Detail $f.Reason
        }
    }

    if (@($State.Manual).Count -gt 0) {
        Write-OptLog -Level Info "$(@($State.Manual).Count) manual checklist item(s) - see the report for the full text"
    }

    if ($State.RebootRequired) { Write-OptLog -Level Warn 'A REBOOT is required for some changes to take effect.' }
    if ($State.LogoffRequired) { Write-OptLog -Level Warn 'A SIGN-OUT is required for some shell/input changes to take effect.' }

    if (-not $State.DryRun -and $State.Paths) {
        Write-OptLog -Level Header 'ARTEFACTS'
        Write-OptLog -Level Plain "  report   : $($State.Paths.Report)"
        Write-OptLog -Level Plain "  manifest : $($State.Paths.Manifest)"
        Write-OptLog -Level Plain "  log      : $($State.Paths.Transcript)"
        Write-OptLog -Level Plain ''
        Write-OptLog -Level Plain '  To undo everything this run did:'
        Write-OptLog -Level Plain "      Optimize-CS2.ps1 -Rollback"
        Write-OptLog -Level Plain '  To re-verify after rebooting (reboot-deferred changes):'
        Write-OptLog -Level Plain "      Optimize-CS2.ps1 -VerifyOnly"
    }
}
