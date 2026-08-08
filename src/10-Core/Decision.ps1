<#
    The single decision sink.

    Gate outcomes, tier skips, unsupported-driver-keyword skips,
    already-correct no-ops, hard findings and manual checklist items ALL land
    here. The spec 1.5.5 console table and the spec 14 markdown report are
    projections of this one list.

    That is what makes "the report is generated from the same source of truth
    as the gates" a structural property rather than an aspiration - there is no
    second place to record why something did or did not happen.
#>

function Add-OptDecision {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,

        # Stable identifier, e.g. 'G-2.2-X3D' (gate) or 'S-7.1-RSS' (section).
        [Parameter(Mandatory)][string]$Id,

        [Parameter(Mandatory)][string]$Section,

        # On            - gate evaluated, tweak permitted
        # Off           - gate blocked it (carries the reason)
        # NoOp          - already in the desired state; NOT a change
        # Applied       - a change record was emitted
        # Finding       - a problem to fix, not a tweak (e.g. VBS off on FACEIT)
        # Manual        - checklist item for the user
        # Failed        - attempted and errored
        # Unverified    - applied but effect cannot be confirmed on this build
        [Parameter(Mandatory)]
        [ValidateSet('On', 'Off', 'NoOp', 'Applied', 'Finding', 'Manual', 'Failed', 'Unverified')]
        [string]$Decision,

        [Parameter(Mandatory)][AllowEmptyString()][string]$Reason,

        [string]$Title,
        [string]$Detail,

        [ValidateSet('Info', 'Warning', 'Error', 'Critical')]
        [string]$Severity = 'Info'
    )

    $entry = [pscustomobject][ordered]@{
        Id        = $Id
        Section   = $Section
        Title     = $Title
        Decision  = $Decision
        Reason    = $Reason
        Detail    = $Detail
        Severity  = $Severity
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    }

    [void]$State.Decisions.Add($entry)

    if ($Decision -eq 'Finding') {
        [void]$State.Findings.Add($entry)
    }
    elseif ($Decision -eq 'Manual') {
        [void]$State.Manual.Add($entry)
    }

    # Echo the outcomes worth watching scroll past.
    #
    # NoOp and Off stay silent on purpose: they are the overwhelming majority
    # (roughly 110 of ~200 decisions on a typical run) and printing them would
    # bury the handful of lines that actually matter. They are still counted in
    # the per-section summary and listed in full in the markdown report.
    if ($State['ConsoleDecisions']) {
        # Lead with the Title, which names the setting. The Reason alone is
        # frequently not self-describing - "would set to 100 (currently 0)"
        # tells you nothing about WHAT is being set.
        #
        # Where the reason ends in "= <value>", collapse to "<Title> = <value>":
        # the registry path is already implied by the title, and the value is
        # the part worth reading. Otherwise keep the reason as a suffix.
        $line = if ($Title -and $Reason -match '=\s*([^=]+)$') {
            '{0} = {1}' -f $Title, $Matches[1].Trim()
        }
        elseif ($Title -and $Reason) { '{0} - {1}' -f $Title, $Reason }
        elseif ($Title)              { [string]$Title }
        else                         { [string]$Reason }

        if ($line.Length -gt 104) { $line = $line.Substring(0, 101) + '...' }

        switch ($Decision) {
            'Applied'    { Write-Host ('    + {0,-6} {1}' -f $Section, $line) -ForegroundColor DarkGray }
            'Failed'     { Write-Host ('    ! {0,-6} {1}' -f $Section, $line) -ForegroundColor Red }
            'Finding'    { Write-Host ('    ! {0,-6} {1}' -f $Section, $line) -ForegroundColor Yellow }
            'Unverified' { Write-Host ('    ? {0,-6} {1}' -f $Section, $line) -ForegroundColor DarkYellow }
        }
    }

    return $entry
}

function Add-OptFinding {
    <#
        A hard finding is a problem the user must fix, not a tweak that
        succeeded. Spec 10.2: on a FACEIT machine with VBS not running, the
        correct output is a blocking problem - never "optimized".
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Reason,
        [string]$Detail,
        [ValidateSet('Warning', 'Error', 'Critical')][string]$Severity = 'Error'
    )

    return Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Finding' `
        -Title $Title -Reason $Reason -Detail $Detail -Severity $Severity
}

function Add-OptManual {
    <#
        Checklist item the script deliberately does not automate - AMD Adrenalin
        and the NVIDIA profile store are opaque binary blobs (spec 3.4 / 3.5),
        Steam's localconfig.vdf is cached in memory and overwritten on exit
        (spec 11.1), and BIOS settings are not scriptable at all (spec 12).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [string]$Reason = 'not safely scriptable - see report checklist'
    )

    return Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Manual' `
        -Title $Title -Reason $Reason -Detail $Detail -Severity 'Info'
}

function Write-OptSectionSummary {
    <#
        One tally line per section, so the outcomes that are deliberately not
        echoed individually (already-correct and gated-off) are still visible
        as counts rather than vanishing.

        Counts only section decisions (S-*), not gate rows (G-*) - the gate
        matrix already reported itself in the detection report, and folding it
        in here would double-count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Section
    )

    if (-not $State['ConsoleDecisions']) { return }

    $rows = @($State.Decisions | Where-Object {
        $_.Id -like 'S-*' -and (Test-OptSectionMatch -Section $_.Section -Patterns @($Section))
    })
    if ($rows.Count -eq 0) {
        Write-Host '    (nothing applicable on this machine)' -ForegroundColor DarkGray
        return
    }

    $applied = @($rows | Where-Object { $_.Decision -eq 'Applied' }).Count
    $noop    = @($rows | Where-Object { $_.Decision -eq 'NoOp'    }).Count
    $off     = @($rows | Where-Object { $_.Decision -eq 'Off'     }).Count
    $failed  = @($rows | Where-Object { $_.Decision -eq 'Failed'  }).Count

    $verb = if ($State.DryRun) { 'planned' } else { 'applied' }
    $parts = @("$applied $verb")
    if ($noop   -gt 0) { $parts += "$noop already correct" }
    if ($off    -gt 0) { $parts += "$off skipped" }
    if ($failed -gt 0) { $parts += "$failed FAILED" }

    Write-Host ('    -> ' + ($parts -join ', ')) -ForegroundColor $(if ($failed -gt 0) { 'Yellow' } else { 'DarkCyan' })
}

function Get-OptDecisionsBySection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [string]$Section
    )

    # Leading comma survives PowerShell's single-element return unroll, so
    # callers always get an array to .Count / iterate.
    if ($Section) {
        return , @($State.Decisions | Where-Object { $_.Section -eq $Section })
    }
    return , @($State.Decisions)
}
