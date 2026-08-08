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
