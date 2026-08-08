<#
    Gate evaluation.

    Resolve-OptGates is a PURE function of a plain profile hashtable plus the
    run options. It makes zero live calls, which is what makes the whole
    gating matrix testable against synthetic profiles.

    It runs once after detection and produces, in a single pass:
      - the blocked-section set
      - the decision list (which the 1.5.5 console table and the section 14
        markdown report are both projections of)
      - findings, manual items, capability changes and tier clamping
#>

function Resolve-OptGates {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ProfileData,
        [Parameter(Mandatory)][string]$Tier,
        [System.Collections.IDictionary]$Options = @{},
        [array]$Rows
    )

    if (-not $Rows) { $Rows = Get-OptGateMatrix }

    $result = [ordered]@{
        Tier            = $Tier
        Abort           = $false
        AbortReason     = $null
        BlockedSections = New-Object 'System.Collections.Generic.List[string]'
        Escalated       = New-Object 'System.Collections.Generic.List[string]'
        Capabilities    = [ordered]@{}
        Decisions       = New-Object System.Collections.ArrayList
    }

    foreach ($row in $Rows) {
        $verdict = $null
        # Deliberately NOT named $error - that is the automatic variable holding
        # the session's error collection, and assigning it silently succeeds.
        $predicateError = $null

        try {
            $verdict = ConvertTo-OptBool -Value (& $row.When $ProfileData $Options)
        }
        catch {
            $predicateError = $_.Exception.Message
            $verdict = $null
        }

        $indeterminate = ($null -eq $verdict)

        # An indeterminate predicate resolves through the row's DECLARED policy,
        # never through PowerShell truthiness. This is the mechanism that keeps
        # "unknown means skip, not guess" from depending on how each predicate
        # happened to be written.
        $fires = if ($indeterminate) {
            ([string]$row.OnIndeterminate -eq 'Block')
        }
        else { $verdict }

        $reason = [string]$row.Reason
        if ($indeterminate) {
            $reason = if ($fires) {
                "$reason [indeterminate - blocked per fail-safe rule]"
            }
            else {
                "$reason [indeterminate - allowed per row policy]"
            }
        }
        if ($predicateError) { $reason = "$reason [predicate error: $predicateError]" }

        $kind     = [string]$row.Kind
        $severity = if ($row.Contains('Severity') -and $row.Severity) { [string]$row.Severity } else { 'Info' }
        $effect   = if ($row.Contains('Effect')) { $row.Effect } else { @{} }

        if (-not $fires) {
            [void]$result.Decisions.Add([pscustomobject][ordered]@{
                Id = $row.Id; Section = $row.Section; Title = $row.Title
                Decision = 'On'; Kind = $kind
                Reason = 'gate condition not met'; Severity = 'Info'
                Indeterminate = $indeterminate
            })
            continue
        }

        switch ($kind) {
            'Abort' {
                $result.Abort = $true
                $result.AbortReason = $reason
            }
            'ForceTier' {
                $wanted = [string]$effect['Tier']
                # Only ever clamp DOWNWARD. A gate must not raise the tier the
                # user asked for.
                if ((Get-OptTierRank -Tier $wanted) -lt (Get-OptTierRank -Tier $result.Tier)) {
                    $result.Tier = $wanted
                }
                foreach ($s in @($effect['Skip'])) { if ($s) { $result.BlockedSections.Add([string]$s) } }
            }
            'Skip' {
                foreach ($s in @($effect['Skip'])) { if ($s) { $result.BlockedSections.Add([string]$s) } }
            }
            'Capability' {
                $caps = $effect['Capability']
                if ($caps) {
                    foreach ($k in $caps.Keys) { $result.Capabilities[$k] = $caps[$k] }
                }
                foreach ($s in @($effect['Skip'])) { if ($s) { $result.BlockedSections.Add([string]$s) } }
            }
            'Escalate' {
                foreach ($s in @($effect['Escalate'])) { if ($s) { $result.Escalated.Add([string]$s) } }
            }
        }

        $decision = switch ($kind) {
            'Finding'  { 'Finding' }
            'Manual'   { 'Manual' }
            'Note'     { 'NoOp' }
            # An Escalate row RAISES a section's priority - the opposite of a
            # block - so it must never render under "GATED OFF".
            'Escalate' { 'NoOp' }
            default    { 'Off' }
        }

        [void]$result.Decisions.Add([pscustomobject][ordered]@{
            Id = $row.Id; Section = $row.Section; Title = $row.Title
            Decision = $decision; Kind = $kind
            Reason = $reason; Severity = $severity
            Indeterminate = $indeterminate
        })
    }

    return $result
}

function Set-OptGateResults {
    <#
        Applies a Resolve-OptGates result to the live run state. Split from the
        evaluation itself so the evaluation can stay pure and testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$GateResult
    )

    if ($GateResult.Abort) {
        $State.Aborted     = $true
        $State.AbortReason = $GateResult.AbortReason
    }

    $State.Tier = $GateResult.Tier

    foreach ($s in $GateResult.BlockedSections) { [void]$State.BlockedSections.Add($s) }

    foreach ($k in $GateResult.Capabilities.Keys) {
        $State.Capabilities[$k] = $GateResult.Capabilities[$k]
    }

    foreach ($d in $GateResult.Decisions) {
        # Only surface gates that actually did something. Logging ~45 "condition
        # not met" lines would bury the ones that matter.
        if ($d.Decision -eq 'On') { continue }

        [void](Add-OptDecision -State $State -Id $d.Id -Section $d.Section `
            -Decision $d.Decision -Reason $d.Reason -Title $d.Title -Severity $d.Severity)
    }
}
