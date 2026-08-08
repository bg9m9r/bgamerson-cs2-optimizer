<#
    Tier gating and section enablement.

    Tiers are cumulative (spec 1.2.10): Aggressive includes Safe, Experimental
    includes both. 'Manual' and 'Report' are pseudo-tiers that always run -
    they emit text, never changes.
#>

function Get-OptTierRank {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Tier)

    switch ($Tier) {
        'Safe'         { return 0 }
        'Aggressive'   { return 1 }
        'Experimental' { return 2 }
        'Manual'       { return -1 }
        'Report'       { return -1 }
        default        { return 99 }
    }
}

function Test-OptTier {
    <#
        Is a tweak tagged $Required permitted at the run's configured tier?
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Required
    )

    $req = Get-OptTierRank -Tier $Required
    if ($req -lt 0) { return $true }          # Manual / Report always run
    if ($req -eq 99) { return $false }        # unknown tag - fail closed

    return ($req -le (Get-OptTierRank -Tier $State.Tier))
}

function Test-OptSectionEnabled {
    <#
        Section gating, in precedence order:
          1. -Sections        (allow-list; if given, nothing else runs)
          2. -ExcludeSections (deny-list)
          3. BlockedSections  (populated by the gate matrix)

        Matching is PREFIX-based on the dotted section number, so blocking '8'
        blocks 8.1 through 8.9, while blocking '3.5' blocks only 3.5. Without
        prefix matching, a gate row that blocks a whole section would have to
        enumerate every subsection by hand.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Section
    )

    $only    = $State.Parameters['Sections']
    $exclude = $State.Parameters['ExcludeSections']

    if ($only -and $only.Count -gt 0) {
        if (-not (Test-OptSectionMatch -Section $Section -Patterns $only)) { return $false }
    }

    if ($exclude -and $exclude.Count -gt 0) {
        if (Test-OptSectionMatch -Section $Section -Patterns $exclude) { return $false }
    }

    foreach ($blocked in $State.BlockedSections) {
        if (Test-OptSectionMatch -Section $Section -Patterns @($blocked)) { return $false }
    }

    return $true
}

function Test-OptSectionMatch {
    <#
        '8' matches '8', '8.1', '8.10'.  '3.5' matches '3.5' and '3.5.1' but
        NOT '3.55' - the boundary check on the next character is what stops
        '3.5' from swallowing '3.55'.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Patterns
    )

    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }

        # Strip any leading non-digit prefix so '7', 'S7', 's7' and the section
        # symbol all mean the same thing. Done with a regex rather than a
        # TrimStart char list on purpose: the section symbol is non-ASCII, and
        # Windows PowerShell 5.1 reads a BOM-less file as ANSI - so the literal
        # would arrive as two characters and TrimStart would throw.
        $p = ($pat.Trim() -replace '^[^\d]+', '').Trim()

        if ($Section.Equals($p, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($Section.StartsWith($p + '.', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Block-OptSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Section
    )
    [void]$State.BlockedSections.Add($Section)
}

function Test-OptCapability {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not $State.Capabilities.Contains($Name)) { return $false }
    return [bool]$State.Capabilities[$Name]
}
