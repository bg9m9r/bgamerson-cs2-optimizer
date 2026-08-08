<#
    Section 9 - Defender exclusions.

    Real-time scanning of shader-cache writes and VPK reads is a measurable
    stutter source. Exclusions get most of the benefit of "disable Defender"
    with none of the trust-signal cost - real-time protection stays ON, which
    section 0 requires.

    Deliberately NOT excluded: FACEIT's own directories. Leave the anti-cheat's
    footprint scanned.
#>

function Invoke-OptSection09 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 9 - Defender exclusions'

    if (-not (Test-OptSectionEnabled -State $State -Section '9')) {
        [void](Add-OptDecision -State $State -Id 'S-9' -Section '9' -Decision 'Off' `
            -Title 'Defender exclusions' -Reason 'section gated off')
        return
    }
    if (-not (Test-OptTier -State $State -Required 'Aggressive')) {
        [void](Add-OptDecision -State $State -Id 'S-9' -Section '9' -Decision 'Off' `
            -Title 'Defender exclusions' -Reason 'requires tier Aggressive')
        return
    }

    $p = $State.Profile

    $current = $null
    try { $current = Get-MpPreference -ErrorAction Stop }
    catch {
        [void](Add-OptDecision -State $State -Id 'S-9-PREF' -Section '9' -Decision 'Failed' `
            -Title 'Defender exclusions' -Severity 'Warning' `
            -Reason "could not read Defender preferences: $($_.Exception.Message)")
        return
    }

    # Get-MpPreference returns $null - not @() - when a list is empty, so .Count
    # would throw under StrictMode without the wrap.
    $existingPaths     = @($current.ExclusionPath)
    $existingProcesses = @($current.ExclusionProcess)

    $paths = New-Object System.Collections.ArrayList
    foreach ($lib in @($p.Games.LibraryPaths)) { if ($lib) { [void]$paths.Add([string]$lib) } }

    # Vendor shader cache. Only the detected vendor's path is added - adding an
    # NVIDIA cache path on an AMD machine would be a meaningless exclusion.
    switch ($p.GPU.PrimaryVendor) {
        'AMD'    { [void]$paths.Add("$env:LOCALAPPDATA\AMD") }
        'NVIDIA' { [void]$paths.Add("$env:LOCALAPPDATA\NVIDIA"); [void]$paths.Add("$env:LOCALAPPDATA\NVIDIA Corporation") }
        'Intel'  { [void]$paths.Add("$env:LOCALAPPDATA\Intel") }
    }

    foreach ($path in $paths) {
        $normalized = ConvertTo-OptNormalizedPath -Path $path
        if (-not $normalized) { continue }

        if (@($existingPaths | Where-Object { [string]$_ -eq $normalized }).Count -gt 0) {
            [void](Add-OptDecision -State $State -Id "S-9-PATH-$normalized" -Section '9' -Decision 'NoOp' `
                -Title 'Defender path exclusion' -Reason "already excluded: $normalized")
            continue
        }

        $r = Invoke-OptCmdletChange -State $State -Description "Add-MpPreference -ExclusionPath $normalized" -Action {
            Add-MpPreference -ExclusionPath $normalized -ErrorAction Stop
        }

        if (-not $r.Success) {
            [void](Add-OptDecision -State $State -Id "S-9-PATH-$normalized" -Section '9' -Decision 'Failed' `
                -Title 'Defender path exclusion' -Severity 'Warning' `
                -Reason "$($r.Error) - Tamper Protection can silently reject exclusion changes")
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'DefenderExclusion' -Section '9' -Tier 'Aggressive' `
            -Path 'Defender' -Name $normalized -Target @{ Kind = 'Path' } `
            -OldValue $null -NewValue $normalized -ExistedBefore $false
        if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

        [void](Add-OptDecision -State $State -Id "S-9-PATH-$normalized" -Section '9' -Decision 'Applied' `
            -Title 'Defender path exclusion' -Reason "excluded $normalized")
    }

    # Process exclusions. cs2.exe only if CS2 is actually installed.
    $processes = @('steam.exe', 'steamwebhelper.exe')
    if ($p.Games.Cs2Installed) { $processes = @('cs2.exe') + $processes }

    foreach ($proc in $processes) {
        if (@($existingProcesses | Where-Object { [string]$_ -eq $proc }).Count -gt 0) {
            [void](Add-OptDecision -State $State -Id "S-9-PROC-$proc" -Section '9' -Decision 'NoOp' `
                -Title 'Defender process exclusion' -Reason "already excluded: $proc")
            continue
        }

        $r = Invoke-OptCmdletChange -State $State -Description "Add-MpPreference -ExclusionProcess $proc" -Action {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
        }

        if (-not $r.Success) {
            [void](Add-OptDecision -State $State -Id "S-9-PROC-$proc" -Section '9' -Decision 'Failed' `
                -Title 'Defender process exclusion' -Severity 'Warning' -Reason $r.Error)
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'DefenderExclusion' -Section '9' -Tier 'Aggressive' `
            -Path 'Defender' -Name $proc -Target @{ Kind = 'Process' } `
            -OldValue $null -NewValue $proc -ExistedBefore $false
        if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

        [void](Add-OptDecision -State $State -Id "S-9-PROC-$proc" -Section '9' -Decision 'Applied' `
            -Title 'Defender process exclusion' -Reason "excluded $proc")
    }

    [void](Add-OptDecision -State $State -Id 'S-9-NOTE' -Section '9' -Decision 'NoOp' `
        -Title 'Defender scope' `
        -Reason 'real-time protection stays ON and FACEIT directories are deliberately left scanned - only game asset and shader-cache paths are excluded')
}
