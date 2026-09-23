<#
    Release update check.

    One HTTPS GET to GitHub's releases API, compared against the version
    constant baked into the header. Non-blocking by design: a short timeout,
    every failure swallowed into a one-line note, and never run for -Rollback
    or -ProfileFrom (an undo or a replay must not depend on the network) or
    with -NoUpdateCheck. It only ever ASKS for a version number - nothing is
    downloaded or installed, and nothing about the machine is sent.
#>

function Compare-OptReleaseVersion {
    <#
        Pure comparison so the decision is testable without the network.
        Newer is $true / $false, or $null when either side does not parse
        (a garbage tag must never produce "update available").
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [AllowNull()][AllowEmptyString()][string]$Current,
        [AllowNull()][AllowEmptyString()][string]$Latest
    )

    $parse = {
        param($s)
        $text = ([string]$s).Trim() -replace '^[vV]', ''
        $v = $null
        if ([version]::TryParse($text, [ref]$v)) { return $v }
        return $null
    }

    $c = & $parse $Current
    $l = & $parse $Latest
    if ($null -eq $c -or $null -eq $l) {
        return @{ Newer = $null; Current = $c; Latest = $l }
    }
    return @{ Newer = ($l -gt $c); Current = $c; Latest = $l }
}

function Get-OptLatestRelease {
    <#
        The one network call. Kept separate so the caller can be tested with
        this function mocked. Throws on any failure; the caller turns that
        into a note.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([int]$TimeoutSec = 5)

    # Windows PowerShell 5.1 can still default to TLS 1.0, which GitHub
    # rejects. OR the flag in rather than replacing the set.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }

    $previousProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $r = Invoke-RestMethod -Uri 'https://api.github.com/repos/bg9m9r/bgamerson-cs2-optimizer/releases/latest' `
            -Headers @{ 'User-Agent' = 'bgamerson-cs2-optimizer'; 'Accept' = 'application/vnd.github+json' } `
            -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
    }
    finally { $ProgressPreference = $previousProgress }

    return @{ TagName = [string]$r.tag_name; Url = [string]$r.html_url }
}

function Invoke-OptUpdateCheck {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][AllowEmptyString()][string]$CurrentVersion
    )

    $result = [ordered]@{ Checked = $false; Newer = $null; Latest = $null; Url = $null; Note = $null }

    try {
        $rel = Get-OptLatestRelease
        $cmp = Compare-OptReleaseVersion -Current $CurrentVersion -Latest $rel.TagName

        $result.Checked = $true
        $result.Latest  = $rel.TagName
        $result.Url     = $rel.Url
        $result.Newer   = $cmp.Newer

        if ($cmp.Newer -eq $true) {
            Write-OptLog -Level Warn "A newer release is available: $($rel.TagName) (this is v$CurrentVersion) - $($rel.Url)"
            Write-OptLog -Level Detail 'The one-liner in the README fetches the latest release. This run continues with the version you have.'
        }
        elseif ($cmp.Newer -eq $false -and $cmp.Latest -lt $cmp.Current) {
            # A source build past the last tag. Say so rather than claiming
            # a release that does not exist yet.
            Write-OptLog -Level Detail "Update check: v$CurrentVersion is ahead of the latest release ($($rel.TagName))"
        }
        elseif ($cmp.Newer -eq $false) {
            Write-OptLog -Level Good "Up to date: v$CurrentVersion is the latest release"
        }
        else {
            Write-OptLog -Level Detail "Update check: could not compare v$CurrentVersion with '$($rel.TagName)'"
        }
    }
    catch {
        # Offline, proxy, rate-limited, DNS - none of it matters to the run.
        $result.Note = $_.Exception.Message
        Write-OptLog -Level Detail "Update check skipped (no answer from GitHub): $($_.Exception.Message)"
    }

    $State['UpdateCheck'] = $result
    return $result
}
