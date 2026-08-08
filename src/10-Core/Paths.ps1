<#
    ProgramData layout and path normalization helpers.

        %ProgramData%\cs2-opt\
          manifest.json                     <- spec 1.1 default, latest run
          logs\run-<ts>.log                 <- transcript
          backup\<ts>\*.reg                 <- per-key reg exports
          runs\<ts>-<runid>\
             changes.jsonl                  <- append-and-flush per change
             manifest.json                  <- consolidated
             report.md
#>

function Initialize-OptPaths {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [string]$Root = "$env:ProgramData\cs2-opt",
        [string]$ManifestPath
    )

    $stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $runDir  = Join-Path $Root ("runs\{0}-{1}" -f $stamp, $State.RunId.Substring(0, 8))

    $paths = [ordered]@{
        Root         = $Root
        Logs         = Join-Path $Root 'logs'
        Backup       = Join-Path $Root ("backup\{0}" -f $stamp)
        RunDir       = $runDir
        Journal      = Join-Path $runDir 'changes.jsonl'
        RunManifest  = Join-Path $runDir 'manifest.json'
        Report       = Join-Path $runDir 'report.md'
        Transcript   = Join-Path $Root ("logs\run-{0}.log" -f $stamp)
        Manifest     = if ($ManifestPath) { $ManifestPath } else { Join-Path $Root 'manifest.json' }
        Stamp        = $stamp
    }

    foreach ($d in @($paths.Root, $paths.Logs, $paths.Backup, $paths.RunDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    $State.Paths = $paths
    return $paths
}

function ConvertTo-OptNormalizedPath {
    <#
        Steam's HKCU SteamPath is stored lowercase with FORWARD slashes
        (verified: 'c:/program files (x86)/steam'). Sections 3.3 and 9 use these
        paths as registry value NAMES and Defender exclusion strings, where
        casing and separators both matter - Windows writes the real casing, so
        a lowercase duplicate reads as a second, separate entry.

        Normalize separators, resolve to a full path, then re-case from the
        filesystem when the path actually exists.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $p = $Path.Replace('/', '\').Trim().TrimEnd('\')
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { return $null }

    $trueCase = Get-OptTrueCasePath -Path $p
    if ($trueCase) { return $trueCase.TrimEnd('\') }

    return $p
}

function Get-OptTrueCasePath {
    <#
        Returns the path as the filesystem actually spells it.

        Get-Item does NOT do this - it echoes back whatever casing you handed
        it, so 'c:/program files (x86)/steam' stays lowercase. The only way to
        recover real casing is to ask each parent directory to enumerate the
        child and take the name it reports.

        This matters because section 3.3 writes the cs2.exe path as a registry
        VALUE NAME and section 9 passes library paths to Add-MpPreference.
        Windows writes those with real casing, so a lowercase variant reads as a
        second, separate entry - which breaks idempotency in a way that is
        invisible in the report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if (-not $root) { return $null }

        $rest = $Path.Substring($root.Length).Trim('\')
        if ([string]::IsNullOrEmpty($rest)) { return $root.ToUpperInvariant() }

        $current = $root.ToUpperInvariant()
        foreach ($part in ($rest -split '\\')) {
            $matched = @([System.IO.Directory]::GetFileSystemEntries($current, $part))
            if ($matched.Count -eq 0) { return $null }
            $current = $matched[0]
        }
        return $current
    }
    catch {
        return $null
    }
}

function Test-OptPathUnder {
    <#
        Case-insensitive containment test that is not fooled by a common
        prefix ('C:\Foo' must not be considered under 'C:\FooBar').
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$Parent
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    $a = $Path.TrimEnd('\', '/')
    $b = $Parent.TrimEnd('\', '/')

    if ($a.Equals($b, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $a.StartsWith($b + '\', [StringComparison]::OrdinalIgnoreCase)
}
