function Get-OptGamesSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        SteamPath = $null; LibraryPaths = @(); Cs2ExePath = $null
        Cs2Installed = $null; Cs2LibraryPath = $null; Cs2LibraryMediaType = 'Unknown'
    }
}

function ConvertFrom-OptVdf {
    <#
        Minimal tokenizer for Valve's KeyValues format.

        A tokenizer rather than a regex because libraryfolders.vdf stores paths
        with escaped backslashes ("D:\\Games\\Steam") and the v2 format nests an
        "apps" block inside each library entry. A regex over quoted pairs
        happily matches the app-id/size pairs inside "apps" and mixes them into
        the library list.

        Returns nested ordered hashtables.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $result = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $result }

    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push($result)
    $pendingKey = $null

    $i = 0
    $len = $Text.Length
    while ($i -lt $len) {
        $ch = $Text[$i]

        if ($ch -eq '"') {
            # Quoted token, honouring backslash escapes.
            $sb = New-Object System.Text.StringBuilder
            $i++
            while ($i -lt $len -and $Text[$i] -ne '"') {
                if ($Text[$i] -eq '\' -and ($i + 1) -lt $len) {
                    $i++
                    switch ($Text[$i]) {
                        'n'     { [void]$sb.Append("`n") }
                        't'     { [void]$sb.Append("`t") }
                        '\'     { [void]$sb.Append('\') }
                        '"'     { [void]$sb.Append('"') }
                        default { [void]$sb.Append($Text[$i]) }
                    }
                }
                else { [void]$sb.Append($Text[$i]) }
                $i++
            }
            $i++
            $token = $sb.ToString()

            if ($null -eq $pendingKey) { $pendingKey = $token }
            else {
                $stack.Peek()[$pendingKey] = $token
                $pendingKey = $null
            }
            continue
        }

        if ($ch -eq '{') {
            $child = [ordered]@{}
            if ($null -ne $pendingKey) {
                $stack.Peek()[$pendingKey] = $child
                $pendingKey = $null
            }
            $stack.Push($child)
            $i++
            continue
        }

        if ($ch -eq '}') {
            if ($stack.Count -gt 1) { [void]$stack.Pop() }
            $i++
            continue
        }

        # Line comments
        if ($ch -eq '/' -and ($i + 1) -lt $len -and $Text[$i + 1] -eq '/') {
            while ($i -lt $len -and $Text[$i] -ne "`n") { $i++ }
            continue
        }

        $i++
    }

    return $result
}

function Get-OptGamesInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$StorageInfo
    )

    return Invoke-OptDetector -State $State -Name 'Games' -UnknownSkeleton (Get-OptGamesSkeleton) -ScriptBlock {
        # Never hardcode C:\Program Files (x86)\Steam. On the reference machine
        # this value reads 'c:/program files (x86)/steam' - lowercase, with
        # FORWARD slashes - which is why it goes through path normalization
        # before being used anywhere.
        $raw = Get-OptRegValueSafe -Hive HKCU -SubKey 'Software\Valve\Steam' -Name 'SteamPath'
        if (-not $raw) {
            $raw = Get-OptRegValueSafe -Hive HKLM -SubKey 'SOFTWARE\WOW6432Node\Valve\Steam' -Name 'InstallPath'
        }

        $steamPath = ConvertTo-OptNormalizedPath -Path ([string]$raw)
        if (-not $steamPath -or -not (Test-Path -LiteralPath $steamPath)) {
            return [ordered]@{
                SteamPath = $null; LibraryPaths = @(); Cs2ExePath = $null
                Cs2Installed = $false; Cs2LibraryPath = $null; Cs2LibraryMediaType = 'Unknown'
            }
        }

        # --- libraries --------------------------------------------------------
        $libraries = @($steamPath)
        $vdfPath = Join-Path $steamPath 'steamapps\libraryfolders.vdf'
        if (Test-Path -LiteralPath $vdfPath) {
            $parsed = ConvertFrom-OptVdf -Text (Get-Content -LiteralPath $vdfPath -Raw -ErrorAction SilentlyContinue)
            $root = $null
            foreach ($k in $parsed.Keys) {
                if ($k -match '^libraryfolders$') { $root = $parsed[$k]; break }
            }
            if (-not $root) { $root = $parsed }

            foreach ($k in $root.Keys) {
                $entry = $root[$k]
                if ($entry -is [System.Collections.IDictionary] -and $entry.Contains('path')) {
                    $p = ConvertTo-OptNormalizedPath -Path ([string]$entry['path'])
                    if ($p -and (Test-Path -LiteralPath $p)) { $libraries += $p }
                }
            }
        }
        $libraries = @($libraries | Sort-Object -Unique)

        # --- CS2 (appid 730) --------------------------------------------------
        $cs2Exe = $null
        $cs2Library = $null
        foreach ($lib in $libraries) {
            $candidate = Join-Path $lib 'steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe'
            if (Test-Path -LiteralPath $candidate) {
                # Re-case from the filesystem: section 3.3 uses this string as a
                # registry VALUE NAME, and Windows writes it with real casing -
                # a lowercase duplicate would read as a separate entry.
                $cs2Exe = (Get-Item -LiteralPath $candidate).FullName
                $cs2Library = $lib
                break
            }
        }

        $mediaType = 'Unknown'
        if ($cs2Library -and $StorageInfo -and $StorageInfo.Volumes) {
            $letter = ($cs2Library.Substring(0, 1))
            $vol = $StorageInfo.Volumes | Where-Object { $_.DriveLetter -eq $letter } | Select-Object -First 1
            if ($vol) { $mediaType = $vol.MediaType }
        }

        [ordered]@{
            SteamPath           = $steamPath
            LibraryPaths        = $libraries
            Cs2ExePath          = $cs2Exe
            Cs2Installed        = ($null -ne $cs2Exe)
            Cs2LibraryPath      = $cs2Library
            Cs2LibraryMediaType = $mediaType
        }
    }
}
