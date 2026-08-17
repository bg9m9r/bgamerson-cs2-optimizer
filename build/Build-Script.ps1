<#
.SYNOPSIS
    Concatenates the src tree into one distributable script, enforcing the
    invariants the tests rely on.

.DESCRIPTION
    The AST gates are the point of this script. They keep architectural rules
    mechanical rather than aspirational:

      1. every file parses
      2. only the header and main file may contain top-level statements, so
         tests can dot-source any single file with no side effects
      3. nothing assigns to $Profile (a PowerShell AUTOMATIC VARIABLE - the
         assignment silently succeeds, which is worse than an error)
      4. every ConvertTo-Json call passes -Depth (the default is 2, which would
         silently destroy the profile and every rollback record)
      5. native tools are only invoked through the chokepoint in Invoke.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipAnalyzer,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'build.psd1')

function Write-BuildLog {
    param([string]$Message, [string]$Level = 'Info')
    if ($Quiet -and $Level -eq 'Info') { return }
    $colour = switch ($Level) { 'Error' { 'Red' } 'Warn' { 'Yellow' } 'Good' { 'Green' } default { 'Gray' } }
    Write-Host $Message -ForegroundColor $colour
}

$errors = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------
# Gate 1-5: AST checks
# ---------------------------------------------------------------------------
$topLevelAllowed = @($manifest.TopLevelAllowed)
$platformFiles   = @($manifest.PlatformFiles)

$nativeTools = @('reg', 'reg.exe', 'powercfg', 'powercfg.exe', 'bcdedit', 'bcdedit.exe',
                 'netsh', 'netsh.exe', 'fsutil', 'fsutil.exe', 'dsregcmd', 'dsregcmd.exe', 'wsl', 'wsl.exe')

foreach ($rel in $manifest.Files) {
    $path = Join-Path $repoRoot $rel
    if (-not (Test-Path -LiteralPath $path)) {
        [void]$errors.Add("MISSING: $rel")
        continue
    }

    # --- gate 6: ASCII only ---
    # Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so a non-ASCII
    # literal in the source silently becomes mojibake in the built artifact -
    # and a two-character string where the code expected one character throws at
    # runtime, far from the cause. Keeping the sources pure ASCII removes the
    # entire failure mode.
    $rawBytes = [System.IO.File]::ReadAllBytes($path)
    $rawText  = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    foreach ($m in [regex]::Matches($rawText, '[^\x00-\x7F]')) {
        $lineNo = ($rawText.Substring(0, $m.Index) -split "`n").Count
        [void]$errors.Add(("NONASCII {0} line {1}: U+{2:X4} - keep sources ASCII-only" -f $rel, $lineNo, [int][char]$m.Value))
        break
    }

    $parseErrors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors) {
        foreach ($e in $parseErrors) {
            [void]$errors.Add("PARSE $rel line $($e.Extent.StartLineNumber): $($e.Message)")
        }
        continue
    }

    # --- gate 2: top-level statements ---
    if ($topLevelAllowed -notcontains $rel) {
        foreach ($stmt in $ast.EndBlock.Statements) {
            if ($stmt -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                [void]$errors.Add("TOPLEVEL $rel line $($stmt.Extent.StartLineNumber): only function definitions are allowed outside the header/main files (tests dot-source these)")
            }
        }
    }

    # --- gate 3: $Profile assignment ---
    $assignments = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
    foreach ($a in $assignments) {
        $left = $a.Left.Extent.Text
        if ($left -match '^\$(Profile|Host|PSHome|PID|Error|Args|Input|Matches|PSItem)$') {
            [void]$errors.Add("AUTOVAR $rel line $($a.Extent.StartLineNumber): assignment to the automatic variable $left")
        }
    }

    # --- gate 4: ConvertTo-Json without -Depth ---
    $commands = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $commands) {
        $name = $c.GetCommandName()
        if ($name -eq 'ConvertTo-Json') {
            $hasDepth = $false
            foreach ($el in $c.CommandElements) {
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -like 'Depth*') {
                    $hasDepth = $true
                }
            }
            if (-not $hasDepth) {
                [void]$errors.Add("JSONDEPTH $rel line $($c.Extent.StartLineNumber): ConvertTo-Json without -Depth (the default of 2 silently truncates)")
            }
        }

        # --- gate 5: native tools outside the chokepoint ---
        if ($name -and ($nativeTools -contains $name.ToLowerInvariant())) {
            if ($platformFiles -notcontains $rel) {
                [void]$errors.Add("NATIVE $rel line $($c.Extent.StartLineNumber): '$name' invoked directly - route it through Invoke-OptNativeCommand")
            }
        }
    }
}

if ($errors.Count -gt 0) {
    Write-BuildLog "BUILD FAILED - $($errors.Count) gate violation(s):" 'Error'
    foreach ($e in $errors) { Write-BuildLog "  $e" 'Error' }
    exit 1
}
Write-BuildLog "AST gates passed ($($manifest.Files.Count) files)" 'Good'

# ---------------------------------------------------------------------------
# PSScriptAnalyzer
# ---------------------------------------------------------------------------
if (-not $SkipAnalyzer -and (Get-Module -ListAvailable PSScriptAnalyzer)) {
    Import-Module PSScriptAnalyzer -Force
    $findings = Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot 'src') -Recurse `
        -Settings (Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1')
    if ($findings) {
        Write-BuildLog "PSScriptAnalyzer: $($findings.Count) finding(s)" 'Warn'
        $findings | ForEach-Object {
            Write-BuildLog ("  [{0}] {1}:{2} {3}" -f $_.Severity, $_.ScriptName, $_.Line, $_.Message) 'Warn'
        }
    }
    else { Write-BuildLog 'PSScriptAnalyzer: clean' 'Good' }
}

# ---------------------------------------------------------------------------
# Concatenate
# ---------------------------------------------------------------------------
$outScript = Join-Path $repoRoot $manifest.OutputScript
$outCmd    = Join-Path $repoRoot $manifest.OutputCmd
$outDir    = Split-Path -Parent $outScript
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$sb = New-Object System.Text.StringBuilder
$hashes = New-Object System.Collections.ArrayList

foreach ($rel in $manifest.Files) {
    $path = Join-Path $repoRoot $rel
    $content = Get-Content -LiteralPath $path -Raw

    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    # Extra parentheses are required: inside a method call the comma would
    # otherwise split this into two arguments to .Add() rather than feeding both
    # values to -f.
    [void]$hashes.Add(("{0}  {1}" -f $hash.Substring(0, 16), $rel))

    # The header must stay first and unwrapped - #Requires and param() are only
    # valid at the very top of a script.
    if ($rel -eq 'src\00-Header.ps1') {
        [void]$sb.AppendLine($content.TrimEnd())
        [void]$sb.AppendLine()
        continue
    }

    [void]$sb.AppendLine("#region $rel")
    [void]$sb.AppendLine($content.TrimEnd())
    [void]$sb.AppendLine("#endregion $rel")
    [void]$sb.AppendLine()
}

$full = $sb.ToString()
$sourceHash = [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($full))
).Replace('-', '').ToLowerInvariant()

# Insert the provenance banner after the header's param block so #Requires stays
# at the top of the file.
$banner = @"

# ============================================================================
#  cs2-opt - built artifact. DO NOT EDIT THIS FILE.
#  Edit the sources under src\ and re-run build\Build-Script.ps1.
#
#  Source hash: sha256:$sourceHash
#  Files:
$(($hashes | ForEach-Object { "#    $_" }) -join "`n")
# ============================================================================

"@

$full = $full -replace '(?m)^(\}\r?\n)(\r?\n)?(#region src\\10-Core\\State\.ps1)', "`$1$banner`$3"

Set-Content -LiteralPath $outScript -Value $full -Encoding UTF8
Set-Content -LiteralPath $outCmd -Encoding ASCII -Value @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Optimize-CS2.ps1" %*
'@

$lines = ($full -split "`r?`n").Count
Write-BuildLog "Built $outScript ($lines lines, sha256:$($sourceHash.Substring(0,16)))" 'Good'

# ---------------------------------------------------------------------------
# Launcher: a standalone script, copied (not concatenated). It still has to
# parse and stay ASCII, so run it through the same two gates.
# ---------------------------------------------------------------------------
$launcherSrc = Join-Path $repoRoot 'launcher\Launch-CS2.ps1'
if (Test-Path -LiteralPath $launcherSrc) {
    $launcherErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($launcherSrc, [ref]$null, [ref]$launcherErrors)
    if ($launcherErrors) {
        Write-BuildLog 'BUILD FAILED - launcher does not parse:' 'Error'
        foreach ($e in $launcherErrors) { Write-BuildLog "  line $($e.Extent.StartLineNumber): $($e.Message)" 'Error' }
        exit 1
    }
    $launcherText = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($launcherSrc))
    if ($launcherText -match '[^\x00-\x7F]') {
        Write-BuildLog 'BUILD FAILED - launcher contains non-ASCII characters' 'Error'
        exit 1
    }

    Copy-Item -LiteralPath $launcherSrc -Destination (Join-Path $repoRoot 'dist\Launch-CS2.ps1') -Force
    # Double-click friendly: on success the window closes itself (the game is
    # starting, nobody needs a console); on failure it pauses so the message
    # does not vanish with the window.
    Set-Content -LiteralPath (Join-Path $repoRoot 'dist\Launch-CS2.cmd') -Encoding ASCII -Value @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-CS2.ps1" %*
if errorlevel 1 (
    echo.
    pause
)
'@
    Write-BuildLog 'Launcher copied to dist (Launch-CS2.ps1 + .cmd)' 'Good'
}

# ---------------------------------------------------------------------------
# Final gate: the built artifact must itself parse
# ---------------------------------------------------------------------------
$buildErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($outScript, [ref]$null, [ref]$buildErrors)
if ($buildErrors) {
    Write-BuildLog 'BUILD FAILED - the concatenated artifact does not parse:' 'Error'
    foreach ($e in $buildErrors) { Write-BuildLog "  line $($e.Extent.StartLineNumber): $($e.Message)" 'Error' }
    exit 1
}
Write-BuildLog 'Built artifact parses cleanly' 'Good'
