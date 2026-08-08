<#
.SYNOPSIS
    Runs the cs2-opt test suite.

.DESCRIPTION
    Deliberately re-launches under Windows PowerShell 5.1 when started from
    PowerShell 7. 5.1 is the script's runtime target, and 7 hides real
    behavioural differences that would let bugs through:
      - ConvertTo-Json default depth
      - ConvertFrom-Json has no -AsHashtable on 5.1
      - native-command error semantics
      - CIM/Appx/NetAdapter module behaviour

    Pester is loaded repo-local from tools\Modules so the stock Pester 3.4.0
    shipped with Windows never auto-loads, and so nothing is installed
    machine-wide.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string[]]$Tag,
    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
    [string]$Output = 'Normal',
    [switch]$SkipAnalyzer,
    [switch]$NoRelaunch
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# --- Relaunch under Windows PowerShell 5.1 -----------------------------------
if ($PSVersionTable.PSEdition -eq 'Core' -and -not $NoRelaunch) {
    $winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $winPs)) { throw "Windows PowerShell 5.1 not found at $winPs" }

    Write-Host "Relaunching test suite under Windows PowerShell 5.1..." -ForegroundColor DarkGray
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-NoRelaunch', '-Output', $Output)
    if ($Path)         { $argList += @('-Path', $Path) }
    if ($Tag)          { $argList += @('-Tag', ($Tag -join ',')) }
    if ($SkipAnalyzer) { $argList += '-SkipAnalyzer' }

    & $winPs @argList
    exit $LASTEXITCODE
}

if ($PSVersionTable.PSVersion.Major -ne 5) {
    throw "Expected Windows PowerShell 5.1, got $($PSVersionTable.PSVersion)."
}

# --- Load repo-local Pester --------------------------------------------------
$pesterManifest = Get-ChildItem (Join-Path $repoRoot 'tools\Modules\Pester') -Filter 'Pester.psd1' -Recurse -ErrorAction SilentlyContinue |
    Sort-Object { [version](Split-Path -Leaf (Split-Path -Parent $_.FullName)) } |
    Select-Object -Last 1

if (-not $pesterManifest) {
    throw "Pester not found under tools\Modules. Bootstrap with:`n" +
          "  Save-Module -Name Pester -MinimumVersion 5.0.0 -Path '$repoRoot\tools\Modules'"
}

Get-Module Pester | Remove-Module -Force -ErrorAction SilentlyContinue
Import-Module $pesterManifest.FullName -Force -ErrorAction Stop
Write-Host "Pester $((Get-Module Pester).Version) on PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray

# --- PSScriptAnalyzer --------------------------------------------------------
$analyzerFailed = $false
if (-not $SkipAnalyzer) {
    if (Get-Module -ListAvailable PSScriptAnalyzer) {
        Import-Module PSScriptAnalyzer -Force
        Write-Host "`nPSScriptAnalyzer..." -ForegroundColor Cyan
        $findings = Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot 'src') -Recurse `
            -Settings (Join-Path $repoRoot 'build\PSScriptAnalyzerSettings.psd1')
        if ($findings) {
            $findings | Format-Table -AutoSize RuleName, Severity, ScriptName, Line, Message | Out-String | Write-Host
            $analyzerFailed = $true
            Write-Host "PSScriptAnalyzer: $($findings.Count) finding(s)" -ForegroundColor Red
        }
        else {
            Write-Host "PSScriptAnalyzer: clean" -ForegroundColor Green
        }
    }
    else {
        Write-Host "PSScriptAnalyzer not installed - skipping" -ForegroundColor Yellow
    }
}

# --- Pester ------------------------------------------------------------------
$config = New-PesterConfiguration
$config.Run.Path       = if ($Path) { $Path } else { $PSScriptRoot }
$config.Run.PassThru   = $true
$config.Output.Verbosity = $Output
if ($Tag) { $config.Filter.Tag = $Tag }

Write-Host "`nPester..." -ForegroundColor Cyan
$result = Invoke-Pester -Configuration $config

$exit = 0
if ($result.FailedCount -gt 0) { $exit = 1 }
if ($analyzerFailed)           { $exit = 1 }

Write-Host ""
Write-Host ("Tests: {0} passed, {1} failed, {2} skipped" -f $result.PassedCount, $result.FailedCount, $result.SkippedCount) `
    -ForegroundColor $(if ($exit -eq 0) { 'Green' } else { 'Red' })

exit $exit
