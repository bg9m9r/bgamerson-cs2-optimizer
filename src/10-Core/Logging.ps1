<#
    Console + transcript logging.

    Everything user-facing goes through Write-Host. That is deliberate, not
    laziness: Start-Transcript only captures the host output and information
    streams. Write-Verbose output does NOT appear in a transcript unless the
    caller passed -Verbose, so routing user-facing text through Write-Verbose
    would produce log files that are missing the very lines you need when
    diagnosing a failed run from the log alone (spec 1.5).
#>

function Start-OptTranscript {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    try {
        # Start-Transcript throws if one is already running in this session.
        Start-Transcript -Path $State.Paths.Transcript -Force -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
        return $false
    }
}

function Stop-OptTranscript {
    [CmdletBinding()]
    param()
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}

function Write-OptLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Good', 'Warn', 'Error', 'Detail', 'Header', 'Plain')]
        [string]$Level = 'Info'
    )

    switch ($Level) {
        'Header' {
            Write-Host ''
            Write-Host $Message -ForegroundColor Cyan
            Write-Host ('-' * [Math]::Min(78, [Math]::Max(8, $Message.Length))) -ForegroundColor DarkCyan
        }
        'Good'   { Write-Host "  [ OK ]  $Message" -ForegroundColor Green }
        'Warn'   { Write-Host "  [WARN]  $Message" -ForegroundColor Yellow }
        'Error'  { Write-Host "  [FAIL]  $Message" -ForegroundColor Red }
        'Detail' { Write-Host "          $Message" -ForegroundColor DarkGray }
        'Plain'  { Write-Host $Message }
        default  { Write-Host "  [ .. ]  $Message" -ForegroundColor Gray }
    }
}

function Write-OptBanner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $mode = if ($State.DryRun) { 'DRY RUN - nothing will be modified' } else { "Tier: $($State.Tier)" }

    Write-Host ''
    Write-Host '===============================================================================' -ForegroundColor Cyan
    Write-Host '  cs2-opt - Windows 11 optimization for competitive CS2 / FACEIT' -ForegroundColor Cyan
    Write-Host "  $mode" -ForegroundColor $(if ($State.DryRun) { 'Yellow' } else { 'Cyan' })
    Write-Host "  Run $($State.RunId)" -ForegroundColor DarkGray
    Write-Host '===============================================================================' -ForegroundColor Cyan
}
