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

    # Deliberately pure ASCII - no Unicode box-drawing. The build gate rejects
    # non-ASCII source because Windows PowerShell 5.1 reads a BOM-less file as
    # ANSI, which would turn any such character into mojibake in the built
    # single-file script. Widest line is 66 chars, so it fits an 80-column
    # console without wrapping.
    $logo = @(
        ' ____    ____     _     __  __  _____  ____   ____    ___   _   _ '
        '| __ )  / ___|   / \   |  \/  || ____||  _ \ / ___|  / _ \ | \ | |'
        '|  _ \ | |  _   / _ \  | |\/| ||  _|  | |_) |\___ \ | | | ||  \| |'
        '| |_) || |_| | / ___ \ | |  | || |___ |  _ <  ___) || |_| || |\  |'
        '|____/  \____|/_/   \_\|_|  |_||_____||_| \_\|____/  \___/ |_| \_|'
    )

    # Vertical gradient: dimmer at the top and bottom, brightest through the
    # middle.
    $shades = @('DarkCyan', 'Cyan', 'Cyan', 'Cyan', 'DarkCyan')

    Write-Host ''
    for ($i = 0; $i -lt $logo.Count; $i++) {
        Write-Host ('  ' + $logo[$i]) -ForegroundColor $shades[$i]
    }

    Write-Host ''
    Write-Host "        C S 2    O P T I M I Z E R    S C R I P T" -ForegroundColor Yellow
    Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan

    if ($State.DryRun) {
        Write-Host '   DRY RUN ' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
        Write-Host ' nothing will be modified' -ForegroundColor Yellow
    }
    else {
        Write-Host '  Tier ' -ForegroundColor Gray -NoNewline
        Write-Host $State.Tier -ForegroundColor Green
    }

    Write-Host "  Run  $($State.RunId)" -ForegroundColor DarkGray
    Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan
}
