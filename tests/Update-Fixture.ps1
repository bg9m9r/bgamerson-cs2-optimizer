<#
.SYNOPSIS
    Captures the current machine's profile and scrubs device identifiers before
    writing it into tests\fixtures\profiles\.

.DESCRIPTION
    The captured profile is genuinely useful as a test fixture, but a raw
    capture contains hardware identifiers that should not be published:

        - NIC MAC addresses (identifying, usable for tracking)
        - disk serial numbers
        - audio endpoint GUIDs

    Tests only need the SHAPE of the profile and the field values the gates read
    (vendor, core count, refresh rate, VBS state...). None of them assert on a
    serial, a MAC, or the fingerprint hash - so scrubbing costs nothing.

    Always regenerate fixtures through this script rather than -CaptureProfile
    directly, or the next refresh silently re-publishes the real values.

.EXAMPLE
    .\tests\Update-Fixture.ps1
#>
[CmdletBinding()]
param(
    [string]$Name = 'reference-amd-x3d',
    [switch]$KeepRaw
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$dist     = Join-Path $repoRoot 'dist\Optimize-CS2.ps1'
$outPath  = Join-Path $repoRoot "tests\fixtures\profiles\$Name.json"
$rawPath  = Join-Path $env:TEMP "cs2opt-rawprofile-$([guid]::NewGuid()).json"

if (-not (Test-Path -LiteralPath $dist)) { throw "Build first: build\Build-Script.ps1" }

$winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $winPs -NoProfile -ExecutionPolicy Bypass -File $dist -CaptureProfile $rawPath | Out-Null
if (-not (Test-Path -LiteralPath $rawPath)) { throw 'Profile capture produced no file.' }

$json = Get-Content -LiteralPath $rawPath -Raw

# --- scrub -----------------------------------------------------------------
# Done as text replacement over the serialized JSON so a field added later in a
# nested structure cannot quietly escape the scrubber.

# MAC addresses, in both AA-BB-... and AA:BB:... forms.
$json = [regex]::Replace($json, '\b([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b', '00-00-5E-00-53-00')

# Samsung/NVMe style serials: grouped hex with underscores, and long bare runs.
$json = [regex]::Replace($json, '"SerialNumber"\s*:\s*"[^"]*"', '"SerialNumber":  "FIXTURE-SERIAL-REDACTED"')
$json = [regex]::Replace($json, '"BootDisk"\s*:\s*"[^"]*"',     '"BootDisk":  "FIXTURE-SERIAL-REDACTED"')
$json = [regex]::Replace($json, '"NicMacs"\s*:\s*"[^"]*"',      '"NicMacs":  "00-00-5E-00-53-00"')

# Per-device audio endpoint GUIDs.
$json = [regex]::Replace($json, '"Id"\s*:\s*"\{[0-9a-fA-F-]{36}\}"', '"Id":  "{00000000-0000-0000-0000-000000000000}"')

# The fingerprint is derived from the values above, so it no longer means
# anything once they are redacted. Blank it rather than leaving a stale hash
# that looks authoritative.
$json = [regex]::Replace($json, '"Hash"\s*:\s*"sha256:[0-9a-f]+"', '"Hash":  "sha256:FIXTURE"')

# Belt and braces: never publish a local account path.
$json = $json.Replace($env:USERNAME, 'user')

Set-Content -LiteralPath $outPath -Value $json -Encoding UTF8

if (-not $KeepRaw) { Remove-Item -LiteralPath $rawPath -Force -ErrorAction SilentlyContinue }

# --- verify the scrub actually worked ---------------------------------------
$check = Get-Content -LiteralPath $outPath -Raw
$leaks = @()
if ($check -match '\b([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}\b' -and $check -notmatch '00-00-5E-00-53-00') { $leaks += 'MAC address' }
if ($check -match '[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}_[0-9A-F]{4}') { $leaks += 'disk serial' }
if ($env:USERNAME -and $check -match [regex]::Escape($env:USERNAME))  { $leaks += 'username' }

if ($leaks.Count -gt 0) {
    throw "Scrub INCOMPLETE - $($leaks -join ', ') still present in $outPath. Do not commit."
}

Write-Host "Fixture written and scrubbed: $outPath" -ForegroundColor Green
Write-Host "  no MAC addresses, disk serials, endpoint GUIDs or usernames remain" -ForegroundColor DarkGray
