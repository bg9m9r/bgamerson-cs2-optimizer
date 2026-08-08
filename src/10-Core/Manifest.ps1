<#
    Manifest read/write.

    Two artefacts per run:
      runs\<ts>-<id>\changes.jsonl   append-and-flush after EVERY change
      runs\<ts>-<id>\manifest.json   consolidated, rewritten at section boundaries

    %ProgramData%\cs2-opt\manifest.json (the spec 1.1 default path) is a copy of
    the latest run's manifest, which is what -Rollback picks up by default.
#>

function Write-OptManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [switch]$Final
    )

    if ($State.DryRun -and -not $Final) { return }
    if (-not $State.Paths) { return }

    $manifest = [ordered]@{
        SchemaVersion = 1
        Tool          = [ordered]@{ Name = 'cs2-opt'; Version = '1.0.0' }
        Run           = Get-OptStateSnapshot -State $State
        Fingerprint   = $(if ($State.Profile) { $State.Profile.Fingerprint } else { $null })
        Profile       = $State.Profile
        Gates         = @($State.Decisions | Where-Object { $_.Id -like 'G-*' })
        Changes       = @($State.Changes)
        Findings      = @($State.Findings)
        Manual        = @($State.Manual)
        Verification  = @($State.Verification)
        Decisions     = @($State.Decisions)
    }

    try {
        # -Depth is mandatory: the default is 2 and this object is far deeper,
        # which would silently serialize nested nodes as the literal string
        # "System.Collections.Hashtable".
        $json = $manifest | ConvertTo-Json -Depth 12

        # Write to a temp file then move, so an interrupted write cannot leave a
        # truncated manifest where a valid one used to be.
        $tmp = "$($State.Paths.RunManifest).tmp"
        Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $State.Paths.RunManifest -Force -ErrorAction Stop

        if ($Final -and -not $State.DryRun) {
            Copy-Item -LiteralPath $State.Paths.RunManifest -Destination $State.Paths.Manifest -Force -ErrorAction Stop
        }
    }
    catch {
        Write-OptLog -Level Warn "Could not write manifest: $($_.Exception.Message)"
    }
}

function Read-OptManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "No manifest found at '$Path'. Nothing to roll back."
    }

    try {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Manifest at '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

function Test-OptFingerprintMatch {
    <#
        Spec 1.5.6 re-run safety.

        Match    - normal idempotent re-run
        Mismatch - hardware changed; previously-applied vendor-specific tweaks
                   may now target absent hardware
        Absent   - first run
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowNull()]$StoredFingerprint,
        [Parameter(Mandatory)][System.Collections.IDictionary]$CurrentFingerprint
    )

    if (-not $StoredFingerprint) {
        return @{ Status = 'Absent'; Matches = $true; Detail = 'no prior run recorded' }
    }

    $storedHash = if ($StoredFingerprint -is [System.Collections.IDictionary]) { $StoredFingerprint['Hash'] } else { $StoredFingerprint.Hash }

    if ([string]$storedHash -eq [string]$CurrentFingerprint.Hash) {
        return @{ Status = 'Match'; Matches = $true; Detail = 'hardware unchanged since the last run' }
    }

    $changed = @()
    $storedComponents = if ($StoredFingerprint -is [System.Collections.IDictionary]) { $StoredFingerprint['Components'] } else { $StoredFingerprint.Components }
    if ($storedComponents) {
        foreach ($k in $CurrentFingerprint.Components.Keys) {
            $old = if ($storedComponents -is [System.Collections.IDictionary]) { $storedComponents[$k] } else { $storedComponents.$k }
            $new = $CurrentFingerprint.Components[$k]
            if ([string]$old -ne [string]$new) { $changed += "${k}: '$old' -> '$new'" }
        }
    }

    return @{
        Status  = 'Mismatch'
        Matches = $false
        Detail  = "hardware changed since the last run: $($changed -join '; ')"
        Changed = $changed
    }
}
