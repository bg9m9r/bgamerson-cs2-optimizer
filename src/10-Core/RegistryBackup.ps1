<#
    Per-key registry export.

    A deliberate reading of spec 1.2.4: it says "reg export the PARENT key", but
    taken literally that is wrong and occasionally catastrophic - the parent of
    HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters (section 6.3) is
    ...\Services, which exports hundreds of megabytes. This exports the EXACT
    key being written, deduplicated per run.

    Equally important, stated plainly in the report: these .reg files are a
    MANUAL LAST RESORT, not the rollback mechanism. Re-importing an exported key
    restores values that were deleted elsewhere and does NOT delete values added
    since. Rollback is value-level, from the manifest.
#>

function Backup-OptRegistryKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$SubKey,
        [int]$MaxSizeMB = 20
    )

    if ($State.DryRun) { return $null }
    if (-not $State.Paths -or -not $State.Paths.Backup) { return $null }

    # -SkipRecovery drops the .reg exports only. The manifest and the journal
    # are untouched, so value-level rollback still works - these files were
    # always a manual last resort, never the undo mechanism.
    if ($State.Parameters['SkipRecovery']) { return $null }

    $full = "$Hive\$SubKey"

    if (-not $State.Contains('BackupDone')) {
        $State['BackupDone'] = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    }
    # Section 8.7 writes eight values under one Explorer\Advanced key; without
    # dedupe that is eight identical exports.
    if ($State['BackupDone'].Contains($full)) { return $null }

    $safe = ($full -replace '[\\/:*?"<>|]', '_')
    if ($safe.Length -gt 150) { $safe = $safe.Substring(0, 150) }
    $file = Join-Path $State.Paths.Backup "$safe.reg"

    $result = Invoke-OptNativeCommand -State $State -FilePath 'reg.exe' `
        -ArgumentList @('export', $full, $file, '/y') -Purpose "backup $full"

    [void]$State['BackupDone'].Add($full)

    if (-not $result.Success) {
        # Exit 1 here almost always means the key does not exist yet, which is a
        # perfectly normal precondition - the manifest records ExistedBefore and
        # rollback deletes rather than restores.
        return $null
    }

    if (Test-Path -LiteralPath $file) {
        $sizeMB = (Get-Item -LiteralPath $file).Length / 1MB
        if ($sizeMB -gt $MaxSizeMB) {
            Write-OptLog -Level Warn ("Registry backup for {0} is {1:N0} MB - removing it. Value-level rollback from the manifest still covers this change." -f $full, $sizeMB)
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            return $null
        }
        return $file
    }

    return $null
}
