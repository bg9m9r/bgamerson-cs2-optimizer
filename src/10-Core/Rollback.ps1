<#
    Rollback: reverse-ordinal replay with a per-Type handler.

    Design rules that came out of thinking about how this actually fails:

    - REVERSE order matters. Section 2.2 writes power values and then re-activates
      the scheme; a key is created before values are set under it. Replaying
      forwards would undo them in the wrong sequence.

    - Rollback is VALUE-LEVEL from the manifest, never `reg import` of the .reg
      backups. Importing an exported key restores values that were deleted
      elsewhere and does not delete values added since.

    - ONE BAD ENTRY MUST NOT ABORT THE WHOLE ROLLBACK. A rollback that stops
      halfway leaves the machine in a state that exists in neither manifest -
      worse than either endpoint. Every entry is attempted; failures are
      collected and reported.

    - Rollback writes its OWN artefact (rollback-<ts>.json) rather than mutating
      the original manifest, so a failed rollback is itself auditable.
#>

function Invoke-OptRollback {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$ManifestPath,
        [switch]$WhatIfOnly
    )

    $manifest = Read-OptManifest -Path $ManifestPath

    $changes = @($manifest.Changes)
    if ($changes.Count -eq 0) {
        Write-OptLog -Level Info 'Manifest contains no changes - nothing to roll back.'
        return @{ Total = 0; Restored = 0; Failed = 0; Skipped = 0; Results = @() }
    }

    # Fingerprint check. A mismatch is not fatal - the user may genuinely want to
    # undo changes after a hardware swap - but vendor-specific entries may now
    # target absent hardware, so say so.
    if ($State.Profile -and $manifest.Fingerprint) {
        $fp = Test-OptFingerprintMatch -StoredFingerprint $manifest.Fingerprint -CurrentFingerprint $State.Profile.Fingerprint
        if (-not $fp.Matches) {
            Write-OptLog -Level Warn "Hardware changed since this manifest was written - $($fp.Detail)"
            Write-OptLog -Level Detail 'Entries targeting hardware that is no longer present will be reported as orphaned.'
        }
    }

    # Reverse ordinal, not reverse array order - the manifest may have been
    # reconstructed from the journal in a different sequence.
    $ordered = @($changes | Sort-Object -Property @{ Expression = { [int]$_.Id } } -Descending)

    Write-OptLog -Level Header "ROLLBACK - $($ordered.Count) change(s), newest first"

    $results  = New-Object System.Collections.ArrayList
    $restored = 0; $failed = 0; $skipped = 0

    foreach ($change in $ordered) {
        $outcome = $null
        try {
            if ($WhatIfOnly) {
                $outcome = @{ Result = 'WOULD-RESTORE'; Detail = (Get-OptRollbackDescription -Change $change) }
            }
            else {
                $outcome = Invoke-OptRollbackEntry -State $State -Change $change
            }
        }
        catch {
            # Never let one entry stop the replay.
            $outcome = @{ Result = 'FAILED'; Detail = $_.Exception.Message }
        }

        switch ($outcome.Result) {
            'RESTORED'      { $restored++; Write-OptLog -Level Good   ("[{0}] {1}" -f $change.Id, $outcome.Detail) }
            'WOULD-RESTORE' { $skipped++;  Write-OptLog -Level Plain  ("  [{0}] {1}" -f $change.Id, $outcome.Detail) }
            'SKIPPED'       { $skipped++;  Write-OptLog -Level Detail ("[{0}] skipped: {1}" -f $change.Id, $outcome.Detail) }
            'IRREVERSIBLE'  { $skipped++;  Write-OptLog -Level Warn   ("[{0}] not reversible: {1}" -f $change.Id, $outcome.Detail) }
            default         { $failed++;   Write-OptLog -Level Error  ("[{0}] {1}" -f $change.Id, $outcome.Detail) }
        }

        [void]$results.Add([pscustomobject][ordered]@{
            ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
            Path = $change.Path; Name = $change.Name
            Result = $outcome.Result; Detail = $outcome.Detail
        })
    }

    $summary = @{ Total = $ordered.Count; Restored = $restored; Failed = $failed; Skipped = $skipped; Results = @($results) }

    if (-not $WhatIfOnly -and $State.Paths) {
        $out = Join-Path $State.Paths.RunDir ("rollback-{0}.json" -f $State.Paths.Stamp)
        try {
            @{ Source = $ManifestPath; Summary = $summary; Results = @($results) } |
                ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $out -Encoding UTF8
            Write-OptLog -Level Detail "Rollback record written to $out"
        }
        catch { Write-OptLog -Level Warn "Could not write rollback record: $($_.Exception.Message)" }
    }

    Write-OptLog -Level $(if ($failed -gt 0) { 'Warn' } else { 'Good' }) `
        ("Rollback complete: {0} restored, {1} failed, {2} skipped" -f $restored, $failed, $skipped)

    return $summary
}

function Get-OptRollbackDescription {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)]$Change)

    switch ([string]$Change.Type) {
        'Registry' {
            if (-not $Change.ExistedBefore) { return "delete $($Change.Path)\$($Change.Name) (did not exist before)" }
            return "restore $($Change.Path)\$($Change.Name) = $(Format-OptValueForLog (ConvertFrom-OptStorableValue $Change.OldValue))"
        }
        'RegistryValueDelete' { return "re-create $($Change.Path)\$($Change.Name)" }
        'ScheduledTask'       { return "re-enable scheduled task $($Change.Target.TaskPath)$($Change.Target.TaskName)" }
        'Service'             { return "restore service $($Change.Target.ServiceName) start type to $($Change.OldValue)" }
        'MMAgent'             { return "restore MMAgent $($Change.Target.Field) to $($Change.OldValue)" }
        'PowerCfgActive'      { return "re-activate power scheme $($Change.OldValue)" }
        'NetAdapterProperty'  { return "restore $($Change.Target.AdapterName) $($Change.Target.Keyword) to $($Change.OldValue)" }
        'DefenderExclusion'   { return "remove Defender exclusion $($Change.NewValue)" }
        'FsutilBehavior'      { return "restore fsutil $($Change.Target.Setting) to $($Change.OldValue)" }
        'DisplayMode'         { return "restore display $($Change.Target.Device) to $($Change.OldValue) Hz" }
        default               { return "$($Change.Type): $($Change.Path)" }
    }
}

function Invoke-OptRollbackEntry {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)]$Change
    )

    if ([string]$Change.Reversible -eq 'None') {
        return @{ Result = 'IRREVERSIBLE'; Detail = "$($Change.Type) cannot be undone by this script" }
    }

    switch ([string]$Change.Type) {

        'Registry' {
            $t = $Change.Target
            $hive = [string]$t.Hive; $sub = [string]$t.SubKey; $name = [string]$t.Name
            $kind = [string]$t.ValueKind

            $base = $null; $key = $null
            try {
                $base = Get-OptRegistryHiveKey -Hive $hive

                if (-not $Change.ExistedBefore) {
                    # The value did not exist before: DELETE it rather than
                    # writing anything back.
                    $key = $base.OpenSubKey($sub, $true)
                    if ($key) { $key.DeleteValue($name, $false) }

                    if (-not $Change.KeyExistedBefore) {
                        # We created the key too (e.g. the whole
                        # ...\Image File Execution Options\cs2.exe\PerfOptions
                        # subtree). Remove it - but never a key that pre-existed.
                        if ($key) { $key.Dispose(); $key = $null }
                        try { $base.DeleteSubKeyTree($sub, $false) } catch { }
                        return @{ Result = 'RESTORED'; Detail = "deleted value and key $hive\$sub\$name" }
                    }
                    return @{ Result = 'RESTORED'; Detail = "deleted $hive\$sub\$name (absent before)" }
                }

                # Restore the old value AND its ORIGINAL kind.
                #
                # Target.ValueKind is the type this script WROTE. Restoring with
                # that would leave a value whose data is right but whose type is
                # wrong - e.g. a setting that was REG_SZ "1" before we replaced
                # it with a REG_DWORD would come back as a DWORD. OldValueKind is
                # what it actually was.
                $old = ConvertFrom-OptStorableValue -Value $Change.OldValue
                $restoreKind = [string]$t.OldValueKind
                if (-not $restoreKind) { $restoreKind = $kind }

                $key = $base.CreateSubKey($sub)
                $key.SetValue($name, (ConvertTo-OptRegistryData -Type $restoreKind -Value $old), [Microsoft.Win32.RegistryValueKind]::$restoreKind)
                return @{ Result = 'RESTORED'; Detail = "restored $hive\$sub\$name = $(Format-OptValueForLog $old) ($restoreKind)" }
            }
            finally {
                if ($key)  { $key.Dispose() }
                if ($base) { $base.Dispose() }
            }
        }

        'RegistryValueDelete' {
            $t = $Change.Target
            $old = ConvertFrom-OptStorableValue -Value $Change.OldValue
            $kind = [string]$t.ValueKind
            if (-not $kind) { $kind = 'String' }

            $base = $null; $key = $null
            try {
                $base = Get-OptRegistryHiveKey -Hive ([string]$t.Hive)
                $key = $base.CreateSubKey([string]$t.SubKey)
                $key.SetValue([string]$t.Name, (ConvertTo-OptRegistryData -Type $kind -Value $old), [Microsoft.Win32.RegistryValueKind]::$kind)
                return @{ Result = 'RESTORED'; Detail = "re-created $($Change.Path)\$($Change.Name)" }
            }
            finally {
                if ($key)  { $key.Dispose() }
                if ($base) { $base.Dispose() }
            }
        }

        'ScheduledTask' {
            $t = $Change.Target
            $task = Get-ScheduledTask -TaskPath ([string]$t.TaskPath) -TaskName ([string]$t.TaskName) -ErrorAction SilentlyContinue
            if (-not $task) { return @{ Result = 'SKIPPED'; Detail = 'task no longer present' } }
            if ([string]$Change.OldValue -eq 'Disabled') { return @{ Result = 'SKIPPED'; Detail = 'was already disabled before the run' } }
            Enable-ScheduledTask -TaskPath ([string]$t.TaskPath) -TaskName ([string]$t.TaskName) -ErrorAction Stop | Out-Null
            return @{ Result = 'RESTORED'; Detail = "re-enabled $($t.TaskPath)$($t.TaskName)" }
        }

        'Service' {
            $t = $Change.Target
            $name = [string]$t.ServiceName
            $old  = [string]$Change.OldValue
            if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
                return @{ Result = 'SKIPPED'; Detail = 'service no longer present' }
            }

            # 'Automatic (Delayed Start)' is NOT restorable with Set-Service
            # alone - it is StartType=Automatic plus DelayedAutoStart=1 in the
            # service's registry key. Section 5.5 requires exactly that for
            # SysMain, so restoring only the start type would silently downgrade
            # it to plain Automatic.
            $wasDelayed = [bool]$t.DelayedAutoStart
            $setType = if ($old -match 'Delayed') { 'Automatic' } else { $old }

            Set-Service -Name $name -StartupType $setType -ErrorAction Stop
            if ($wasDelayed -or $old -match 'Delayed') {
                $base = $null; $key = $null
                try {
                    $base = Get-OptRegistryHiveKey -Hive 'HKLM'
                    $key = $base.CreateSubKey("SYSTEM\CurrentControlSet\Services\$name")
                    $key.SetValue('DelayedAutostart', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
                }
                finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
            }
            return @{ Result = 'RESTORED'; Detail = "restored service $name to $old" }
        }

        'MMAgent' {
            $field = [string]$Change.Target.Field
            $old   = [bool]$Change.OldValue
            # Restore the RECORDED pre-state, never a Windows default. On the
            # reference machine both fields were already False before the run;
            # "restoring the default" would enable them - a state the user has
            # never been in.
            if ($old) { Enable-MMAgent  -$field -ErrorAction Stop | Out-Null }
            else      { Disable-MMAgent -$field -ErrorAction Stop | Out-Null }
            return @{ Result = 'RESTORED'; Detail = "MMAgent $field restored to $old" }
        }

        'PowerCfgActive' {
            $old = [string]$Change.OldValue
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/setactive', $old)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "powercfg /setactive $old failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "re-activated power scheme $old" }
        }

        'PowerCfgSetting' {
            $t = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
                 -ArgumentList @('/setacvalueindex', [string]$t.Scheme, [string]$t.SubGroup, [string]$t.Setting, [string]$Change.OldValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "powercfg restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored $($t.SubGroup)/$($t.Setting) to $($Change.OldValue)" }
        }

        'PowerCfgScheme' {
            # Only delete a scheme this script created.
            if (-not $Change.Target.CreatedByUs) { return @{ Result = 'SKIPPED'; Detail = 'scheme pre-existed; left in place' } }
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/delete', [string]$Change.NewValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "powercfg /delete failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "deleted power scheme $($Change.NewValue)" }
        }

        'NetshTcpGlobal' {
            $t = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'netsh.exe' `
                 -ArgumentList @('int', 'tcp', 'set', 'global', "$([string]$t.Setting)=$([string]$Change.OldValue)")
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "netsh restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored netsh $($t.Setting) to $($Change.OldValue)" }
        }

        'FsutilBehavior' {
            $t = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
                 -ArgumentList @('behavior', 'set', [string]$t.Setting, [string]$Change.OldValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "fsutil restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored fsutil $($t.Setting) to $($Change.OldValue)" }
        }

        'DefenderExclusion' {
            $t = $Change.Target
            try {
                if ([string]$t.Kind -eq 'Path') { Remove-MpPreference -ExclusionPath ([string]$Change.NewValue) -ErrorAction Stop }
                else { Remove-MpPreference -ExclusionProcess ([string]$Change.NewValue) -ErrorAction Stop }
                return @{ Result = 'RESTORED'; Detail = "removed Defender exclusion $($Change.NewValue)" }
            }
            catch { return @{ Result = 'FAILED'; Detail = $_.Exception.Message } }
        }

        'NetAdapterProperty' {
            $t = $Change.Target
            try {
                Set-NetAdapterAdvancedProperty -Name ([string]$t.AdapterName) `
                    -RegistryKeyword ([string]$t.Keyword) -RegistryValue ([string]$Change.OldValue) `
                    -NoRestart -ErrorAction Stop
                return @{ Result = 'RESTORED'; Detail = "restored $($t.Keyword) to $($Change.OldValue) (adapter restart pending)" }
            }
            catch { return @{ Result = 'SKIPPED'; Detail = "adapter or keyword no longer present: $($_.Exception.Message)" } }
        }

        'BcdEditValue' {
            $t = $Change.Target
            if (-not $Change.ExistedBefore) {
                $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/deletevalue', [string]$t.Element)
                return @{ Result = 'RESTORED'; Detail = "removed bcdedit element $($t.Element)" }
            }
            $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/set', [string]$t.Element, [string]$Change.OldValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "bcdedit restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored bcdedit $($t.Element) to $($Change.OldValue)" }
        }

        'DisplayMode' {
            $t = $Change.Target
            $res = [Cs2Opt.Display.Api]::TrySetRefresh([string]$t.Device, [int]$Change.OldValue, $false)
            if (-not $res.Applied) { return @{ Result = 'FAILED'; Detail = "display restore failed: $($res.CodeName)" } }
            return @{ Result = 'RESTORED'; Detail = "restored $($t.Device) to $($Change.OldValue) Hz" }
        }

        'AutomaticPagefile' {
            try {
                $inst = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                Set-CimInstance -InputObject $inst -Property @{ AutomaticManagedPagefile = [bool]$Change.OldValue } -ErrorAction Stop
                return @{ Result = 'RESTORED'; Detail = "AutomaticManagedPagefile restored to $($Change.OldValue)" }
            }
            catch { return @{ Result = 'FAILED'; Detail = $_.Exception.Message } }
        }

        'NetAdapterPowerMgmt' {
            $name = [string]$Change.Target.AdapterName
            try {
                Enable-NetAdapterPowerManagement -Name $name -ErrorAction Stop -Confirm:$false
                return @{ Result = 'RESTORED'; Detail = "re-enabled power management on $name" }
            }
            catch { return @{ Result = 'SKIPPED'; Detail = "adapter no longer present: $($_.Exception.Message)" } }
        }

        'UsbPowerMgmt' {
            # Partial by design: endpoints that have since been unplugged are
            # skipped rather than failing the whole rollback.
            $ids = @($Change.Target.InstanceIds)
            $restored = 0
            foreach ($id in $ids) {
                try {
                    $nodes = Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop |
                             Where-Object { $_.InstanceName -like "*$([string]$id -replace '\\','\\')*" }
                    foreach ($n in $nodes) {
                        Set-CimInstance -InputObject $n -Property @{ Enable = $true } -ErrorAction Stop
                        $restored++
                    }
                }
                catch { }
            }
            return @{ Result = 'RESTORED'; Detail = "re-enabled power management on $restored of $($ids.Count) USB endpoint(s)" }
        }

        'WindowsOptionalFeature' {
            $feature = [string]$Change.Target.FeatureName
            try {
                if ([string]$Change.OldValue -eq 'Enabled') {
                    Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction Stop | Out-Null
                    return @{ Result = 'RESTORED'; Detail = "re-enabled optional feature $feature (reboot required)" }
                }
                return @{ Result = 'SKIPPED'; Detail = "feature $feature was not enabled before the run" }
            }
            catch { return @{ Result = 'FAILED'; Detail = $_.Exception.Message } }
        }

        'AppxPackage' {
            return @{ Result = 'IRREVERSIBLE'; Detail = "Appx removal cannot be undone by this script - reinstall '$($Change.Name)' from the Store" }
        }

        default {
            return @{ Result = 'SKIPPED'; Detail = "no rollback handler for change type '$($Change.Type)'" }
        }
    }
}
