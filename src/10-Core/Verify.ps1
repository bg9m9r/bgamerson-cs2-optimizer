<#
    Verification pass (spec 1.2.9 / 14).

    Re-reads every changed value and reports PASS/FAIL.

    The honest part is VerifyMode. Several changes cannot be confirmed before a
    reboot, and the spec calls this out for MMAgent specifically: Get-MMAgent
    reports the new value immediately, but neither change takes real effect
    until the compression store is drained. The same is true of HwSchMode,
    HiberbootEnabled, Win32PrioritySeparation, the pagefile, and every bcdedit
    change.

    Those are marked PostReboot and reported as DEFERRED, never as PASS. The
    -VerifyOnly switch re-runs this pass after the reboot, which is the only way
    they ever get a real result.
#>

function Invoke-OptVerification {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [array]$Changes,
        [switch]$PostReboot
    )

    if (-not $Changes) { $Changes = @($State.Changes) }

    $summary = @{ Pass = 0; Fail = 0; Deferred = 0; Skipped = 0; Planned = 0 }

    # Under -DryRun nothing was written, so re-reading every value would report
    # FAIL for the entire planned change set - which looks like a catastrophe and
    # means nothing. Report them as PLANNED instead.
    if ($State.DryRun) {
        foreach ($change in $Changes) {
            $summary.Planned++
            [void]$State.Verification.Add([pscustomobject][ordered]@{
                ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
                Path = $change.Path; Name = $change.Name
                Result = 'PLANNED'; Expected = $change.NewValue; Actual = $change.OldValue
                Detail = 'dry run - not applied, so not verified'
            })
        }
        return $summary
    }

    foreach ($change in $Changes) {
        $mode = [string]$change.VerifyMode

        if ($mode -eq 'None') {
            $summary.Skipped++
            continue
        }

        if ($mode -eq 'PostReboot' -and -not $PostReboot) {
            $summary.Deferred++
            [void]$State.Verification.Add([pscustomobject][ordered]@{
                ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
                Path = $change.Path; Name = $change.Name
                Result = 'DEFERRED'; Expected = $change.NewValue; Actual = $null
                Detail = 'takes effect on reboot - re-run with -VerifyOnly afterwards'
            })
            continue
        }

        $result = Test-OptChangeApplied -State $State -Change $change

        if ($result.Result -eq 'PASS') { $summary.Pass++ }
        elseif ($result.Result -eq 'FAIL') { $summary.Fail++ }
        else { $summary.Skipped++ }

        [void]$State.Verification.Add([pscustomobject][ordered]@{
            ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
            Path = $change.Path; Name = $change.Name
            Result = $result.Result; Expected = $result.Expected; Actual = $result.Actual
            Detail = $result.Detail
        })
    }

    return $summary
}

function Test-OptChangeApplied {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)]$Change
    )

    switch ([string]$Change.Type) {

        'Registry' {
            $target = $Change.Target
            $hive   = [string]$target.Hive
            $sub    = [string]$target.SubKey
            $name   = [string]$target.Name
            $kind   = [string]$target.ValueKind

            $info = Get-OptRegistryValueInfo -State $State -Hive $hive -SubKey $sub -Name $name
            $expected = ConvertFrom-OptStorableValue -Value $Change.NewValue

            if (-not $info.ValueExists) {
                return @{ Result = 'FAIL'; Expected = (Format-OptValueForLog $expected); Actual = '<absent>'; Detail = 'value is not present after apply' }
            }

            $match = Compare-OptRegistryData -Type $kind -Current $info.Value -Desired (ConvertTo-OptRegistryData -Type $kind -Value $expected)
            return @{
                Result   = $(if ($match) { 'PASS' } else { 'FAIL' })
                Expected = (Format-OptValueForLog $expected)
                Actual   = (Format-OptValueForLog $info.Value)
                Detail   = $null
            }
        }

        'RegistryValueDelete' {
            $target = $Change.Target
            $info = Get-OptRegistryValueInfo -State $State -Hive ([string]$target.Hive) -SubKey ([string]$target.SubKey) -Name ([string]$target.Name)
            return @{
                Result   = $(if ($info.ValueExists) { 'FAIL' } else { 'PASS' })
                Expected = '<absent>'
                Actual   = $(if ($info.ValueExists) { (Format-OptValueForLog $info.Value) } else { '<absent>' })
                Detail   = $null
            }
        }

        'ScheduledTask' {
            $target = $Change.Target
            $task = Get-ScheduledTask -TaskPath ([string]$target.TaskPath) -TaskName ([string]$target.TaskName) -ErrorAction SilentlyContinue
            if (-not $task) { return @{ Result = 'SKIP'; Expected = 'Disabled'; Actual = '<not present>'; Detail = 'task no longer present' } }
            return @{
                Result   = $(if ([string]$task.State -eq 'Disabled') { 'PASS' } else { 'FAIL' })
                Expected = 'Disabled'; Actual = [string]$task.State; Detail = $null
            }
        }

        'Service' {
            $target = $Change.Target
            $svc = Get-Service -Name ([string]$target.ServiceName) -ErrorAction SilentlyContinue
            if (-not $svc) { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = '<not present>'; Detail = 'service no longer present' } }
            return @{
                Result   = $(if ([string]$svc.StartType -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = [string]$Change.NewValue; Actual = [string]$svc.StartType; Detail = $null
            }
        }

        'MMAgent' {
            $target = $Change.Target
            try {
                $agent = Get-MMAgent -ErrorAction Stop
                $actual = $agent.($target.Field)
                return @{
                    Result   = $(if ([bool]$actual -eq [bool]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                    Expected = [string]$Change.NewValue; Actual = [string]$actual
                    Detail   = 'reported immediately but not fully effective until reboot'
                }
            }
            catch { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = $_.Exception.Message } }
        }

        'PowerCfgActive' {
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/getactivescheme') -ReadOnly
            $schemes = Get-OptPowerSchemes -Text $r.StdOut
            $active = @($schemes)[0]
            return @{
                Result   = $(if ($active -and [string]$active.Guid -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = [string]$Change.NewValue
                Actual   = $(if ($active) { $active.Guid } else { '<unknown>' })
                Detail   = $null
            }
        }

        'NetAdapterProperty' {
            $target = $Change.Target
            try {
                $prop = Get-NetAdapterAdvancedProperty -Name ([string]$target.AdapterName) `
                            -RegistryKeyword ([string]$target.Keyword) -ErrorAction Stop
                $actual = @($prop.RegistryValue)[0]
                return @{
                    Result   = $(if ([string]$actual -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                    Expected = [string]$Change.NewValue; Actual = [string]$actual; Detail = $null
                }
            }
            catch { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = 'adapter or keyword no longer present' } }
        }

        'DefenderExclusion' {
            try {
                $pref = Get-MpPreference -ErrorAction Stop
                $target = $Change.Target
                # Get-MpPreference returns $null (not @()) when a list is empty,
                # so .Count would throw under StrictMode without the @() wrap.
                $list = @(if ([string]$target.Kind -eq 'Path') { $pref.ExclusionPath } else { $pref.ExclusionProcess })
                $present = [bool](@($list | Where-Object { [string]$_ -eq [string]$Change.NewValue }).Count)
                return @{
                    Result   = $(if ($present) { 'PASS' } else { 'FAIL' })
                    Expected = [string]$Change.NewValue
                    Actual   = $(if ($present) { [string]$Change.NewValue } else { '<not in exclusion list>' })
                    Detail   = $(if (-not $present) { 'Tamper Protection can silently reject exclusion changes' } else { $null })
                }
            }
            catch { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = $_.Exception.Message } }
        }

        'FsutilBehavior' {
            $target = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
                 -ArgumentList @('behavior', 'query', [string]$target.Setting) -ReadOnly
            $line = @(Get-OptCommandLines -Text $r.StdOut) | Select-Object -First 1
            $actual = $null
            if ($line -and $line -match '=\s*(\d+)') { $actual = $Matches[1] }
            return @{
                Result   = $(if ([string]$actual -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = [string]$Change.NewValue; Actual = [string]$actual; Detail = $null
            }
        }

        'DisplayMode' {
            $target = $Change.Target
            $cur = Get-OptDisplayCurrentMode -Device ([string]$target.Device)
            if (-not $cur) { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = 'display no longer present' } }
            return @{
                Result   = $(if ([int]$cur.Hz -eq [int]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = "$($Change.NewValue) Hz"; Actual = "$($cur.Hz) Hz"; Detail = $null
            }
        }

        default {
            return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = "no verifier for change type '$($Change.Type)'" }
        }
    }
}

function Write-OptVerificationReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $rows = @($State.Verification)
    if ($rows.Count -eq 0) { return }

    Write-OptLog -Level Header 'VERIFICATION'

    $planned = @($rows | Where-Object { $_.Result -eq 'PLANNED' })
    if ($planned.Count -gt 0) {
        Write-OptLog -Level Info "$($planned.Count) change(s) planned. Nothing was applied, so nothing is verified."
        return
    }

    $failed = @($rows | Where-Object { $_.Result -eq 'FAIL' })
    foreach ($r in $failed) {
        Write-OptLog -Level Error ("{0} {1}\{2}: expected '{3}', got '{4}'" -f $r.Section, $r.Path, $r.Name, $r.Expected, $r.Actual)
    }

    $deferred = @($rows | Where-Object { $_.Result -eq 'DEFERRED' })
    if ($deferred.Count -gt 0) {
        Write-OptLog -Level Info "$($deferred.Count) change(s) take effect on reboot and are NOT yet verified:"
        foreach ($r in $deferred) {
            Write-OptLog -Level Detail ("{0} {1} {2}" -f $r.Section, $r.Path, $r.Name)
        }
    }

    $pass = @($rows | Where-Object { $_.Result -eq 'PASS' }).Count
    $skip = @($rows | Where-Object { $_.Result -eq 'SKIP' }).Count
    $level = if ($failed.Count -gt 0) { 'Warn' } else { 'Good' }
    Write-OptLog -Level $level ("{0} passed, {1} failed, {2} deferred to reboot, {3} skipped" -f $pass, $failed.Count, $deferred.Count, $skip)
}
