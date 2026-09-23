BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    # Must be dot-sourced HERE, not inside a helper function - see TestHelper.ps1.
    foreach ($f in (Get-Cs2OptSourceFiles)) { . $f }
}

Describe 'Set-OptRegistryValue' {

    BeforeEach {
        $script:state = New-Cs2OptTestState -PathsRoot (Join-Path $TestDrive 'cs2-opt')
    }
    AfterEach {
        Remove-Cs2OptTestState -State $script:state
    }

    It 'applies a value that does not exist, and records ExistedBefore = false' {
        $r = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'Alpha' `
            -Type DWord -Value 1 -Section '4.1' -Tier 'Safe'

        $r.Action | Should -Be 'Applied'
        $r.Change.ExistedBefore | Should -BeFalse
        # Rollback must DELETE, not restore, in this case.
        $r.Change.OldValue | Should -BeNullOrEmpty
        $script:state.Changes.Count | Should -Be 1
    }

    It 'does NOT record a change when the value is already correct' {
        # This is the single most dangerous bug in the design: recording a no-op
        # as a change means -Rollback moves the machine to a state it was never in.
        Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'Beta' `
            -Type DWord -Value 7 -Section '4.1' -Tier 'Safe' | Out-Null
        $script:state.Changes.Count | Should -Be 1

        $r = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'Beta' `
            -Type DWord -Value 7 -Section '4.1' -Tier 'Safe'

        $r.Action | Should -Be 'AlreadyCorrect'
        $script:state.Changes.Count | Should -Be 1   # unchanged
        @($script:state.Decisions | Where-Object { $_.Decision -eq 'NoOp' }).Count | Should -BeGreaterThan 0
    }

    It 'handles the 0xFFFFFFFF DWORD sign trap idempotently' {
        # NetworkThrottlingIndex (section 4.1) is 0xFFFFFFFF and reads back as -1.
        # A naive -eq comparison is false forever, so the value is rewritten on
        # every run and the manifest stores an unwritable -1.
        $r1 = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'Throttle' `
            -Type DWord -Value 4294967295 -Section '4.1' -Tier 'Safe'
        $r1.Action | Should -Be 'Applied'

        $r2 = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'Throttle' `
            -Type DWord -Value 4294967295 -Section '4.1' -Tier 'Safe'
        $r2.Action | Should -Be 'AlreadyCorrect'

        $info = Get-OptRegistryValueInfo -State $script:state `
            -Hive 'HKCU' -SubKey "$($script:state['SandboxRoot'])\HKLM\SOFTWARE\Test" -Name 'Throttle'
        $info.Value | Should -Be -1
    }

    It 'writes a SINGLE-entry MultiString correctly (the pagefile case)' {
        # Regression: PowerShell unrolls a one-element array on function
        # return, so ConvertTo-OptRegistryData handed SetValue a bare String
        # against RegistryValueKind.MultiString and the write threw. Caught on
        # a real run - the 5.1 pagefile is exactly a single-entry MULTI_SZ.
        $r = Set-OptRegistryValue -State $script:state `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
            -Name 'PagingFiles' -Type MultiString -Value @('C:\pagefile.sys 16384 16384') `
            -Section '5.1' -Tier 'Safe'

        $r.Action | Should -Be 'Applied'

        $info = Get-OptRegistryValueInfo -State $script:state `
            -Hive 'HKCU' -SubKey "$($script:state['SandboxRoot'])\HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
            -Name 'PagingFiles'
        $info.Kind | Should -Be 'MultiString'
        @($info.Value).Count | Should -Be 1
        @($info.Value)[0] | Should -Be 'C:\pagefile.sys 16384 16384'

        # Idempotent on the second pass.
        $r2 = Set-OptRegistryValue -State $script:state `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
            -Name 'PagingFiles' -Type MultiString -Value @('C:\pagefile.sys 16384 16384') `
            -Section '5.1' -Tier 'Safe'
        $r2.Action | Should -Be 'AlreadyCorrect'
    }

    It 'writes a single-byte Binary value correctly (same unroll hazard)' {
        $r = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'OneByte' `
            -Type Binary -Value ([byte[]]@(0x5A)) -Section '4.1' -Tier 'Safe'
        $r.Action | Should -Be 'Applied'

        $info = Get-OptRegistryValueInfo -State $script:state `
            -Hive 'HKCU' -SubKey "$($script:state['SandboxRoot'])\HKLM\SOFTWARE\Test" -Name 'OneByte'
        $info.Kind | Should -Be 'Binary'
        @($info.Value).Count | Should -Be 1
        @($info.Value)[0] | Should -Be 0x5A
    }

    It 'respects tier gating' {
        $script:state.Tier = 'Safe'
        $r = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Test' -Name 'Exp' `
            -Type DWord -Value 1 -Section '5.4' -Tier 'Experimental'

        $r.Action | Should -Be 'Skipped'
        $script:state.Changes.Count | Should -Be 0
    }

    It 'refuses policy writes when PolicyWrites capability is off' {
        $script:state.Capabilities.PolicyWrites = $false
        $r = Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
            -Name 'AllowTelemetry' -Type DWord -Value 0 -Section '8.2' -Tier 'Aggressive'

        $r.Action | Should -Be 'Skipped'
        $script:state.Changes.Count | Should -Be 0
        # Still logged individually so the report stays complete.
        @($script:state.Decisions | Where-Object { $_.Reason -like '*policy writes blocked*' }).Count | Should -Be 1
    }

    It 'writes nothing under -DryRun but still produces the planned change' {
        $dry = New-Cs2OptTestState -DryRun -PathsRoot (Join-Path $TestDrive 'cs2-opt-dry')
        try {
            $r = Set-OptRegistryValue -State $dry -Path 'HKLM:\SOFTWARE\Test' -Name 'Ghost' `
                -Type DWord -Value 1 -Section '4.1' -Tier 'Safe'

            $r.Action | Should -Be 'DryRun'
            $dry.Changes.Count | Should -Be 1

            $info = Get-OptRegistryValueInfo -State $dry `
                -Hive 'HKCU' -SubKey "$($dry['SandboxRoot'])\HKLM\SOFTWARE\Test" -Name 'Ghost'
            $info.ValueExists | Should -BeFalse
        }
        finally { Remove-Cs2OptTestState -State $dry }
    }

    It 'throws rather than escaping the sandbox when the interlock is armed' {
        # A test that forgets to configure redirection must NOT be able to write
        # to the real HKLM.
        $rogue = New-OptState -Tier 'Safe' -Parameters @{ DryRun = $false }
        $rogue.RegistryRootMap = @{}
        $env:CS2OPT_TEST_ROOT = 'HKCU\Software\Cs2OptTests'
        try {
            { Resolve-OptRegistryPath -State $rogue -Path 'HKLM:\SOFTWARE\Real' } |
                Should -Throw -ExpectedMessage '*interlock*'
        }
        finally { $env:CS2OPT_TEST_ROOT = $null }
    }
}

Describe 'Rollback round-trip' {

    BeforeEach {
        $script:state = New-Cs2OptTestState -PathsRoot (Join-Path $TestDrive "rt-$([guid]::NewGuid())")
    }
    AfterEach {
        Remove-Cs2OptTestState -State $script:state
    }

    It 'restores the exact prior state, including absent values and value kinds' {
        $sandbox = $script:state['SandboxRoot']

        # Seed a randomised pre-state across the four interesting cases:
        # absent / present-wrong-value / present-correct-value / present-wrong-type.
        $seedPath = "HKCU:\$sandbox\HKLM\SOFTWARE\Seed"
        New-Item -Path $seedPath -Force | Out-Null
        New-ItemProperty -Path $seedPath -Name 'WrongValue'   -Value 111 -PropertyType DWord  -Force | Out-Null
        New-ItemProperty -Path $seedPath -Name 'CorrectValue' -Value 42  -PropertyType DWord  -Force | Out-Null
        New-ItemProperty -Path $seedPath -Name 'WrongType'    -Value '1' -PropertyType String -Force | Out-Null
        # 'Absent' is deliberately not created.

        $before = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox

        foreach ($n in @('Absent', 'WrongValue', 'CorrectValue', 'WrongType')) {
            Set-OptRegistryValue -State $script:state -Path 'HKLM:\SOFTWARE\Seed' -Name $n `
                -Type DWord -Value 42 -Section '4.1' -Tier 'Safe' | Out-Null
        }

        # CorrectValue was already 42, so it must NOT have produced a change record.
        $script:state.Changes.Count | Should -Be 3

        # Rollback strictly from a written-and-re-read file. Most bugs in this
        # class are serialization bugs, not logic bugs, so replaying the
        # in-memory object would not exercise the real path.
        Write-OptManifest -State $script:state -Final
        $manifestPath = $script:state.Paths.RunManifest
        Test-Path $manifestPath | Should -BeTrue

        Invoke-OptRollback -State $script:state -ManifestPath $manifestPath | Out-Null

        $after = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox
        $diff = Compare-Cs2OptSnapshot -Before $before -After $after
        $diff | Should -BeNullOrEmpty
    }

    It 'round-trips REG_BINARY through JSON without corrupting it' {
        # UserPreferencesMask (section 8.3) is binary. ConvertTo-Json turns a
        # byte[] into an int array and ConvertFrom-Json returns Object[], so a
        # naive rollback writes garbage.
        $sandbox = $script:state['SandboxRoot']
        $original = [byte[]]@(0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00)

        $seedPath = "HKCU:\$sandbox\HKCU\Control Panel\Desktop"
        New-Item -Path $seedPath -Force | Out-Null
        New-ItemProperty -Path $seedPath -Name 'UserPreferencesMask' -Value $original -PropertyType Binary -Force | Out-Null

        $before = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox

        # Assert the write actually happened. This test once passed VACUOUSLY:
        # the binary write itself was broken (unrolled byte[] -> Object[]), so
        # nothing changed and "rollback restored everything" was trivially
        # true while hiding two real bugs at once.
        $write = Set-OptRegistryValue -State $script:state -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' `
            -Type Binary -Value ([byte[]]@(0x9E, 0x1E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00)) `
            -Section '8.3' -Tier 'Aggressive'
        $write.Action | Should -Be 'Applied'

        $mid = (Get-ItemProperty -LiteralPath $seedPath -Name 'UserPreferencesMask').UserPreferencesMask
        [System.Convert]::ToBase64String([byte[]]$mid) |
            Should -Not -Be ([System.Convert]::ToBase64String($original)) -Because 'the write must have really changed the value'

        Write-OptManifest -State $script:state -Final
        Invoke-OptRollback -State $script:state -ManifestPath $script:state.Paths.RunManifest | Out-Null

        $after = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox
        Compare-Cs2OptSnapshot -Before $before -After $after | Should -BeNullOrEmpty

        $restored = (Get-ItemProperty -LiteralPath $seedPath -Name 'UserPreferencesMask').UserPreferencesMask
        [System.Convert]::ToBase64String([byte[]]$restored) |
            Should -Be ([System.Convert]::ToBase64String($original))
    }

    It 'deletes a key it created rather than leaving an orphan' {
        $sandbox = $script:state['SandboxRoot']

        Set-OptRegistryValue -State $script:state `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions' `
            -Name 'CpuPriorityClass' -Type DWord -Value 3 -Section '6.4' -Tier 'Aggressive' | Out-Null

        $keyPath = "HKCU:\$sandbox\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions"
        Test-Path -LiteralPath $keyPath | Should -BeTrue

        Write-OptManifest -State $script:state -Final
        Invoke-OptRollback -State $script:state -ManifestPath $script:state.Paths.RunManifest | Out-Null

        Test-Path -LiteralPath $keyPath | Should -BeFalse
    }
}

Describe '-SkipRecovery' {

    It 'skips the .reg exports but STILL records changes, so rollback keeps working' {
        # The failure mode worth guarding: someone widens -SkipRecovery until it
        # also skips the manifest, silently turning every run into a one-way trip.
        $state = New-Cs2OptTestState -PathsRoot (Join-Path $TestDrive "skiprec-$([guid]::NewGuid())")
        $state.Parameters['SkipRecovery'] = $true
        try {
            $sandbox = $state['SandboxRoot']
            $seedPath = "HKCU:\$sandbox\HKLM\SOFTWARE\Seed"
            New-Item -Path $seedPath -Force | Out-Null
            New-ItemProperty -Path $seedPath -Name 'Val' -Value 1 -PropertyType DWord -Force | Out-Null
            $before = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox

            $r = Set-OptRegistryValue -State $state -Path 'HKLM:\SOFTWARE\Seed' -Name 'Val' `
                -Type DWord -Value 99 -Section '4.1' -Tier 'Safe'

            $r.Action | Should -Be 'Applied'
            $r.Change.BackupFile | Should -BeNullOrEmpty -Because 'the .reg export is what -SkipRecovery drops'
            $state.Changes.Count  | Should -Be 1 -Because 'the manifest record must survive -SkipRecovery'

            # And rollback must still fully restore.
            Write-OptManifest -State $state -Final
            Invoke-OptRollback -State $state -ManifestPath $state.Paths.RunManifest | Out-Null

            $after = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox
            Compare-Cs2OptSnapshot -Before $before -After $after | Should -BeNullOrEmpty
        }
        finally { Remove-Cs2OptTestState -State $state }
    }

    It 'writes a .reg export when -SkipRecovery is NOT set' {
        $state = New-Cs2OptTestState -PathsRoot (Join-Path $TestDrive "withrec-$([guid]::NewGuid())")
        try {
            $r = Set-OptRegistryValue -State $state -Path 'HKLM:\SOFTWARE\Seed2' -Name 'Val' `
                -Type DWord -Value 5 -Section '4.1' -Tier 'Safe'
            $r.Action | Should -Be 'Applied'
            # The key did not exist beforehand, so reg export legitimately has
            # nothing to write - assert the call path ran rather than the file.
            $state.Contains('BackupDone') | Should -BeTrue
        }
        finally { Remove-Cs2OptTestState -State $state }
    }
}

Describe 'Section 7.4 - UDP receive offload' {

    BeforeAll {
        $script:udpFixture = Get-Content -LiteralPath (Join-Path $script:Cs2OptRepoRoot 'tests\fixtures\cmdout\netsh-udp-global.txt') -Raw
    }
    BeforeEach {
        $script:state = New-Cs2OptTestState -Tier 'Aggressive' -PathsRoot (Join-Path $TestDrive "uro-$([guid]::NewGuid())")
    }
    AfterEach {
        Remove-Cs2OptTestState -State $script:state
    }

    It 'parses the URO state out of captured netsh output' {
        $lines = Get-OptCommandLines -Text $script:udpFixture
        Get-OptNetshGlobalValue -Lines $lines -Label 'Receive Offload State' | Should -Be 'enabled'
        Get-OptNetshGlobalValue -Lines $lines -Label 'Send Offload State'    | Should -Be 'enabled'
        Get-OptNetshGlobalValue -Lines $lines -Label 'No Such Label'         | Should -BeNullOrEmpty
        # The 7.2 fixture must parse through the same helper.
        $tcp = Get-OptCommandLines -Text (Get-Content -LiteralPath (Join-Path $script:Cs2OptRepoRoot 'tests\fixtures\cmdout\netsh-tcp-global.txt') -Raw)
        Get-OptNetshGlobalValue -Lines $tcp -Label 'Receive Window Auto-Tuning Level' | Should -Not -BeNullOrEmpty
    }

    It 'disables URO through the chokepoint and records a NetshUdpGlobal change with the prior state' {
        $script:calls = New-Object System.Collections.ArrayList
        Mock Invoke-OptNativeCommand {
            [void]$script:calls.Add(@($ArgumentList) -join ' ')
            if ((@($ArgumentList) -join ' ') -like '*show global*') {
                return @{ Success = $true; ExitCode = 0; StdOut = $script:udpFixture; StdErr = '' }
            }
            return @{ Success = $true; ExitCode = 0; StdOut = 'Ok.'; StdErr = '' }
        }

        Invoke-OptSection74Uro -State $script:state

        $script:calls | Should -Contain 'int udp show global'
        $script:calls | Should -Contain 'int udp set global uro=disabled'

        $change = @($script:state.Changes | Where-Object { $_.Type -eq 'NetshUdpGlobal' })
        $change.Count | Should -Be 1
        $change[0].OldValue | Should -Be 'enabled'
        $change[0].NewValue | Should -Be 'disabled'
        $change[0].Target.Setting | Should -Be 'uro'

        $d = @($script:state.Decisions | Where-Object { $_.Id -eq 'S-7.4-uro' })[0]
        $d.Decision | Should -Be 'Applied'
    }

    It 'does nothing, and records nothing, when URO is already disabled' {
        Mock Invoke-OptNativeCommand {
            return @{ Success = $true; ExitCode = 0; StdOut = ($script:udpFixture -replace 'Receive Offload State\s*:\s*enabled', 'Receive Offload State               : disabled'); StdErr = '' }
        }
        Invoke-OptSection74Uro -State $script:state
        @($script:state.Changes).Count | Should -Be 0
        @($script:state.Decisions | Where-Object { $_.Id -eq 'S-7.4-uro' })[0].Decision | Should -Be 'NoOp'
    }

    It 'rolls URO back to its recorded prior state' {
        $script:calls = New-Object System.Collections.ArrayList
        Mock Invoke-OptNativeCommand {
            [void]$script:calls.Add(@($ArgumentList) -join ' ')
            return @{ Success = $true; ExitCode = 0; StdOut = 'Ok.'; StdErr = '' }
        }
        $change = @{ Type = 'NetshUdpGlobal'; Target = @{ Setting = 'uro' }; OldValue = 'enabled'; NewValue = 'disabled'; Reversible = 'Full' }
        $r = Invoke-OptRollbackEntry -State $script:state -Change $change
        $r.Result | Should -Be 'RESTORED'
        $script:calls | Should -Contain 'int udp set global uro=enabled'
        Get-OptRollbackDescription -Change $change | Should -Match 'udp'
    }
}

Describe 'Section 7.5 - NIC interrupt affinity' {

    BeforeEach {
        $script:state = New-Cs2OptTestState -Tier 'Experimental' -PathsRoot (Join-Path $TestDrive "irq-$([guid]::NewGuid())")
        $script:state.Profile = New-Cs2OptTestProfile @{
            'CPU.LogicalCores' = 8; 'CPU.SmtEnabled' = $false
            'Network.ActiveAdapterName' = 'TestNic'
            'Network.Adapters' = @([ordered]@{
                Name = 'TestNic'; PnpDeviceId = 'PCI\VEN_10EC&DEV_8125\FIXTURE'
                MsiSupported = 1; InterruptPolicy = $null; InterruptMask = $null
            })
        }
    }
    AfterEach {
        Remove-Cs2OptTestState -State $script:state
    }

    It 'writes the documented affinity policy for logical CPU 0 and rolls it back to nothing' {
        $sandbox = $script:state['SandboxRoot']
        New-Item -Path "HKCU:\$sandbox" -Force | Out-Null
        $before = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox

        Invoke-OptSection75InterruptAffinity -State $script:state

        # Assert the writes happened before asserting the rollback (the
        # vacuous-pass lesson from the REG_BINARY test).
        $changes = @($script:state.Changes)
        $changes.Count | Should -Be 2
        $keyPath = "HKCU:\$sandbox\HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_10EC&DEV_8125\FIXTURE\Device Parameters\Interrupt Management\Affinity Policy"
        (Get-ItemProperty -LiteralPath $keyPath -Name 'DevicePolicy').DevicePolicy | Should -Be 4
        $mask = (Get-ItemProperty -LiteralPath $keyPath -Name 'AssignmentSetOverride').AssignmentSetOverride
        [System.BitConverter]::ToString([byte[]]$mask) | Should -Be '01-00-00-00-00-00-00-00'
        @($script:state.Decisions | Where-Object { $_.Id -eq 'S-7.5-NOTE' }).Count | Should -Be 1

        Write-OptManifest -State $script:state -Final
        Invoke-OptRollback -State $script:state -ManifestPath $script:state.Paths.RunManifest | Out-Null

        Compare-Cs2OptSnapshot -Before $before -After (Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox) | Should -BeNullOrEmpty
    }

    It 'uses the 0+1 pair when SMT is on' {
        $script:state.Profile.CPU.SmtEnabled = $true
        Invoke-OptSection75InterruptAffinity -State $script:state
        $keyPath = "HKCU:\$($script:state['SandboxRoot'])\HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_10EC&DEV_8125\FIXTURE\Device Parameters\Interrupt Management\Affinity Policy"
        $mask = (Get-ItemProperty -LiteralPath $keyPath -Name 'AssignmentSetOverride').AssignmentSetOverride
        [System.BitConverter]::ToString([byte[]]$mask) | Should -Be '03-00-00-00-00-00-00-00'
    }

    It 'leaves a policy someone else configured alone' {
        $script:state.Profile.Network.Adapters[0].InterruptPolicy = 1
        $script:state.Profile.Network.Adapters[0].InterruptMask = '0F000000'
        Invoke-OptSection75InterruptAffinity -State $script:state
        @($script:state.Changes).Count | Should -Be 0
        @($script:state.Decisions | Where-Object { $_.Id -eq 'S-7.5' })[0].Decision | Should -Be 'Manual'
    }

    It 'refuses below the Experimental tier' {
        $script:state.Tier = 'Aggressive'
        Invoke-OptSection75InterruptAffinity -State $script:state
        @($script:state.Changes).Count | Should -Be 0
        @($script:state.Decisions | Where-Object { $_.Id -eq 'S-7.5' })[0].Decision | Should -Be 'Off'
    }
}

Describe 'Detection helpers added with the 2026 research pass' {

    It 'reads CS2 launch options from a localconfig.vdf tree by exact key, ignoring decoys' {
        $vdf = @'
"UserLocalConfigStore"
{
    "friends"
    {
        "730"        { "LaunchOptions" "-decoy-friend" }
    }
    "Software"
    {
        "Valve"
        {
            "Steam"
            {
                "apps"
                {
                    "7300"   { "LaunchOptions" "-decoy-prefix" }
                    "730"
                    {
                        "LastPlayed"     "1700000000"
                        "LaunchOptions"  "+fps_max 600 -nojoy -console"
                        "cloud"          { "last_sync_state" "synchronized" }
                    }
                    "570"    { "LaunchOptions" "-decoy-other" }
                }
            }
        }
    }
}
'@
        Get-OptCs2LaunchOptions -Parsed (ConvertFrom-OptVdf -Text $vdf) | Should -Be '+fps_max 600 -nojoy -console'
    }

    It 'distinguishes "no launch options set" from "nothing known"' {
        $withBlock = '"UserLocalConfigStore" { "Software" { "Valve" { "Steam" { "apps" { "730" { "LastPlayed" "1" } } } } } }'
        Get-OptCs2LaunchOptions -Parsed (ConvertFrom-OptVdf -Text $withBlock) | Should -Be ''

        $noBlock = '"UserLocalConfigStore" { "Software" { "Valve" { "Steam" { "apps" { "570" { "LaunchOptions" "x" } } } } } }'
        Get-OptCs2LaunchOptions -Parsed (ConvertFrom-OptVdf -Text $noBlock) | Should -BeNullOrEmpty
        Get-OptCs2LaunchOptions -Parsed $null | Should -BeNullOrEmpty
    }

    It 'reviews launch options against the checklist advice' {
        $ok = Get-OptCs2LaunchOptionsReview -Options '+fps_max 600 -nojoy -console' -GpuVendor 'AMD' -MaxRefreshHz 540
        $ok | Should -Match 'Currently set:\s+\+fps_max 600 -nojoy -console'
        $ok | Should -Match 'nothing to change'

        $bad = Get-OptCs2LaunchOptionsReview -Options '-high -threads 8 -novid -noreflex +fps_max 300' -GpuVendor 'AMD' -MaxRefreshHz 540
        $bad | Should -Match '-high'
        $bad | Should -Match '-threads'
        $bad | Should -Match '-novid'
        $bad | Should -Match 'noreflex is inert'
        $bad | Should -Match '-nojoy is missing'
        $bad | Should -Match 'fps_max 300 is BELOW'

        # -noreflex is a legitimate NVIDIA experiment, not a flag there.
        (Get-OptCs2LaunchOptionsReview -Options '-noreflex -nojoy' -GpuVendor 'NVIDIA' -MaxRefreshHz 240) | Should -Not -Match 'noreflex is inert'

        # Nothing read -> nothing rendered; empty string -> "(none)".
        Get-OptCs2LaunchOptionsReview -Options $null -GpuVendor 'AMD' -MaxRefreshHz 540 | Should -Be ''
        Get-OptCs2LaunchOptionsReview -Options '' -GpuVendor 'AMD' -MaxRefreshHz 540 | Should -Match '\(none\)'
    }

    It 'annotates known overlay / RGB suites in the startup inventory and nothing else' {
        Get-OptStartupEntryNote -Name 'Discord' -Command '"C:\Users\x\AppData\Local\Discord\Update.exe" --processStart Discord.exe' | Should -Match 'overlay'
        Get-OptStartupEntryNote -Name 'LGHUB' -Command '"C:\Program Files\LGHUB\lghub.exe" --background' | Should -Match 'RGB'
        Get-OptStartupEntryNote -Name 'SecurityHealth' -Command 'C:\Windows\system32\SecurityHealthSystray.exe' | Should -Be ''
        # 'obs' must not match inside unrelated words.
        Get-OptStartupEntryNote -Name 'Jobs Scheduler' -Command 'C:\Tools\jobs.exe' | Should -Be ''
    }
}

Describe 'Release update check' {

    It 'compares versions with or without the v prefix' {
        (Compare-OptReleaseVersion -Current '1.0.7' -Latest 'v1.0.8').Newer  | Should -BeTrue
        (Compare-OptReleaseVersion -Current 'v1.0.8' -Latest 'v1.0.8').Newer | Should -BeFalse
        (Compare-OptReleaseVersion -Current '1.0.9' -Latest 'v1.0.8').Newer  | Should -BeFalse
        (Compare-OptReleaseVersion -Current '1.0.7' -Latest 'v1.10.0').Newer | Should -BeTrue -Because 'numeric, not lexical'
    }

    It 'never reports an update from a tag it cannot parse' {
        (Compare-OptReleaseVersion -Current '1.0.7' -Latest 'nightly').Newer | Should -BeNullOrEmpty
        (Compare-OptReleaseVersion -Current '' -Latest 'v1.0.8').Newer       | Should -BeNullOrEmpty
        (Compare-OptReleaseVersion -Current $null -Latest $null).Newer       | Should -BeNullOrEmpty
    }

    It 'announces a newer release and records it on the state' {
        Mock Get-OptLatestRelease { @{ TagName = 'v9.9.9'; Url = 'https://example.invalid/rel' } }
        $state = New-OptState -Tier 'Safe' -Parameters @{}
        $r = Invoke-OptUpdateCheck -State $state -CurrentVersion '1.0.8'
        $r.Checked | Should -BeTrue
        $r.Newer   | Should -BeTrue
        $state['UpdateCheck'].Latest | Should -Be 'v9.9.9'
    }

    It 'swallows every network failure and lets the run continue' {
        Mock Get-OptLatestRelease { throw 'The remote name could not be resolved' }
        $state = New-OptState -Tier 'Safe' -Parameters @{}
        $r = $null
        { $r = Invoke-OptUpdateCheck -State $state -CurrentVersion '1.0.8' } | Should -Not -Throw
        $r = $state['UpdateCheck']
        $r.Checked | Should -BeFalse
        $r.Newer   | Should -BeNullOrEmpty
        $r.Note    | Should -Match 'resolved'
    }
}

Describe 'Report auto-open' {
    # The launcher is injected: nothing here opens a window.

    BeforeEach {
        $script:state = New-Cs2OptTestState -Tier 'Safe' -PathsRoot (Join-Path $TestDrive "rep-$([guid]::NewGuid())")
        Set-Content -LiteralPath $script:state.Paths.Report -Value '# report' -Encoding UTF8
        $script:opened = New-Object System.Collections.ArrayList
        $script:launcher = { param($path) [void]$script:opened.Add($path) }
    }
    AfterEach { Remove-Cs2OptTestState -State $script:state }

    It 'opens the report that the run just wrote' {
        $r = Open-OptReport -State $script:state -Launcher $script:launcher
        $r | Should -BeTrue
        @($script:opened) | Should -Be @($script:state.Paths.Report)
    }

    It 'stays closed with -NoOpenReport' {
        $script:state.Parameters['NoOpenReport'] = $true
        Open-OptReport -State $script:state -Launcher $script:launcher | Should -BeFalse
        @($script:opened).Count | Should -Be 0
    }

    It 'does nothing when no report was written' {
        Remove-Item -LiteralPath $script:state.Paths.Report -Force
        Open-OptReport -State $script:state -Launcher $script:launcher | Should -BeFalse
        @($script:opened).Count | Should -Be 0
    }

    It 'never lets a launcher failure surface as an error' {
        $boom = { param($path) throw 'no association' }
        { Open-OptReport -State $script:state -Launcher $boom } | Should -Not -Throw
        Open-OptReport -State $script:state -Launcher $boom | Should -BeFalse
    }
}

Describe 'Section 3.3 - compatibility flags are idempotent' {
    # The Program Compatibility Assistant rewrites the Layers value with a
    # trailing space when the game launches. That must not read as drift.

    BeforeEach {
        $script:state = New-Cs2OptTestState -Tier 'Safe' -PathsRoot (Join-Path $TestDrive "l33-$([guid]::NewGuid())")
        $script:state.Profile = New-Cs2OptTestProfile @{}
        $script:exe = [string]$script:state.Profile.Games.Cs2ExePath
        $script:layers = "HKCU:\$($script:state['SandboxRoot'])\HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        New-Item -Path $script:layers -Force | Out-Null
    }
    AfterEach { Remove-Cs2OptTestState -State $script:state }

    It 'records nothing when the flag is already present, even with PCA''s trailing space' {
        New-ItemProperty -Path $script:layers -Name $script:exe -Value '~ HIGHDPIAWARE DISABLEDXMAXIMIZEDWINDOWEDMODE ' -PropertyType String -Force | Out-Null
        Invoke-OptSection33PerApp -State $script:state
        @($script:state.Changes | Where-Object { $_.Path -like '*Layers*' }).Count | Should -Be 0
        @($script:state.Decisions | Where-Object { $_.Id -eq 'S-3.3-LAYERS' })[0].Decision | Should -Be 'NoOp'
        # Untouched, trailing space and all.
        (Get-ItemProperty -LiteralPath $script:layers).PSObject.Properties[$script:exe].Value | Should -Be '~ HIGHDPIAWARE DISABLEDXMAXIMIZEDWINDOWEDMODE '
    }

    It 'merges the flag into existing flags rather than replacing them' {
        New-ItemProperty -Path $script:layers -Name $script:exe -Value '~ HIGHDPIAWARE' -PropertyType String -Force | Out-Null
        Invoke-OptSection33PerApp -State $script:state
        @($script:state.Changes | Where-Object { $_.Path -like '*Layers*' }).Count | Should -Be 1
        (Get-ItemProperty -LiteralPath $script:layers).PSObject.Properties[$script:exe].Value | Should -Be '~ HIGHDPIAWARE DISABLEDXMAXIMIZEDWINDOWEDMODE'
    }
}

Describe 'Section 2.4 - device power management reports what actually happened' {

    It 'records the NIC change only when the after-state confirms it' {
        (Resolve-OptDevicePowerOutcome -Before 'Enabled' -After 'Disabled' -Success $true -DryRun $false).Record   | Should -BeTrue
        (Resolve-OptDevicePowerOutcome -Before 'Enabled' -After 'Disabled' -Success $true -DryRun $false).Decision | Should -Be 'Applied'

        $stuck = Resolve-OptDevicePowerOutcome -Before 'Enabled' -After 'Enabled' -Success $true -DryRun $false
        $stuck.Record   | Should -BeFalse
        $stuck.Decision | Should -Be 'Unverified'

        $blind = Resolve-OptDevicePowerOutcome -Before $null -After $null -Success $true -DryRun $false
        $blind.Record   | Should -BeTrue -Because 'rollback must still be able to re-enable it'
        $blind.Decision | Should -Be 'Unverified'

        (Resolve-OptDevicePowerOutcome -Before 'Enabled' -After $null -Success $false -DryRun $false -ErrorText 'boom').Decision | Should -Be 'Failed'
        (Resolve-OptDevicePowerOutcome -Before 'Enabled' -After $null -Success $true -DryRun $true).Decision | Should -Be 'Applied'
    }

    It 'classifies USB endpoints as changed, already off, refused or missing from real reads' {
        $state = New-Cs2OptTestState -Tier 'Safe' -PathsRoot (Join-Path $TestDrive "usb-$([guid]::NewGuid())")
        try {
            # Fake WMI nodes: 'accept' flips when written, 'stubborn' ignores the write.
            $nodes = @{
                'USB\ACCEPT\1'   = [pscustomobject]@{ InstanceName = 'USB\ACCEPT\1_0';   Enable = $true }
                'USB\STUBBORN\1' = [pscustomobject]@{ InstanceName = 'USB\STUBBORN\1_0'; Enable = $true }
                'USB\OFF\1'      = [pscustomobject]@{ InstanceName = 'USB\OFF\1_0';      Enable = $false }
            }
            $get = { param($id) if ($nodes.ContainsKey($id)) { @($nodes[$id]) } else { @() } }.GetNewClosure()
            $set = { param($n) if ($n.InstanceName -like 'USB\ACCEPT*') { $n.Enable = $false } }

            $r = Invoke-OptUsbPowerSweep -State $state -InstanceIds @('USB\ACCEPT\1', 'USB\STUBBORN\1', 'USB\OFF\1', 'USB\GONE\1') -GetNodes $get -DisableNode $set
            @($r.Changed)    | Should -Be @('USB\ACCEPT\1')
            @($r.Refused)    | Should -Be @('USB\STUBBORN\1')
            @($r.AlreadyOff) | Should -Be @('USB\OFF\1')
            @($r.Missing)    | Should -Be @('USB\GONE\1')
            @($r.Failed).Count | Should -Be 0

            # A second sweep is a no-op for the endpoint that accepted.
            $r2 = Invoke-OptUsbPowerSweep -State $state -InstanceIds @('USB\ACCEPT\1') -GetNodes $get -DisableNode $set
            @($r2.AlreadyOff) | Should -Be @('USB\ACCEPT\1')
            @($r2.Changed).Count | Should -Be 0
        }
        finally { Remove-Cs2OptTestState -State $state }
    }
}

Describe 'No-unrecorded-mutation invariant' {

    It 'records every value it changed, and changes nothing it did not record' {
        # The highest-value test in the suite. A round-trip test can never catch
        # "applied but not recorded", because it only ever replays what WAS
        # recorded - so that bug class is invisible to it.
        $state = New-Cs2OptTestState -PathsRoot (Join-Path $TestDrive "inv-$([guid]::NewGuid())")
        try {
            $sandbox = $state['SandboxRoot']
            New-Item -Path "HKCU:\$sandbox" -Force | Out-Null
            $before = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox

            Set-OptRegistryValue -State $state -Path 'HKLM:\SOFTWARE\A' -Name 'One'   -Type DWord  -Value 1     -Section '4.1' -Tier 'Safe' | Out-Null
            Set-OptRegistryValue -State $state -Path 'HKLM:\SOFTWARE\A' -Name 'Two'   -Type String -Value 'x'   -Section '4.1' -Tier 'Safe' | Out-Null
            Set-OptRegistryValue -State $state -Path 'HKCU:\SOFTWARE\B' -Name 'Three' -Type QWord  -Value 99    -Section '6.1' -Tier 'Safe' | Out-Null

            $after = Get-Cs2OptSandboxSnapshot -SandboxRoot $sandbox
            $actuallyChanged = @(Compare-Cs2OptSnapshot -Before $before -After $after)

            # Project the manifest onto the same "sub\name" key space the
            # snapshot uses, so the two sets are directly comparable.
            $recorded = @($state.Changes | ForEach-Object { "$($_.Target.SubKey)\$($_.Target.Name)" })

            # Both directions. A one-way check would miss either half.
            @($actuallyChanged | Where-Object { $recorded -notcontains $_ }) | Should -BeNullOrEmpty
            @($recorded | Where-Object { $actuallyChanged -notcontains $_ }) | Should -BeNullOrEmpty
        }
        finally { Remove-Cs2OptTestState -State $state }
    }
}
