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
