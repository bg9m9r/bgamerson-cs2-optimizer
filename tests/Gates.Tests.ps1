BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    foreach ($f in (Get-Cs2OptSourceFiles)) { . $f }
}

Describe 'Gate matrix - structural invariants' {

    It 'every row has the fields the resolver depends on' {
        foreach ($row in (Get-OptGateMatrix)) {
            $row.Id              | Should -Not -BeNullOrEmpty
            $row.Section         | Should -Not -BeNullOrEmpty
            $row.Title           | Should -Not -BeNullOrEmpty
            $row.Reason          | Should -Not -BeNullOrEmpty
            $row.Kind            | Should -Not -BeNullOrEmpty
            $row.When            | Should -BeOfType [scriptblock]
            # The fail-safe rule is only mechanical if EVERY row states what an
            # indeterminate predicate means. A missing policy would silently
            # fall back to PowerShell truthiness.
            $row.OnIndeterminate | Should -BeIn @('Block', 'Allow') -Because "row $($row.Id) must declare an indeterminate policy"
        }
    }

    It 'has unique gate ids' {
        $ids = @(Get-OptGateMatrix | ForEach-Object { $_.Id })
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
    }

    It 'evaluates every row without throwing, on a profile where everything is unknown' {
        # The nastiest input: every field null. Nothing may throw, and the
        # fail-safe policy must decide each row.
        $empty = [ordered]@{
            OS = [ordered]@{}; CPU = [ordered]@{}; GPU = [ordered]@{ Adapters = @() }
            Memory = [ordered]@{ MMAgent = [ordered]@{} }; Storage = [ordered]@{ Volumes = @() }
            Network = [ordered]@{ Adapters = @() }; Display = [ordered]@{ Displays = @() }
            Audio = [ordered]@{}; Input = [ordered]@{}; Power = [ordered]@{}
            Security = [ordered]@{ AntiCheat = @() }; Games = [ordered]@{}
            Boot = [ordered]@{}; Virtualization = [ordered]@{}
        }

        { Resolve-OptGates -ProfileData $empty -Tier 'Aggressive' } | Should -Not -Throw

        $result = Resolve-OptGates -ProfileData $empty -Tier 'Aggressive'
        @($result.Decisions | Where-Object { $_.Reason -like '*predicate error*' }) | Should -BeNullOrEmpty
    }
}

Describe 'Gate matrix - hardware conditions' {

    It 'aborts inside a virtual machine' {
        $p = New-Cs2OptTestProfile @{ 'Virtualization.IsVirtualMachine' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.Abort | Should -BeTrue
    }

    It 'clamps a laptop down to the Safe tier' {
        $p = New-Cs2OptTestProfile @{ 'Power.IsLaptop' = $true; 'Power.HasBattery' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'
        $r.Tier | Should -Be 'Safe'
        $r.BlockedSections | Should -Contain '2.1'
    }

    It 'never RAISES the tier' {
        $p = New-Cs2OptTestProfile @{ 'Power.IsLaptop' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe'
        $r.Tier | Should -Be 'Safe'
    }

    It 'skips IFEO High priority on an Intel hybrid part' {
        $p = New-Cs2OptTestProfile @{
            'CPU.Vendor' = 'Intel'; 'CPU.HasHybridTopology' = $true; 'CPU.Microarch' = 'RaptorLake'
        }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.BlockedSections | Should -Contain '6.4'
    }

    It 'skips IFEO High priority below 8 logical cores' {
        $p = New-Cs2OptTestProfile @{ 'CPU.LogicalCores' = 4; 'CPU.HasHybridTopology' = $false }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.BlockedSections | Should -Contain '6.4'
    }

    It 'allows IFEO High priority at exactly 8 logical cores on a non-hybrid part' {
        # The reference machine sits exactly on this boundary (8C/8T, SMT off).
        $p = New-Cs2OptTestProfile @{ 'CPU.LogicalCores' = 8; 'CPU.HasHybridTopology' = $false }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.BlockedSections | Should -Not -Contain '6.4'
    }

    It 'blocks IFEO High priority when the core count is UNKNOWN' {
        # Unknown means skip, not guess.
        $p = New-Cs2OptTestProfile @{ 'CPU.LogicalCores' = $null }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.BlockedSections | Should -Contain '6.4'
    }

    It 'selects exactly one vendor GPU checklist' -ForEach @(
        @{ Vendor = 'AMD';    Expected = '3.4'; Blocked = @('3.5', '3.6') }
        @{ Vendor = 'NVIDIA'; Expected = '3.5'; Blocked = @('3.4', '3.6') }
        @{ Vendor = 'Intel';  Expected = '3.6'; Blocked = @('3.4', '3.5') }
    ) {
        $p = New-Cs2OptTestProfile @{ 'GPU.PrimaryVendor' = $Vendor }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.BlockedSections | Should -Not -Contain $Expected
        foreach ($b in $Blocked) { $r.BlockedSections | Should -Contain $b }
    }

    It 'applies no vendor GPU checklist when the vendor is unknown' {
        $p = New-Cs2OptTestProfile @{ 'GPU.PrimaryVendor' = 'Unknown' }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        foreach ($s in @('3.4', '3.5', '3.6')) { $r.BlockedSections | Should -Contain $s }
    }

    It 'skips memory-compression disable under 32 GB' {
        $p = New-Cs2OptTestProfile @{ 'Memory.TotalMB' = 16384 }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'
        $r.BlockedSections | Should -Contain '5.4.1'
    }

    It 'skips memory-compression disable when commit charge is already high' {
        # Headroom, not capacity, is what matters.
        $p = New-Cs2OptTestProfile @{ 'Memory.TotalMB' = 65536; 'Memory.CommitPercentOfRam' = 72.5 }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'
        $r.BlockedSections | Should -Contain '5.4.1'
    }

    It 'allows memory-compression disable on a roomy machine' {
        $p = New-Cs2OptTestProfile @{ 'Memory.TotalMB' = 32768; 'Memory.CommitPercentOfRam' = 30 }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'
        $r.BlockedSections | Should -Not -Contain '5.4.1'
    }

    It 'keeps SysMain enabled when a spinning disk is present' {
        $p = New-Cs2OptTestProfile @{ 'Storage.HasHdd' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'
        $r.BlockedSections | Should -Contain '5.5'
    }

    It 'skips NIC tuning on a wireless adapter' {
        $p = New-Cs2OptTestProfile @{ 'Network.ActiveIsWireless' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.BlockedSections | Should -Contain '7.1'
    }

    It 'flags an inbox NIC driver as a finding rather than silently failing' {
        $p = New-Cs2OptTestProfile @{ 'Network.ActiveDriverProvider' = 'Microsoft' }
        $d = Get-Cs2OptGateDecision -ProfileData $p -GateId 'G-7.1-INBOX'
        $d.Decision | Should -Be 'Finding'
    }

    It 'skips every CS2 path-dependent section when CS2 is absent' {
        $p = New-Cs2OptTestProfile @{ 'Games.Cs2Installed' = $false }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        foreach ($s in @('3.3', '6.4', '9.1', '11')) { $r.BlockedSections | Should -Contain $s }
    }

    It 'escalates Fast Startup on a dual-boot machine' {
        $p = New-Cs2OptTestProfile @{ 'Boot.IsDualBoot' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe'
        $r.Escalated | Should -Contain '2.3'
        # An escalation is the OPPOSITE of a block and must not render as one.
        $d = @($r.Decisions | Where-Object { $_.Id -eq 'G-2.3-DUALBOOT' })[0]
        $d.Decision | Should -Not -Be 'Off'
    }

    It 'skips refresh enforcement when already at max' {
        $p = New-Cs2OptTestProfile @{ 'Display.RefreshBelowMax' = $false }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe'
        $r.BlockedSections | Should -Contain '3.8'
    }

    It 'runs refresh enforcement when the display is below its max' {
        $p = New-Cs2OptTestProfile @{ 'Display.RefreshBelowMax' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe'
        $r.BlockedSections | Should -Not -Contain '3.8'
    }
}

Describe 'Gate matrix - blanket safety assertions' {

    # These matter more than any individual gate test: they survive future code
    # additions, so a newly added row cannot quietly sneak past them.

    It 'never permits anything VBS/hypervisor-adjacent while a kernel anti-cheat is present' {
        $p = New-Cs2OptTestProfile   # reference machine: FACEIT AC present
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'

        # The capability that actually gates the mutation chokepoints.
        $r.Capabilities['HypervisorOff'] | Should -BeFalse

        # The VBS-protection gate must have FIRED (Decision 'Off' = it blocked),
        # not merely been evaluated.
        $vbsGate = @($r.Decisions | Where-Object { $_.Id -eq 'G-10-VBS' })[0]
        $vbsGate.Decision | Should -Be 'Off'

        # And the HVCI experiment stays out of reach even at Experimental tier.
        $r.BlockedSections | Should -Contain '10.4'

        # The "no anti-cheat, VBS disable becomes available" note must NOT have
        # fired, since an anti-cheat IS present.
        $noAcNote = @($r.Decisions | Where-Object { $_.Id -eq 'G-10-NOAC' })[0]
        $noAcNote.Decision | Should -Be 'On' -Because "'On' means the row's condition was not met, i.e. the note is correctly inert"
    }

    It 'raises a critical finding when FACEIT is present but VBS is off' {
        $p = New-Cs2OptTestProfile @{ 'Security.VbsRunning' = $false }
        $d = Get-Cs2OptGateDecision -ProfileData $p -GateId 'G-10-VBS-OFF'
        $d.Decision | Should -Be 'Finding'
        $d.Severity | Should -Be 'Critical'
    }

    It 'does NOT report an IOMMU failure when the state is merely indeterminate' {
        # A false positive here sends the user into their BIOS for nothing.
        $p = New-Cs2OptTestProfile @{ 'Security.IommuEnabled' = $null }
        $d = Get-Cs2OptGateDecision -ProfileData $p -GateId 'G-10-IOMMU-OFF'
        $d.Decision | Should -Not -Be 'Finding'
    }

    It 'reports an IOMMU failure when it is definitively off' {
        $p = New-Cs2OptTestProfile @{ 'Security.IommuEnabled' = $false }
        $d = Get-Cs2OptGateDecision -ProfileData $p -GateId 'G-10-IOMMU-OFF'
        $d.Decision | Should -Be 'Finding'
    }

    It 'blocks bcdedit whenever BitLocker is protecting a volume' {
        $p = New-Cs2OptTestProfile @{ 'Security.BitLockerAnyProtected' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe' -Options @{ BitLockerAcknowledged = $false }
        $r.Capabilities['BcdEdit'] | Should -BeFalse
    }

    It 'still permits bcdedit when BitLocker is acknowledged explicitly' {
        $p = New-Cs2OptTestProfile @{ 'Security.BitLockerAnyProtected' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe' -Options @{ BitLockerAcknowledged = $true }
        $r.Capabilities.Contains('BcdEdit') | Should -BeFalse
    }

    It 'blocks bcdedit when BitLocker state is UNKNOWN' {
        $p = New-Cs2OptTestProfile @{ 'Security.BitLockerAnyProtected' = $null }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Safe' -Options @{ BitLockerAcknowledged = $false }
        $r.Capabilities['BcdEdit'] | Should -BeFalse
    }

    It 'blocks policy writes on a managed device' -ForEach @(
        @{ Field = 'OS.IsDomainJoined' }
        @{ Field = 'OS.IsAzureAdJoined' }
        @{ Field = 'OS.IsMdmEnrolled' }
    ) {
        $p = New-Cs2OptTestProfile @{ $Field = $true; 'OS.IsManaged' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Aggressive'
        $r.Capabilities['PolicyWrites'] | Should -BeFalse
    }

    It 'blocks hypervisor disable when Hyper-V, WSL, Docker or Sandbox is in use' {
        $p = New-Cs2OptTestProfile @{ 'Virtualization.BlocksHypervisorOff' = $true }
        $r = Resolve-OptGates -ProfileData $p -Tier 'Experimental'
        $r.Capabilities['HypervisorOff'] | Should -BeFalse
    }
}

Describe 'Section gating' {

    It 'matches on prefix so a parent blocks its children' {
        Test-OptSectionMatch -Section '8.1' -Patterns @('8')   | Should -BeTrue
        Test-OptSectionMatch -Section '8'   -Patterns @('8')   | Should -BeTrue
        Test-OptSectionMatch -Section '3.5' -Patterns @('3.5') | Should -BeTrue
    }

    It 'does not let 3.5 swallow 3.55' {
        Test-OptSectionMatch -Section '3.55' -Patterns @('3.5') | Should -BeFalse
    }

    It 'accepts section symbols and S-prefixes from the command line' {
        Test-OptSectionMatch -Section '7.1' -Patterns @('S7')  | Should -BeTrue
        Test-OptSectionMatch -Section '7.1' -Patterns @('#7')  | Should -BeTrue
        Test-OptSectionMatch -Section '7.1' -Patterns @('7')   | Should -BeTrue
    }

    It 'treats -Sections as an allow-list' {
        $state = New-OptState -Tier 'Aggressive' -Parameters @{ Sections = @('7') }
        Test-OptSectionEnabled -State $state -Section '7.1' | Should -BeTrue
        Test-OptSectionEnabled -State $state -Section '4.1' | Should -BeFalse
    }

    It 'treats -ExcludeSections as a deny-list' {
        $state = New-OptState -Tier 'Aggressive' -Parameters @{ ExcludeSections = @('8') }
        Test-OptSectionEnabled -State $state -Section '8.7' | Should -BeFalse
        Test-OptSectionEnabled -State $state -Section '4.1' | Should -BeTrue
    }
}

Describe 'Tier gating' {

    It 'is cumulative' -ForEach @(
        @{ Run = 'Safe';         Required = 'Safe';         Expected = $true }
        @{ Run = 'Safe';         Required = 'Aggressive';   Expected = $false }
        @{ Run = 'Safe';         Required = 'Experimental'; Expected = $false }
        @{ Run = 'Aggressive';   Required = 'Safe';         Expected = $true }
        @{ Run = 'Aggressive';   Required = 'Aggressive';   Expected = $true }
        @{ Run = 'Aggressive';   Required = 'Experimental'; Expected = $false }
        @{ Run = 'Experimental'; Required = 'Experimental'; Expected = $true }
    ) {
        $state = New-OptState -Tier $Run -Parameters @{}
        Test-OptTier -State $state -Required $Required | Should -Be $Expected
    }

    It 'fails closed on an unknown tier tag' {
        $state = New-OptState -Tier 'Experimental' -Parameters @{}
        Test-OptTier -State $state -Required 'Nonsense' | Should -BeFalse
    }
}
