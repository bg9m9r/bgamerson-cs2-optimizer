BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:LauncherSrc = Join-Path $script:RepoRoot 'launcher\Launch-CS2.ps1'

    # The guard makes dot-sourcing define the functions and stop before any
    # topology probing or game launching.
    $env:CS2OPT_LAUNCHER_TEST = '1'
    . $script:LauncherSrc
}

AfterAll {
    $env:CS2OPT_LAUNCHER_TEST = $null
}

Describe 'Launch-CS2 affinity plan' {

    It 'excludes logical CPUs 0 and 1 on an SMT machine' {
        # 8C/16T: physical core 0 owns the logical pair 0+1.
        $plan = Get-Cs2AffinityPlan -PhysicalCores 8 -LogicalCores 16
        $plan.Apply | Should -BeTrue
        $plan.ExcludedCpus | Should -Be @(0, 1)
        $plan.Mask | Should -Be 0xFFFC
    }

    It 'excludes only logical CPU 0 when SMT is off' {
        # The reference machine: 9850X3D with SMT disabled, 8C/8T.
        $plan = Get-Cs2AffinityPlan -PhysicalCores 8 -LogicalCores 8
        $plan.Apply | Should -BeTrue
        $plan.ExcludedCpus | Should -Be @(0)
        $plan.Mask | Should -Be 0xFE
    }

    It 'handles a 16C/32T part' {
        $plan = Get-Cs2AffinityPlan -PhysicalCores 16 -LogicalCores 32
        $plan.Apply | Should -BeTrue
        # Written as decimal on purpose: 5.1 parses the hex literal 0xFFFFFFFC
        # as int32 and wraps it to -4, which is not the mask being tested.
        $plan.Mask | Should -Be ([int64]4294967292)
    }

    It 'refuses on small-core parts where losing a core costs more' -ForEach @(
        @{ P = 4; L = 8 }
        @{ P = 4; L = 4 }
        @{ P = 2; L = 4 }
    ) {
        $plan = Get-Cs2AffinityPlan -PhysicalCores $P -LogicalCores $L
        $plan.Apply | Should -BeFalse
        $plan.Mask | Should -BeNullOrEmpty
        $plan.Reason | Should -Match 'physical cores'
    }

    It 'refuses beyond one processor group rather than computing a wrong mask' {
        $plan = Get-Cs2AffinityPlan -PhysicalCores 64 -LogicalCores 128
        $plan.Apply | Should -BeFalse
        $plan.Reason | Should -Match 'processor group'
    }

    It 'always leaves at least physical-minus-one cores in the mask' {
        # Bit-count sanity across a spread of real topologies.
        foreach ($topo in @(@(6,12), @(6,6), @(8,16), @(12,24), @(16,32), @(24,32))) {
            $plan = Get-Cs2AffinityPlan -PhysicalCores $topo[0] -LogicalCores $topo[1]
            if (-not $plan.Apply) { continue }
            $bits = 0
            $m = [int64]$plan.Mask
            while ($m -ne 0) { $bits += ($m -band 1); $m = $m -shr 1 }
            # @() wrap: the dot-sourced launcher's StrictMode applies here, and
            # a single-element ExcludedCpus unrolls to a bare int whose .Count
            # would then throw.
            $bits | Should -Be ($topo[1] - @($plan.ExcludedCpus).Count)
        }
    }
}

Describe 'Launch-CS2 affinity retry' {
    # No game is launched here. The test host itself stands in for cs2.exe:
    # with Mask equal to its current affinity the loop runs resolve / verify /
    # settle for real without changing anything. The Idle process (PID 0)
    # stands in for the "Access is denied" case - nothing can open it with
    # SET_INFORMATION, so it is a repeatable refusal with no risk of actually
    # changing anything.
    BeforeAll {
        $script:SelfMask = [int64](Get-Process -Id $PID).ProcessorAffinity
    }

    It 'is satisfied by a process that already carries the mask, after two clean passes' {
        $r = Invoke-Cs2AffinityApply -Mask $script:SelfMask -TimeoutSeconds 5 `
            -RetryMilliseconds 10 -SettleMilliseconds 0 `
            -ResolveProcesses { @(Get-Process -Id $PID) }
        $r.Ok | Should -BeTrue
        @($r.Applied).Count | Should -Be 0
        $r.Attempts | Should -Be 2
    }

    It 'keeps polling while cs2.exe is absent and succeeds once it appears' {
        $script:resolveCalls = 0
        $r = Invoke-Cs2AffinityApply -Mask $script:SelfMask -TimeoutSeconds 5 `
            -RetryMilliseconds 10 -SettleMilliseconds 0 `
            -ResolveProcesses { $script:resolveCalls++; if ($script:resolveCalls -le 3) { @() } else { @(Get-Process -Id $PID) } }
        $r.Ok | Should -BeTrue
        $r.Attempts | Should -BeGreaterThan 3
    }

    It 'retries a refusal until the deadline instead of failing on the first one' {
        $r = Invoke-Cs2AffinityApply -Mask 0xFE -TimeoutSeconds 1 `
            -RetryMilliseconds 50 -SettleMilliseconds 0 `
            -ResolveProcesses { @(Get-Process -Id 0) }
        $r.Ok | Should -BeFalse
        $r.Attempts | Should -BeGreaterThan 3
        $r.LastError | Should -Match '^PID 0:'
    }

    It 'gives up early when the game is gone, rather than waiting out the budget' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-Cs2AffinityApply -Mask 0xFE -TimeoutSeconds 60 `
            -RetryMilliseconds 10 -SettleMilliseconds 0 -ExitGraceMilliseconds 30 `
            -ResolveProcesses { @() }
        $sw.Stop()
        $r.Ok | Should -BeFalse
        $r.LastError | Should -Be 'cs2.exe exited'
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
    }

    It 'single attempt never throws on a refused process' {
        $r = Set-Cs2Affinity -Process (Get-Process -Id 0) -Mask 0xFE
        $r.Ok | Should -BeFalse
        $r.Changed | Should -BeFalse
        $r.Error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Launch-CS2 dist freshness' {

    It 'ships in dist, identical to the launcher source' {
        $distCopy = Join-Path $script:RepoRoot 'dist\Launch-CS2.ps1'
        Test-Path -LiteralPath $distCopy | Should -BeTrue -Because 'run build\Build-Script.ps1'

        (Get-FileHash -LiteralPath $distCopy -Algorithm SHA256).Hash |
            Should -Be (Get-FileHash -LiteralPath $script:LauncherSrc -Algorithm SHA256).Hash `
            -Because 'dist launcher is stale - re-run build\Build-Script.ps1 and commit'
    }

    It 'ships its cmd wrapper' {
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'dist\Launch-CS2.cmd') | Should -BeTrue
    }
}
