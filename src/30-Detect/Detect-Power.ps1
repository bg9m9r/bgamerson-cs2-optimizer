function Get-OptPowerSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        ActiveSchemeGuid = $null; ActiveSchemeName = $null; Schemes = @()
        IsLaptop = $null; HasBattery = $null; OnAcPower = $null
        SupportsModernStandby = $null; AvailableSleepStates = @()
        UltimatePerformanceGuid = $null
    }
}

function Get-OptSleepStates {
    <#
        Parses `powercfg /a`, which has TWO sections:

            The following sleep states are available on this system:
                ...
            The following sleep states are not available on this system:
                ...

        A naive `powercfg /a | Select-String 'S0 Low Power Idle'` matches text in
        EITHER section and therefore reports the OPPOSITE answer on machines
        where S0ix is listed as unavailable. Verified on the reference machine:
        S0 Low Power Idle appears under "not available", so the naive check
        returns $true when the correct answer is $false.

        Returns only the states in the AVAILABLE section.
    #>
    [CmdletBinding()][OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text)

    $lines = Get-OptCommandLines -Text $Text
    if ($lines.Count -eq 0) { return , @() }

    $available = @()
    $inAvailable = $false

    foreach ($line in $lines) {
        # Order matters: test the negative header FIRST, because it is a
        # superstring of the positive one.
        if ($line -match 'sleep states are not available|not available on this system') {
            $inAvailable = $false
            continue
        }
        if ($line -match 'sleep states are available|available on this system') {
            $inAvailable = $true
            continue
        }
        if (-not $inAvailable) { continue }

        # Indented state names; skip the indented explanatory sentences that
        # follow an unavailable state.
        $t = $line.Trim()
        if ($t -match '^(Standby|Hibernate|Hybrid Sleep|Fast Startup|S\d)' ) {
            $available += $t
        }
    }

    return , @($available)
}

function Get-OptPowerSchemes {
    <#
        Parses `powercfg /L` lines of the form:
            Power Scheme GUID: 381b4222-...  (Balanced) *
        The trailing asterisk marks the active scheme.
    #>
    [CmdletBinding()][OutputType([array])]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text)

    $schemes = @()
    foreach ($line in (Get-OptCommandLines -Text $Text)) {
        if ($line -match 'GUID:\s*([0-9a-fA-F-]{36})\s*\(([^)]*)\)\s*(\*)?') {
            $schemes += [ordered]@{
                Guid     = $Matches[1].ToLowerInvariant()
                Name     = $Matches[2].Trim()
                IsActive = ($Matches[3] -eq '*')
            }
        }
    }
    return , @($schemes)
}

function Get-OptPowerInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Power' -UnknownSkeleton (Get-OptPowerSkeleton) -ScriptBlock {
        # Canonical built-in Ultimate Performance GUID. On the reference machine
        # this scheme ALREADY exists and is already active - so section 2.1 must
        # reuse it. A blind `powercfg -duplicatescheme` creates a second copy
        # every run, which is the main idempotency trap in that section.
        $ultimateGuid = '682abefa-2beb-44cf-ad85-84c45fd50e03'

        $listResult = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/L') -ReadOnly
        $schemes = Get-OptPowerSchemes -Text $listResult.StdOut

        $active = $schemes | Where-Object { $_.IsActive } | Select-Object -First 1
        if (-not $active) {
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/getactivescheme') -ReadOnly
            $parsed = Get-OptPowerSchemes -Text $r.StdOut
            $active = $parsed | Select-Object -First 1
        }

        $aResult = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/a') -ReadOnly
        $sleepStates = Get-OptSleepStates -Text $aResult.StdOut

        # --- chassis / battery ------------------------------------------------
        $battery = @(Get-OptCimSafe -ClassName Win32_Battery)
        $hasBattery = ($battery.Count -gt 0)

        $enclosure = Get-OptCimSafe -ClassName Win32_SystemEnclosure | Select-Object -First 1
        $laptopChassis = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
        $isLaptopChassis = $false
        if ($enclosure -and $enclosure.ChassisTypes) {
            foreach ($t in @($enclosure.ChassisTypes)) {
                if ($laptopChassis -contains [int]$t) { $isLaptopChassis = $true }
            }
        }

        $onAc = $null
        if ($hasBattery) {
            $b = $battery | Select-Object -First 1
            # BatteryStatus 2 = AC connected.
            if ($null -ne $b.BatteryStatus) { $onAc = ([int]$b.BatteryStatus -eq 2) }
        }
        else { $onAc = $true }

        $existingUltimate = $schemes | Where-Object { $_.Guid -eq $ultimateGuid } | Select-Object -First 1

        [ordered]@{
            ActiveSchemeGuid        = $(if ($active) { $active.Guid } else { $null })
            ActiveSchemeName        = $(if ($active) { $active.Name } else { $null })
            Schemes                 = $schemes
            IsLaptop                = ($hasBattery -or $isLaptopChassis)
            HasBattery              = $hasBattery
            ChassisTypes            = $(if ($enclosure) { @($enclosure.ChassisTypes) } else { @() })
            OnAcPower               = $onAc
            AvailableSleepStates    = $sleepStates
            # S0ix machines ignore some legacy timeouts. Spec says log it rather
            # than fight it - apply the settings but do not report them as
            # effective without verification.
            SupportsModernStandby   = [bool](@($sleepStates | Where-Object { $_ -match 'S0 Low Power Idle' }).Count)
            UltimatePerformanceGuid = $(if ($existingUltimate) { $existingUltimate.Guid } else { $null })
            UltimatePerformanceExists = ($null -ne $existingUltimate)
        }
    }
}
