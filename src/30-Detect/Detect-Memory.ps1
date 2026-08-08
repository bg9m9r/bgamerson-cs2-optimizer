function Get-OptMemorySkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        TotalMB = $null; UsableMB = $null; SpeedMTs = $null; ChannelCount = $null; ModuleCount = $null
        CommittedBytes = $null; AvailableMB = $null; CommitPercentOfRam = $null
        DdrGeneration = $null; LooksLikeJedecBase = $null
        MMAgent = [ordered]@{
            MemoryCompression = $null; PageCombining = $null
            ApplicationLaunchPrefetching = $null; ApplicationPreLaunch = $null
            OperationAPI = $null; MaxOperationAPIFiles = $null
            Available = $false
        }
    }
}

function Get-OptJedecBaseSpeed {
    <#
        Nominal JEDEC base for a DDR generation. Used only to flag
        "EXPO/XMP appears not enabled" in the report (spec 12) - never to change
        anything, since memory timings are firmware-side.
    #>
    [CmdletBinding()][OutputType([int])]
    param([Parameter(Mandatory)][AllowNull()]$SmbiosMemoryType)

    switch ([int]$SmbiosMemoryType) {
        26 { return 2133 }   # DDR4
        34 { return 4800 }   # DDR5
        default { return 0 }
    }
}

function Get-OptMemoryInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Memory' -UnknownSkeleton (Get-OptMemorySkeleton) -ScriptBlock {
        $cs      = Get-OptCimSafe -ClassName Win32_ComputerSystem | Select-Object -First 1
        $modules = @(Get-OptCimSafe -ClassName Win32_PhysicalMemory)

        # INSTALLED capacity, summed from the DIMMs - not
        # Win32_ComputerSystem.TotalPhysicalMemory, which reports memory
        # VISIBLE TO WINDOWS after the hardware reservation. On the reference
        # machine that difference is 32404 MB vs 32768 MB, and the 5.4.1 gate
        # compares against exactly 32768 - so using the OS-visible figure makes
        # a genuine 32 GB machine fail a ">= 32 GB" test.
        $totalMb  = $null
        $usableMb = $null
        if ($cs -and $cs.TotalPhysicalMemory) { $usableMb = [int]([long]$cs.TotalPhysicalMemory / 1MB) }

        $capacitySum = ($modules | Where-Object { $_.Capacity } | Measure-Object -Property Capacity -Sum).Sum
        if ($capacitySum -and [long]$capacitySum -gt 0) { $totalMb = [int]([long]$capacitySum / 1MB) }
        elseif ($null -ne $usableMb)                    { $totalMb = $usableMb }

        $speed = $null
        $ddrGen = $null
        $jedecBase = 0
        if ($modules -and $modules.Count -gt 0) {
            # ConfiguredClockSpeed is the speed actually in use; Speed is the
            # module's rated speed. The difference is exactly what tells you
            # whether EXPO/XMP is enabled.
            $configured = ($modules | Where-Object { $_.ConfiguredClockSpeed } |
                           Measure-Object -Property ConfiguredClockSpeed -Minimum).Minimum
            if ($configured) { $speed = [int]$configured }

            $smbiosType = ($modules | Select-Object -First 1).SMBIOSMemoryType
            $jedecBase = Get-OptJedecBaseSpeed -SmbiosMemoryType $smbiosType
            $ddrGen = switch ([int]$smbiosType) { 26 { 'DDR4' } 34 { 'DDR5' } default { $null } }
        }

        # --- commit charge ----------------------------------------------------
        # Deliberately NOT Get-Counter '\Memory\Committed Bytes': performance
        # counter PATH NAMES are localized, so that call fails outright on a
        # non-English Windows and would silently skip the 5.4.1 gate with a
        # confusing error. WMI class and property names are not localized.
        $committedBytes = $null
        $availableMb    = $null
        $perf = Get-OptCimSafe -ClassName Win32_PerfRawData_PerfOS_Memory | Select-Object -First 1
        if ($perf) {
            if ($null -ne $perf.CommittedBytes)  { $committedBytes = [long]$perf.CommittedBytes }
            if ($null -ne $perf.AvailableMBytes) { $availableMb    = [long]$perf.AvailableMBytes }
        }

        $commitPct = $null
        if ($committedBytes -and $totalMb -and $totalMb -gt 0) {
            $commitPct = [math]::Round(($committedBytes / 1MB) / $totalMb * 100, 1)
        }

        # --- MMAgent ----------------------------------------------------------
        # Cmdlet-backed, not plain registry values, so these need a dedicated
        # recorder and rollback path (spec 5.4). Record the ACTUAL current state:
        # on this machine both are already False, and a rollback that assumed
        # Windows defaults would ENABLE them - a state the user has never been in.
        $mm = Get-OptMemorySkeleton
        $mmState = $mm.MMAgent
        try {
            $agent = Get-MMAgent -ErrorAction Stop
            if ($agent) {
                $mmState.MemoryCompression            = [bool]$agent.MemoryCompression
                $mmState.PageCombining                = [bool]$agent.PageCombining
                $mmState.ApplicationLaunchPrefetching = [bool]$agent.ApplicationLaunchPrefetching
                $mmState.ApplicationPreLaunch         = [bool]$agent.ApplicationPreLaunch
                $mmState.OperationAPI                 = [bool]$agent.OperationAPI
                $mmState.MaxOperationAPIFiles         = [int]$agent.MaxOperationAPIFiles
                $mmState.Available                    = $true
            }
        }
        catch {
            $mmState.Available = $false
        }

        [ordered]@{
            TotalMB            = $totalMb
            UsableMB           = $usableMb
            SpeedMTs           = $speed
            ChannelCount       = $null
            ModuleCount        = @($modules).Count
            CommittedBytes     = $committedBytes
            AvailableMB        = $availableMb
            CommitPercentOfRam = $commitPct
            DdrGeneration      = $ddrGen
            LooksLikeJedecBase = $(if ($speed -and $jedecBase -gt 0) { ($speed -le $jedecBase) } else { $null })
            MMAgent            = $mmState
        }
    }
}
