function Get-OptCpuSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Vendor = 'Unknown'; Name = $null; Family = $null; Model = $null; Stepping = $null
        PhysicalCores = $null; LogicalCores = $null
        Microarch = 'Unknown'; HasVCache = $null; CcdCount = $null
        HasHybridTopology = $null; PpmDriver = $null
        L3TotalMB = $null; SmtEnabled = $null
    }
}

function Get-OptCpuMicroarch {
    <#
        Family/Model -> microarchitecture.

        A miss returns 'Unknown', and callers must then treat every
        arch-specific decision as "skip" (spec 1.5.3). This is not a
        theoretical concern: the reference machine is a Ryzen 7 9850X3D
        reporting AMD64 Family 26 (0x1A) Model 68, and any table written before
        that part shipped misses it.

        Crucially, nothing structural depends on this table. HasHybridTopology
        and CcdCount both come from GetLogicalProcessorInformationEx, and
        HasVCache comes from the measured L3 size - so a table miss degrades the
        report text, not the safety of the gates.
    #>
    [CmdletBinding()][OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][string]$Vendor,
        [Parameter(Mandatory)][AllowNull()]$Family,
        [Parameter(Mandatory)][AllowNull()]$Model,
        [AllowNull()][string]$Name
    )

    if ($Name -and $Name -match 'Ryzen.*\b9\d{3}X3D\b') { return 'Zen5-X3D' }

    $f = 0; $m = 0
    [void][int]::TryParse([string]$Family, [ref]$f)
    [void][int]::TryParse([string]$Model,  [ref]$m)

    if ($Vendor -eq 'AMD') {
        switch ($f) {
            23 { return 'Zen2' }                      # 0x17
            25 { return 'Zen3/Zen4' }                 # 0x19 - both live here
            26 { return 'Zen5' }                      # 0x1A
            default { return 'Unknown' }
        }
    }
    elseif ($Vendor -eq 'Intel') {
        if ($f -eq 6) {
            switch ($m) {
                151 { return 'AlderLake' }   # 0x97
                154 { return 'AlderLake' }   # 0x9A
                183 { return 'RaptorLake' }  # 0xB7
                186 { return 'RaptorLake' }  # 0xBA
                191 { return 'RaptorLake' }  # 0xBF
                197 { return 'ArrowLake' }   # 0xC5
                198 { return 'ArrowLake' }   # 0xC6
                default { return 'Unknown' }
            }
        }
        return 'Unknown'
    }

    return 'Unknown'
}

function Get-OptCpuInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'CPU' -UnknownSkeleton (Get-OptCpuSkeleton) -ScriptBlock {
        $procs = @(Get-OptCimSafe -ClassName Win32_Processor)
        if (-not $procs -or $procs.Count -eq 0) { return $null }
        $cpu = $procs | Select-Object -First 1

        $vendor = 'Unknown'
        if ($cpu.Manufacturer -match 'AMD|AuthenticAMD')      { $vendor = 'AMD' }
        elseif ($cpu.Manufacturer -match 'Intel|GenuineIntel'){ $vendor = 'Intel' }

        # Sum across sockets rather than reading the first processor (spec 1.5.2).
        $wmiCores   = ($procs | Measure-Object -Property NumberOfCores -Sum).Sum
        $wmiLogical = ($procs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum

        # Topology straight from the OS. Preferred over WMI and over any table.
        $topo = Get-OptCpuTopology

        $physical = if ($null -ne $topo.PhysicalCores -and $topo.PhysicalCores -gt 0) { $topo.PhysicalCores } else { [int]$wmiCores }
        $logical  = if ($null -ne $topo.LogicalCores  -and $topo.LogicalCores  -gt 0) { $topo.LogicalCores }  else { [int]$wmiLogical }

        # --- V-Cache ----------------------------------------------------------
        # Win32_CacheMemory.Level is a WMI ENUM, not a cache level: Level 3 is
        # L1, Level 4 is L2, Level 5 is L3. Filtering on `Level -eq 3` looking
        # for "L3" silently returns the L1 caches and kills X3D detection.
        # Verified on this machine: Level 5 = 98304 KB = 96 MB.
        $l3Bytes = 0
        if ($topo.L3CacheBytesMax) {
            $l3Bytes = [long]$topo.L3CacheBytesMax
        }
        else {
            $l3 = Get-OptCimSafe -ClassName Win32_CacheMemory | Where-Object { $_.Level -eq 5 }
            if ($l3) { $l3Bytes = [long](($l3 | Measure-Object -Property MaxCacheSize -Maximum).Maximum) * 1024 }
        }
        $l3Mb = if ($l3Bytes -gt 0) { [int][math]::Round($l3Bytes / 1MB) } else { $null }

        # Name regex OR measured size, OR'd - name matching alone is fragile
        # for OEM SKUs, size alone would misfire on a future large-L3 non-X3D part.
        $hasVCache = $null
        if ($cpu.Name -match 'X3D') { $hasVCache = $true }
        elseif ($null -ne $l3Mb)    { $hasVCache = ($l3Mb -ge 96) }

        # --- PPM driver -------------------------------------------------------
        $ppm = $null
        $ppmDrivers = @(Get-OptCimSafe -ClassName Win32_SystemDriver -Filter "Name='amdppm' OR Name='intelppm' OR Name='processr'")
        $running = $ppmDrivers | Where-Object { $_.State -eq 'Running' } | Select-Object -First 1
        if ($running) { $ppm = $running.Name.ToLowerInvariant() }

        $family = $cpu.Family
        $model  = $null
        if ($cpu.Description -match 'Model\s+(\d+)') { $model = [int]$Matches[1] }
        $stepping = $null
        if ($cpu.Description -match 'Stepping\s+(\d+)') { $stepping = [int]$Matches[1] }

        [ordered]@{
            Vendor            = $vendor
            Name              = if ($cpu.Name) { $cpu.Name.Trim() } else { $null }
            Family            = $family
            Model             = $model
            Stepping          = $stepping
            PhysicalCores     = $physical
            LogicalCores      = $logical
            SmtEnabled        = $(if ($physical -gt 0) { ($logical -gt $physical) } else { $null })
            Microarch         = Get-OptCpuMicroarch -Vendor $vendor -Family $family -Model $model -Name $cpu.Name
            HasVCache         = $hasVCache
            L3TotalMB         = $l3Mb
            # From distinct L3 instances, not inferred from core count.
            CcdCount          = $topo.CcdCount
            # From distinct EfficiencyClass values. Derived from a DIRECT signal
            # rather than the microarch table on purpose: an unknown SKU would
            # otherwise make this indeterminate, which would skip section 6.4 on
            # a machine where it is entirely appropriate.
            HasHybridTopology = $topo.IsHybrid
            PpmDriver         = $ppm
            TopologySource    = $topo.Source
        }
    }
}
