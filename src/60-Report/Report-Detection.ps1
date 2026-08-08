<#
    The spec 1.5.5 detection report.

    Printed before anything is applied. Both this table and the section 14
    markdown report are projections of the SAME decision list produced by
    Resolve-OptGates - there is no second source of truth about why something
    was or was not done.
#>

function Write-OptDetectionReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile

    Write-OptLog -Level Header 'DETECTED'

    # --- CPU ---
    $cpuBits = @()
    if ($p.CPU.Microarch -ne 'Unknown') { $cpuBits += $p.CPU.Microarch }
    if ($null -ne $p.CPU.PhysicalCores) { $cpuBits += "$($p.CPU.PhysicalCores)C/$($p.CPU.LogicalCores)T" }
    if ($null -ne $p.CPU.CcdCount)      { $cpuBits += "$($p.CPU.CcdCount) CCD" }
    if ($p.CPU.HasVCache -eq $true)     { $cpuBits += "V-Cache $($p.CPU.L3TotalMB)MB" }
    if ($p.CPU.SmtEnabled -eq $false)   { $cpuBits += 'SMT off' }
    if ($p.CPU.HasHybridTopology -eq $true) { $cpuBits += 'hybrid P/E' }
    Write-OptLog -Level Plain ("  CPU      : {0} ({1})" -f ([string]$p.CPU.Name).Trim(), ($cpuBits -join ', '))

    # --- GPU ---
    foreach ($g in $p.GPU.Adapters) {
        $tag = if ($g.IsPrimary) { 'primary' } else { 'secondary' }
        $vram = if ($g.VramMB) { ", $([math]::Round($g.VramMB/1024))GB" } else { '' }
        Write-OptLog -Level Plain ("  GPU      : {0} ({1}, driver {2}{3})" -f $g.Name, $tag, $g.DriverVersion, $vram)
    }

    # --- memory / storage ---
    $memBits = @("$([math]::Round(([int]$p.Memory.TotalMB)/1024)) GB")
    if ($p.Memory.DdrGeneration) { $memBits += $p.Memory.DdrGeneration }
    if ($p.Memory.SpeedMTs)      { $memBits += "$($p.Memory.SpeedMTs) MT/s" }
    if ($null -ne $p.Memory.CommitPercentOfRam) { $memBits += "commit $($p.Memory.CommitPercentOfRam)%" }
    Write-OptLog -Level Plain ("  MEMORY   : {0}" -f ($memBits -join ', '))
    Write-OptLog -Level Plain ("  STORAGE  : boot {0}/{1}, {2} GB free, TRIM {3}" -f `
        $p.Storage.BootBusType, $p.Storage.BootMediaType, $p.Storage.BootFreeGB,
        $(if ($p.Storage.TrimEnabled) { 'on' } else { 'off' }))

    # --- display ---
    foreach ($d in $p.Display.Displays) {
        $tag = if ($d.IsPrimary) { 'primary' } else { 'secondary' }
        $rate = if ($d.RefreshBelowMax) { "$($d.CurrentRefreshHz) Hz of $($d.MaxRefreshHz) Hz available" }
                else { "$($d.CurrentRefreshHz) Hz (max)" }
        Write-OptLog -Level Plain ("  DISPLAY  : {0} {1}x{2} @ {3} [{4}]" -f $d.MonitorName, $d.Width, $d.Height, $rate, $tag)
    }

    # --- network ---
    $active = $p.Network.Adapters | Where-Object { $_.Name -eq $p.Network.ActiveAdapterName } | Select-Object -First 1
    if ($active) {
        Write-OptLog -Level Plain ("  NETWORK  : {0} ({1}), {2}, driver by {3}, {4} tunable keywords" -f `
            $active.Description, $active.Name, $active.LinkSpeed, $active.DriverProvider, @($active.SupportedKeywords).Count)
    }

    # --- audio / input ---
    if ($p.Audio.DefaultName) {
        Write-OptLog -Level Plain ("  AUDIO    : {0}{1}" -f $p.Audio.DefaultName, $(if ($p.Audio.DefaultIsHdmi) { ' [HDMI/DP - check this is intended]' } else { '' }))
    }
    if (@($p.Input.VendorUtilities).Count -gt 0) {
        Write-OptLog -Level Plain ("  INPUT    : {0} installed" -f ((@($p.Input.VendorUtilities) | ForEach-Object { $_.Name }) -join ', '))
    }

    # --- power / os ---
    Write-OptLog -Level Plain ("  POWER    : {0}{1}" -f $p.Power.ActiveSchemeName,
        $(if ($p.Power.SupportsModernStandby) { ', Modern Standby' } else { '' }))
    Write-OptLog -Level Plain ("  OS       : Windows build {0} {1} {2}{3}" -f `
        $p.OS.BuildNumber, $p.OS.DisplayVersion, $p.OS.Edition,
        $(if ($p.OS.HasNpu) { ', NPU present' } else { '' }))

    # --- security ---
    $sec = @(
        "Secure Boot $(Format-OptTriState $p.Security.SecureBootEnabled)"
        "TPM $(Format-OptTriState $p.Security.TpmReady)"
        "VBS $(Format-OptTriState $p.Security.VbsRunning)"
        "HVCI $(Format-OptTriState $p.Security.HvciRunning)"
        "IOMMU $(Format-OptTriState $p.Security.IommuEnabled)"
    )
    Write-OptLog -Level Plain ("  SECURITY : {0}" -f ($sec -join ', '))
    if (@($p.Security.BitLockerProtected).Count -gt 0) {
        Write-OptLog -Level Plain ("  BITLOCKER: protected on {0}" -f ((@($p.Security.BitLockerProtected) | ForEach-Object { $_.MountPoint }) -join ', '))
    }
    foreach ($ac in $p.Security.AntiCheat) {
        Write-OptLog -Level Plain ("  ANTICHEAT: {0} - services [{1}] drivers [{2}]" -f `
            $ac.Name, (@($ac.ServiceStates) -join ' '), (@($ac.DriverStates) -join ' '))
    }

    # --- games / boot ---
    if ($p.Games.SteamPath) {
        Write-OptLog -Level Plain ("  STEAM    : {0} ({1} librar{2})" -f $p.Games.SteamPath, @($p.Games.LibraryPaths).Count, $(if (@($p.Games.LibraryPaths).Count -eq 1) { 'y' } else { 'ies' }))
    }
    Write-OptLog -Level Plain ("  CS2      : {0}" -f $(if ($p.Games.Cs2Installed) { $p.Games.Cs2ExePath } else { 'not installed' }))
    Write-OptLog -Level Plain ("  BOOT     : {0}{1}, Fast Startup {2}" -f `
        $p.Boot.FirmwareType,
        $(if ($p.Boot.IsDualBoot) { ', dual-boot' } else { '' }),
        $(if ($p.Boot.FastStartupEnabled) { 'ON' } else { 'off' }))

    if (@($p.DetectionErrors).Count -gt 0) {
        Write-OptLog -Level Warn "$(@($p.DetectionErrors).Count) detector(s) failed - affected tweaks will be skipped:"
        foreach ($e in $p.DetectionErrors) { Write-OptLog -Level Detail "$($e.Detector): $($e.Message)" }
    }

    Write-OptDecisionSummary -State $State
}

function Format-OptTriState {
    <#
        Renders the tri-state honestly. '?' is a distinct answer from 'off' and
        must look like one - reporting an unconfirmed IOMMU as "off" would send
        the user into their BIOS for nothing.
    #>
    [CmdletBinding()][OutputType([string])]
    param([AllowNull()]$Value)

    if ($null -eq $Value)  { return '?' }
    if ($Value -is [bool]) { return $(if ($Value) { 'ON' } else { 'off' }) }
    return [string]$Value
}

function Write-OptDecisionSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $gated = @($State.Decisions | Where-Object { $_.Decision -eq 'Off' })
    if ($gated.Count -gt 0) {
        Write-OptLog -Level Header 'GATED OFF'
        foreach ($d in $gated) {
            Write-OptLog -Level Plain ("  {0,-22} {1}" -f "$($d.Section) $($d.Title)", $d.Reason)
        }
    }

    $notes = @($State.Decisions | Where-Object { $_.Decision -eq 'NoOp' -and $_.Id -like 'G-*' })
    if ($notes.Count -gt 0) {
        Write-OptLog -Level Header 'NOTES'
        foreach ($d in $notes) {
            Write-OptLog -Level Plain ("  {0,-22} {1}" -f "$($d.Section) $($d.Title)", $d.Reason)
        }
    }

    $findings = @($State.Findings)
    if ($findings.Count -gt 0) {
        Write-OptLog -Level Header 'FINDINGS - these are problems to fix, not tweaks that succeeded'
        foreach ($f in $findings) {
            $level = switch ($f.Severity) { 'Critical' { 'Error' } 'Error' { 'Error' } default { 'Warn' } }
            Write-OptLog -Level $level ("[{0}] {1}" -f $f.Section, $f.Title)
            Write-OptLog -Level Detail $f.Reason
        }
    }
}
