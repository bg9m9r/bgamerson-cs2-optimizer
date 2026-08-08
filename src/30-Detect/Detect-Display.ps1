function Get-OptDisplaySkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Displays = @(); PrimaryRefreshHz = $null; PrimaryMaxRefreshHz = $null
        RefreshBelowMax = $null; PrimaryOnIntegrated = $null
    }
}

function Get-OptDisplayInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$GpuInfo
    )

    return Invoke-OptDetector -State $State -Name 'Display' -UnknownSkeleton (Get-OptDisplaySkeleton) -ScriptBlock {
        if (-not $State.Capabilities.Interop) { return $null }

        $adapters = @(Get-OptDisplayAdapters | Where-Object { $_.IsAttached })
        if ($adapters.Count -eq 0) { return $null }

        $displays = @()
        foreach ($a in $adapters) {
            $cur = Get-OptDisplayCurrentMode -Device $a.DeviceName
            if (-not $cur) { continue }

            # Max refresh AT THE CURRENT RESOLUTION AND DEPTH. Not the global
            # maximum: many panels offer a higher rate at a lower resolution,
            # and silently switching resolution to reach it is what spec 3.8.5
            # forbids.
            $max = Get-OptDisplayMaxRefresh -Device $a.DeviceName -Width $cur.Width -Height $cur.Height -Bpp $cur.Bpp

            $monitorName = $null
            try { $monitorName = [Cs2Opt.Display.Api]::GetMonitorName($a.DeviceName) } catch { }

            $displays += [ordered]@{
                Device            = $a.DeviceName
                MonitorName       = $monitorName
                AdapterName       = $a.DeviceString
                AdapterDeviceId   = $a.DeviceId
                IsPrimary         = [bool]$a.IsPrimary
                Width             = [int]$cur.Width
                Height            = [int]$cur.Height
                Bpp               = [int]$cur.Bpp
                CurrentRefreshHz  = [int]$cur.Hz
                MaxRefreshHz      = [int]$max
                RefreshBelowMax   = ($max -gt 0 -and $cur.Hz -lt $max)
            }
        }

        if ($displays.Count -eq 0) { return $null }

        $primary = @($displays | Where-Object { $_.IsPrimary }) | Select-Object -First 1
        if (-not $primary) { $primary = $displays[0] }

        # Primary display driven by the iGPU while a discrete card exists is a
        # silent, very large performance loss - and it is a cable problem, not
        # something any registry value can fix.
        $primaryOnIgpu = $null
        if ($GpuInfo -and $GpuInfo.Adapters -and $GpuInfo.Adapters.Count -gt 1) {
            $igpu = @($GpuInfo.Adapters | Where-Object { $_.IsIntegrated -and $_.DrivesPrimary })
            $dgpu = @($GpuInfo.Adapters | Where-Object { -not $_.IsIntegrated })
            $primaryOnIgpu = (($igpu.Count -gt 0) -and ($dgpu.Count -gt 0))
        }
        elseif ($GpuInfo -and $GpuInfo.Adapters) {
            $primaryOnIgpu = $false
        }

        [ordered]@{
            Displays            = $displays
            PrimaryDevice       = $primary.Device
            PrimaryRefreshHz    = $primary.CurrentRefreshHz
            PrimaryMaxRefreshHz = $primary.MaxRefreshHz
            RefreshBelowMax     = [bool]($displays | Where-Object { $_.RefreshBelowMax })
            PrimaryOnIntegrated = $primaryOnIgpu
        }
    }
}
