function Get-OptNetworkSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Adapters = @(); ActiveAdapterName = $null; ActiveIsWireless = $null
        MultipleDefaultRoutes = $null; VirtualAheadOfPhysical = $null
    }
}

function Get-OptNetworkInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Network' -UnknownSkeleton (Get-OptNetworkSkeleton) -ScriptBlock {
        $nics = @()
        try { $nics = @(Get-NetAdapter -ErrorAction Stop) } catch { return $null }
        if ($nics.Count -eq 0) { return $null }

        # Default routes tell us which adapter actually carries game traffic.
        # Machines routinely enumerate Hyper-V vSwitches, VPN tunnels,
        # Tailscale, Bluetooth PAN and a disconnected second NIC all at once,
        # and tuning the wrong one does nothing while looking like the tweak
        # failed.
        $routes = @()
        try {
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                        Sort-Object -Property RouteMetric)
        }
        catch { }

        $adapters = @()
        foreach ($n in $nics) {
            $route = $routes | Where-Object { $_.ifIndex -eq $n.ifIndex } | Select-Object -First 1

            # Advanced properties are captured ONCE here; section 7.1 iterates
            # this snapshot rather than re-querying per property.
            $props = @()
            try {
                $props = @(Get-NetAdapterAdvancedProperty -Name $n.Name -ErrorAction Stop | ForEach-Object {
                    [ordered]@{
                        RegistryKeyword    = $_.RegistryKeyword
                        DisplayName        = $_.DisplayName
                        DisplayValue       = $_.DisplayValue
                        RegistryValue      = $(if ($_.RegistryValue) { @($_.RegistryValue)[0] } else { $null })
                        ValidDisplayValues = @($_.ValidDisplayValues)
                        ValidRegistryValues= @($_.ValidRegistryValues)
                    }
                })
            }
            catch { }

            $isVirtual = [bool]$n.Virtual -or
                         ($n.InterfaceDescription -match 'WAN Miniport|Hyper-V|VirtualBox|VMware|TAP-|Tailscale|WireGuard|Bluetooth|Loopback|Npcap')

            $adapters += [ordered]@{
                Name             = $n.Name
                IfIndex          = [int]$n.ifIndex
                Description      = $n.InterfaceDescription
                MacAddress       = $n.MacAddress
                LinkSpeed        = [string]$n.LinkSpeed
                Status           = [string]$n.Status
                IsActive         = ($n.Status -eq 'Up')
                IsWireless       = ($n.PhysicalMediaType -match 'Native 802.11|Wireless' -or $n.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11')
                IsVirtual        = $isVirtual
                IsDefaultRoute   = ($null -ne $route)
                RouteMetric      = $(if ($route) { [int]$route.RouteMetric } else { $null })
                # An inbox Microsoft driver exposes almost none of the section
                # 7.1 keywords. When that is the case the real fix is installing
                # the vendor driver, not editing the registry.
                DriverProvider   = [string]$n.DriverProvider
                DriverVersion    = [string]$n.DriverVersion
                SupportedKeywords= @($props | ForEach-Object { $_.RegistryKeyword })
                AdvancedProperties = $props
            }
        }

        # The adapter to tune: has a default route, is up, and is not virtual.
        # Lowest route metric wins when several qualify.
        $candidates = @($adapters |
            Where-Object { $_.IsDefaultRoute -and $_.IsActive -and -not $_.IsVirtual } |
            Sort-Object -Property @{ Expression = { if ($null -eq $_.RouteMetric) { [int]::MaxValue } else { $_.RouteMetric } } })

        $active = $candidates | Select-Object -First 1

        # A VPN / Tailscale / Hyper-V adapter holding a LOWER metric than the
        # physical NIC silently routes game traffic through it, which alone can
        # add tens of milliseconds.
        $virtualAhead = $false
        $physMetric = $(if ($active -and $null -ne $active.RouteMetric) { $active.RouteMetric } else { [int]::MaxValue })
        foreach ($a in $adapters) {
            if ($a.IsVirtual -and $a.IsDefaultRoute -and $a.IsActive -and
                $null -ne $a.RouteMetric -and $a.RouteMetric -lt $physMetric) {
                $virtualAhead = $true
            }
        }

        [ordered]@{
            Adapters              = $adapters
            ActiveAdapterName     = $(if ($active) { $active.Name } else { $null })
            ActiveIfIndex         = $(if ($active) { $active.IfIndex } else { $null })
            ActiveIsWireless      = $(if ($active) { $active.IsWireless } else { $null })
            ActiveDriverProvider  = $(if ($active) { $active.DriverProvider } else { $null })
            ActiveLinkSpeed       = $(if ($active) { $active.LinkSpeed } else { $null })
            MultipleDefaultRoutes = (@($adapters | Where-Object { $_.IsDefaultRoute -and $_.IsActive }).Count -gt 1)
            VirtualAheadOfPhysical= $virtualAhead
        }
    }
}
