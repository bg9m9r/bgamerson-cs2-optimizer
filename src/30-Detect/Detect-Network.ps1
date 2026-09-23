function Get-OptNetworkSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Adapters = @(); ActiveAdapterName = $null; ActiveIsWireless = $null
        ActiveIfIndex = $null; ActiveDriverProvider = $null; ActiveLinkSpeed = $null
        MultipleDefaultRoutes = $null; VirtualAheadOfPhysical = $null
        ActiveAdapterPnpDeviceId = $null; ActiveAdapterMsiSupported = $null
        ActiveAdapterInterruptPolicy = $null; IdleWirelessAdapters = @()
    }
}

function Get-OptAdapterInterruptInfo {
    <#
        Reads the device's interrupt configuration straight from its PnP
        registry node. MSISupported tells section 7.5 whether the adapter uses
        message-signalled interrupts (line-based IRQs are shared and must not be
        pinned); DevicePolicy / AssignmentSetOverride reveal an affinity policy
        someone else already set, which the section then leaves alone.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowNull()][string]$PnpDeviceId)

    $info = [ordered]@{ MsiSupported = $null; InterruptPolicy = $null; InterruptMask = $null }
    if (-not $PnpDeviceId -or $PnpDeviceId -notlike 'PCI\*') { return $info }

    $base = "SYSTEM\CurrentControlSet\Enum\$PnpDeviceId\Device Parameters\Interrupt Management"
    $msi = Get-OptRegValueSafe -Hive HKLM -SubKey "$base\MessageSignaledInterruptProperties" -Name 'MSISupported'
    if ($null -ne $msi) { $info.MsiSupported = [int]$msi }

    $policy = Get-OptRegValueSafe -Hive HKLM -SubKey "$base\Affinity Policy" -Name 'DevicePolicy'
    if ($null -ne $policy) { $info.InterruptPolicy = [int]$policy }

    $mask = Get-OptRegValueSafe -Hive HKLM -SubKey "$base\Affinity Policy" -Name 'AssignmentSetOverride'
    if ($null -ne $mask) {
        # REG_BINARY, REG_DWORD and REG_QWORD are all legal here; normalise to a
        # hex string so the profile stays serializable and comparable.
        # A REG_BINARY arrives as Object[], not byte[]: PowerShell unrolls the
        # byte[] on the way out of Get-OptRegValueSafe. Caught live - the first
        # run after section 7.5 wrote this value took down the whole detector.
        $bytes = if ($mask -is [System.Array]) { [byte[]]@($mask | ForEach-Object { [byte]$_ }) }
                 else { [System.BitConverter]::GetBytes([uint64]$mask) }
        $info.InterruptMask = ([System.BitConverter]::ToString($bytes)).Replace('-', '')
    }
    return $info
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

            $pnpId = [string]$n.PnPDeviceID
            $irq = Get-OptAdapterInterruptInfo -PnpDeviceId $pnpId

            $adapters += [ordered]@{
                Name             = $n.Name
                IfIndex          = [int]$n.ifIndex
                Description      = $n.InterfaceDescription
                MacAddress       = $n.MacAddress
                PnpDeviceId      = $(if ($pnpId) { $pnpId } else { $null })
                MsiSupported     = $irq.MsiSupported
                InterruptPolicy  = $irq.InterruptPolicy
                InterruptMask    = $irq.InterruptMask
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

        # A Wi-Fi radio that is enabled but not connected keeps scanning in the
        # background while the wired NIC carries the game. Only meaningful when
        # the active adapter is wired - on a Wi-Fi-only machine there is nothing
        # to switch off.
        $idleWireless = @()
        if ($active -and -not $active.IsWireless) {
            $idleWireless = @($adapters |
                Where-Object { $_.IsWireless -and -not $_.IsVirtual -and $_.Status -eq 'Disconnected' } |
                ForEach-Object { $_.Name })
        }

        [ordered]@{
            Adapters              = $adapters
            ActiveAdapterName     = $(if ($active) { $active.Name } else { $null })
            ActiveIfIndex         = $(if ($active) { $active.IfIndex } else { $null })
            ActiveIsWireless      = $(if ($active) { $active.IsWireless } else { $null })
            ActiveDriverProvider  = $(if ($active) { $active.DriverProvider } else { $null })
            ActiveLinkSpeed       = $(if ($active) { $active.LinkSpeed } else { $null })
            ActiveAdapterPnpDeviceId     = $(if ($active) { $active.PnpDeviceId } else { $null })
            ActiveAdapterMsiSupported    = $(if ($active) { $active.MsiSupported } else { $null })
            ActiveAdapterInterruptPolicy = $(if ($active) { $active.InterruptPolicy } else { $null })
            IdleWirelessAdapters  = $idleWireless
            MultipleDefaultRoutes = (@($adapters | Where-Object { $_.IsDefaultRoute -and $_.IsActive }).Count -gt 1)
            VirtualAheadOfPhysical= $virtualAhead
        }
    }
}
