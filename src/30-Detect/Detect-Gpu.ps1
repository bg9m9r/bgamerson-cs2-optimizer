function Get-OptGpuSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{ Adapters = @(); PrimaryVendor = 'Unknown'; Count = 0; HasMultiple = $null }
}

function Test-OptGpuIsVirtual {
    <#
        Filters out adapters that are not real display hardware: the Microsoft
        Basic Display Adapter (what you get before a driver installs), RDP /
        Hyper-V synthetic video, and streaming host virtual displays (Parsec,
        Sunshine, IddSampleDriver). Treating any of these as the primary GPU
        would branch the whole of section 3 down the wrong vendor path.
    #>
    [CmdletBinding()][OutputType([bool])]
    param([Parameter(Mandatory)][AllowNull()][string]$Name, [AllowNull()][string]$PnpDeviceId)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

    $virtualNames = @(
        'Microsoft Basic Display', 'Microsoft Remote Display', 'RDPDD', 'RDP Encoder',
        'Hyper-V Video', 'VMware SVGA', 'VirtualBox Graphics', 'QXL', 'Citrix',
        'Parsec Virtual Display', 'IddSampleDriver', 'Sunshine', 'USB Display',
        'DisplayLink', 'Virtual Display'
    )
    foreach ($v in $virtualNames) {
        if ($Name -like "*$v*") { return $true }
    }

    # Real display adapters sit on PCI. Root-enumerated devices are software.
    if ($PnpDeviceId -and $PnpDeviceId -notlike 'PCI\*') { return $true }

    return $false
}

function Get-OptGpuVendorFromId {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][string]$PnpDeviceId, [AllowNull()][string]$Name)

    if ($PnpDeviceId -match 'VEN_([0-9A-Fa-f]{4})') {
        switch ($Matches[1].ToUpperInvariant()) {
            '1002'  { return 'AMD' }      # ATI/AMD
            '1022'  { return 'AMD' }
            '10DE'  { return 'NVIDIA' }
            '8086'  { return 'Intel' }
        }
    }
    # PCI vendor ID is authoritative; the marketing name is only a fallback.
    if ($Name -match 'NVIDIA|GeForce|RTX|GTX|Quadro') { return 'NVIDIA' }
    if ($Name -match 'Radeon|AMD|FirePro')            { return 'AMD' }
    if ($Name -match 'Intel|Arc|Iris|UHD Graphics')   { return 'Intel' }
    return 'Unknown'
}

function Get-OptGpuVramMB {
    <#
        Win32_VideoController.AdapterRAM is a SIGNED 32-bit value and therefore
        wraps for any card with more than 2 GB of VRAM - a 20 GB RX 7900 XT
        reports a negative or nonsense number. The driver's registry
        HardwareInformation.qwMemorySize is a QWORD and is correct.
    #>
    [CmdletBinding()][OutputType([System.Nullable[int]])]
    param([Parameter(Mandatory)][AllowNull()][string]$PnpDeviceId, [AllowNull()]$AdapterRam)

    $classRoot = 'SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    for ($i = 0; $i -le 16; $i++) {
        $sub = '{0}\{1:D4}' -f $classRoot, $i
        $match = Get-OptRegValueSafe -Hive HKLM -SubKey $sub -Name 'MatchingDeviceId'
        if (-not $match) { continue }
        if ($PnpDeviceId -and ($PnpDeviceId -replace '\\', '\') -notlike "*$($match -replace '\\','\')*") {
            if (-not ($PnpDeviceId -like "*$match*")) { continue }
        }
        $qw = Get-OptRegValueSafe -Hive HKLM -SubKey $sub -Name 'HardwareInformation.qwMemorySize'
        if ($qw) { return [int]([long]$qw / 1MB) }
    }

    if ($AdapterRam -and [long]$AdapterRam -gt 0) { return [int]([long]$AdapterRam / 1MB) }
    return $null
}

function Get-OptGpuInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$DisplayAdapters
    )

    return Invoke-OptDetector -State $State -Name 'GPU' -UnknownSkeleton (Get-OptGpuSkeleton) -ScriptBlock {
        $controllers = @(Get-OptCimSafe -ClassName Win32_VideoController)
        if (-not $controllers -or $controllers.Count -eq 0) { return $null }

        # The interop enumeration gives us the PCI DeviceId of the adapter that
        # actually drives the primary display. That is what makes the
        # "primary display is plugged into the motherboard while a dGPU exists"
        # check possible - it is a cable problem no registry tweak can fix.
        $primaryDeviceId = $null
        if ($DisplayAdapters) {
            $pd = @($DisplayAdapters | Where-Object { $_.IsPrimary }) | Select-Object -First 1
            if ($pd) { $primaryDeviceId = $pd.DeviceId }
        }

        $adapters = @()
        foreach ($c in $controllers) {
            $isVirtual = Test-OptGpuIsVirtual -Name $c.Name -PnpDeviceId $c.PNPDeviceID
            if ($isVirtual) { continue }

            $vendor = Get-OptGpuVendorFromId -PnpDeviceId $c.PNPDeviceID -Name $c.Name

            $drivesPrimary = $false
            if ($primaryDeviceId -and $c.PNPDeviceID) {
                # Compare on the VEN_/DEV_/SUBSYS_ portion; the interop string
                # and the WMI PNPDeviceID differ in their trailing instance path.
                $a = ($c.PNPDeviceID -split '\\')[1]
                if ($a -and $primaryDeviceId -like "*$a*") { $drivesPrimary = $true }
            }

            $adapters += [ordered]@{
                Vendor        = $vendor
                Name          = $c.Name
                DriverVersion = $c.DriverVersion
                DriverDate    = $(if ($c.DriverDate) { ([datetime]$c.DriverDate).ToString('yyyy-MM-dd') } else { $null })
                PnpDeviceId   = $c.PNPDeviceID
                DeviceId      = $(if ($c.PNPDeviceID -match 'DEV_([0-9A-Fa-f]{4})') { $Matches[1] } else { $null })
                VramMB        = Get-OptGpuVramMB -PnpDeviceId $c.PNPDeviceID -AdapterRam $c.AdapterRAM
                IsIntegrated  = ($c.Name -match 'UHD Graphics|Iris|Vega.*Graphics|Radeon.*Graphics$|HD Graphics')
                DrivesPrimary = $drivesPrimary
                IsPrimary     = $false   # resolved below
            }
        }

        if ($adapters.Count -eq 0) { return $null }

        # Prefer the adapter that actually drives the primary display; fall back
        # to the first discrete adapter; last resort the first adapter at all.
        $primaryIndex = 0
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            if ($adapters[$i].DrivesPrimary) { $primaryIndex = $i; break }
        }
        if (-not $adapters[$primaryIndex].DrivesPrimary) {
            for ($i = 0; $i -lt $adapters.Count; $i++) {
                if (-not $adapters[$i].IsIntegrated) { $primaryIndex = $i; break }
            }
        }
        $adapters[$primaryIndex].IsPrimary = $true

        [ordered]@{
            Adapters      = $adapters
            PrimaryVendor = $adapters[$primaryIndex].Vendor
            Count         = $adapters.Count
            HasMultiple   = ($adapters.Count -gt 1)
        }
    }
}
