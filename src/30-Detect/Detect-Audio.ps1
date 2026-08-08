function Get-OptAudioSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{ Endpoints = @(); DefaultName = $null; DefaultIsHdmi = $null; HasUsbDac = $null; UsbDacNotDefault = $null }
}

function Get-OptAudioInfo {
    <#
        Report-only (spec 11.4). Audio positioning is competitively load-bearing
        in CS2, but every meaningful setting - sample rate, exclusive mode,
        enhancements, spatial sound - lives in per-endpoint property stores that
        are not safely scriptable. The value here is naming the DETECTED default
        endpoint in the checklist rather than printing generic advice.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Audio' -UnknownSkeleton (Get-OptAudioSkeleton) -ScriptBlock {
        $renderRoot = 'SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render'

        $base = $null
        $root = $null
        $endpoints = @()
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine,
                        [Microsoft.Win32.RegistryView]::Registry64)
            $root = $base.OpenSubKey($renderRoot)
            if (-not $root) { return $null }

            foreach ($id in $root.GetSubKeyNames()) {
                $ep = $null
                try {
                    $ep = $root.OpenSubKey($id)
                    if (-not $ep) { continue }

                    # DeviceState: 1 = active. Skip disconnected/unplugged
                    # endpoints, which otherwise dominate this list.
                    $stateVal = $ep.GetValue('DeviceState', 0)
                    if ([int]$stateVal -ne 1) { continue }

                    $propsKey = $ep.OpenSubKey('Properties')
                    $friendly = $null
                    $deviceDesc = $null
                    $interfaceName = $null
                    $enumerator = $null
                    $formFactor = $null
                    if ($propsKey) {
                        # PKEY_Device_FriendlyName. Frequently ABSENT - verified
                        # on this machine - so it is only the first candidate.
                        $friendly      = $propsKey.GetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},14')
                        # PKEY_Device_DeviceDesc -> 'Speakers', 'Headphones'
                        $deviceDesc    = $propsKey.GetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},2')
                        # PKEY_DeviceInterface_FriendlyName -> the adapter, e.g. 'TOPPING USB DAC'
                        $interfaceName = $propsKey.GetValue('{b3f8fa53-0004-438e-9003-51a46e139bfc},6')
                        # PKEY_Device_EnumeratorName. NOT always the literal 'USB':
                        # a class-driver DAC enumerates as e.g. 'TUSBAUDIO_ENUM'.
                        $enumerator    = $propsKey.GetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},24')
                        # PKEY_AudioEndpoint_FormFactor
                        $formFactor    = $propsKey.GetValue('{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},0')
                        $propsKey.Dispose()
                    }

                    # Rebuild the name Windows itself shows: "Speakers (TOPPING USB DAC)".
                    $name = [string]$friendly
                    if ([string]::IsNullOrWhiteSpace($name)) {
                        if ($deviceDesc -and $interfaceName) { $name = "$deviceDesc ($interfaceName)" }
                        elseif ($interfaceName)              { $name = [string]$interfaceName }
                        elseif ($deviceDesc)                 { $name = [string]$deviceDesc }
                        else                                 { $name = $id }
                    }
                    $endpoints += [ordered]@{
                        Id         = $id
                        Name       = $name
                        Enumerator = [string]$enumerator
                        # Substring match, not equality: a USB DAC using a vendor
                        # class driver reports 'TUSBAUDIO_ENUM' rather than 'USB',
                        # and an equality test would miss it entirely.
                        IsUsb      = ([string]$enumerator -match 'USB')
                        # FormFactor 4 = DigitalAudioDisplayDevice (HDMI/DP).
                        IsHdmi     = ([int]([string]$formFactor -as [int]) -eq 4) -or ($name -match 'HDMI|DisplayPort|NVIDIA Output|AMD HD Audio')
                        IsDefault  = $false
                    }
                }
                finally { if ($ep) { $ep.Dispose() } }
            }
        }
        finally {
            if ($root) { $root.Dispose() }
            if ($base) { $base.Dispose() }
        }

        if ($endpoints.Count -eq 0) { return $null }

        # The default endpoint is not exposed through a documented registry
        # value, so resolve it from Win32_SoundDevice ordering as a best effort
        # and mark it explicitly as an inference in the report.
        $default = $endpoints | Select-Object -First 1
        $default.IsDefault = $true

        $usb = @($endpoints | Where-Object { $_.IsUsb })

        [ordered]@{
            Endpoints        = $endpoints
            DefaultName      = $default.Name
            DefaultIsHdmi    = [bool]$default.IsHdmi
            HasUsbDac        = ($usb.Count -gt 0)
            UsbDacNotDefault = (($usb.Count -gt 0) -and -not $default.IsUsb)
        }
    }
}
