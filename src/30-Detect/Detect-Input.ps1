function Get-OptInputSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{ VendorUtilities = @(); HasVendorUtility = $null; Mouse = $null }
}

function Get-OptInputInfo {
    <#
        Report-only, and it matters (spec 1.5.4): peripheral vendor utilities
        override the Windows mouse settings that section 6.1 writes. Disabling
        acceleration in Windows while G HUB / Synapse / iCUE re-applies its own
        acceleration or angle-snapping leaves the user worse off than before,
        believing it was fixed.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Input' -UnknownSkeleton (Get-OptInputSkeleton) -ScriptBlock {
        $known = @(
            @{ Name = 'Logitech G HUB';    Process = 'lghub';        Pattern = 'G HUB' }
            @{ Name = 'Logitech Gaming';   Process = 'LCore';        Pattern = 'Logitech Gaming Software' }
            @{ Name = 'Razer Synapse';     Process = 'Razer Synapse';Pattern = 'Razer Synapse' }
            @{ Name = 'Corsair iCUE';      Process = 'iCUE';         Pattern = 'iCUE' }
            @{ Name = 'ASUS Armoury Crate';Process = 'ArmouryCrate'; Pattern = 'Armoury Crate' }
            @{ Name = 'SteelSeries GG';    Process = 'SteelSeriesGG';Pattern = 'SteelSeries' }
            @{ Name = 'Glorious Core';     Process = 'GloriousCore'; Pattern = 'Glorious' }
            @{ Name = 'Pulsar Fusion';     Process = 'Fusion';       Pattern = 'Pulsar' }
            @{ Name = 'Wooting';           Process = 'wootility';    Pattern = 'Wootility' }
        )

        $installed = @()
        foreach ($root in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                            'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $base = $null; $key = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                            [Microsoft.Win32.RegistryHive]::LocalMachine,
                            [Microsoft.Win32.RegistryView]::Registry64)
                $key = $base.OpenSubKey($root)
                if (-not $key) { continue }
                foreach ($sub in $key.GetSubKeyNames()) {
                    $s = $null
                    try {
                        $s = $key.OpenSubKey($sub)
                        if ($s) { $installed += [string]$s.GetValue('DisplayName') }
                    }
                    finally { if ($s) { $s.Dispose() } }
                }
            }
            catch { }
            finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
        }

        $running = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)

        $found = @()
        foreach ($k in $known) {
            $isInstalled = [bool](@($installed | Where-Object { $_ -and $_ -like "*$($k.Pattern)*" }).Count)
            $isRunning   = [bool](@($running   | Where-Object { $_ -like "*$($k.Process)*" }).Count)
            if ($isInstalled -or $isRunning) {
                $found += [ordered]@{ Name = $k.Name; Installed = $isInstalled; Running = $isRunning }
            }
        }

        [ordered]@{
            VendorUtilities  = $found
            HasVendorUtility = ($found.Count -gt 0)
            Mouse            = Get-OptMouseState
        }
    }
}
