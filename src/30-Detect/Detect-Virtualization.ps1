function Get-OptVirtualizationSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        IsVirtualMachine = $null; VmEvidence = $null
        HyperVEnabled = $null; WslInstalled = $null; DockerInstalled = $null
        SandboxEnabled = $null; VmPlatformEnabled = $null
        BlocksHypervisorOff = $null; HypervisorPresent = $null
    }
}

function Get-OptVirtualizationInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Virtualization' -UnknownSkeleton (Get-OptVirtualizationSkeleton) -ScriptBlock {
        $cs = Get-OptCimSafe -ClassName Win32_ComputerSystem | Select-Object -First 1
        $bios = Get-OptCimSafe -ClassName Win32_BIOS | Select-Object -First 1

        # --- is this a VM -----------------------------------------------------
        # Note HypervisorPresent is TRUE on any machine running VBS, because VBS
        # IS a hypervisor. It must never be used as a VM signal - doing so would
        # abort the run on exactly the FACEIT-compliant machines this script
        # exists for.
        $vmEvidence = $null
        $model = [string]$cs.Model
        $manufacturer = [string]$cs.Manufacturer
        $biosVersion = [string]$bios.SMBIOSBIOSVersion

        $vmPatterns = @(
            @{ Pattern = 'Virtual Machine';   Source = 'Model' }
            @{ Pattern = 'VMware';            Source = 'Model' }
            @{ Pattern = 'VirtualBox';        Source = 'Model' }
            @{ Pattern = 'KVM|QEMU|Bochs';    Source = 'Model' }
            @{ Pattern = 'Parallels';         Source = 'Model' }
            @{ Pattern = 'Xen';               Source = 'Model' }
        )
        foreach ($p in $vmPatterns) {
            if ($model -match $p.Pattern)        { $vmEvidence = "Model='$model'"; break }
            if ($manufacturer -match $p.Pattern) { $vmEvidence = "Manufacturer='$manufacturer'"; break }
        }
        if (-not $vmEvidence -and $manufacturer -match 'Microsoft Corporation' -and $model -match 'Virtual') {
            $vmEvidence = "Model='$model'"
        }
        if (-not $vmEvidence -and $biosVersion -match 'VRTUAL|A M I |VBOX|BOCHS|PRLS') {
            $vmEvidence = "BIOS='$biosVersion'"
        }

        # --- optional features ------------------------------------------------
        # Get-WindowsOptionalFeature is slow (seconds), so query only the names
        # that gate a decision.
        $features = @{}
        foreach ($name in @('Microsoft-Hyper-V-Hypervisor', 'Microsoft-Windows-Subsystem-Linux',
                            'VirtualMachinePlatform', 'Containers-DisposableClientVM')) {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
                $features[$name] = ([string]$f.State -eq 'Enabled')
            }
            catch { $features[$name] = $null }
        }

        $wsl = $features['Microsoft-Windows-Subsystem-Linux']
        if (-not $wsl) {
            $wslDistros = $null
            try {
                $r = Invoke-OptNativeCommand -State $State -FilePath 'wsl.exe' -ArgumentList @('-l', '-q') -ReadOnly
                if ($r.Success -and (Get-OptCommandLines -Text $r.StdOut).Count -gt 0) { $wslDistros = $true }
            }
            catch { }
            if ($wslDistros) { $wsl = $true }
        }

        $docker = $null
        try {
            $docker = [bool](Get-Service -Name 'com.docker.service', 'docker' -ErrorAction SilentlyContinue)
        }
        catch { $docker = $false }

        $hyperV  = $features['Microsoft-Hyper-V-Hypervisor']
        $sandbox = $features['Containers-DisposableClientVM']
        $vmp     = $features['VirtualMachinePlatform']

        [ordered]@{
            IsVirtualMachine    = ($null -ne $vmEvidence)
            VmEvidence          = $vmEvidence
            HypervisorPresent   = $(if ($cs) { [bool]$cs.HypervisorPresent } else { $null })
            HyperVEnabled       = $hyperV
            WslInstalled        = $wsl
            DockerInstalled     = $docker
            SandboxEnabled      = $sandbox
            VmPlatformEnabled   = $vmp
            # Any of these means `bcdedit /set hypervisorlaunchtype off` would
            # break a workload the user actually uses (spec 1.5.4).
            BlocksHypervisorOff = ([bool]$hyperV -or [bool]$wsl -or [bool]$docker -or [bool]$sandbox -or [bool]$vmp)
        }
    }
}
