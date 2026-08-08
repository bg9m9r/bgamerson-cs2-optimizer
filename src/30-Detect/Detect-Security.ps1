function Get-OptSecuritySkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        SecureBootEnabled = $null; SecureBootSupported = $null
        TpmPresent = $null; TpmReady = $null; TpmVersion = $null
        VbsStatus = $null; VbsRunning = $null; HvciRunning = $null
        CredentialGuardRunning = $null; SecurityServicesRunning = @()
        AvailableSecurityProperties = @(); HypervisorLaunchType = $null
        IommuEnabled = $null; IommuEvidence = @(); KernelDmaProtection = $null
        BitLockerProtected = @(); BitLockerAnyProtected = $null
        BitLockerRecoveryKeyEscrowed = $null
        AntiCheat = @(); HasKernelAntiCheat = $null; HasFaceitAc = $null
    }
}

function Get-OptAntiCheatTable {
    <#
        Match on service AND driver: an uninstalled product very often leaves
        one behind, and either alone is a false signal.
    #>
    [CmdletBinding()][OutputType([array])]
    param()
    return , @(
        @{ Name = 'FACEIT AC';    Services = @('FACEITService', 'FACEIT');          Drivers = @('FACEIT', 'FACEIT_IOMMU') }
        @{ Name = 'Vanguard';     Services = @('vgc');                              Drivers = @('vgk') }
        @{ Name = 'EasyAntiCheat';Services = @('EasyAntiCheat', 'EasyAntiCheat_EOS');Drivers = @('EasyAntiCheat', 'EasyAntiCheat_EOS') }
        @{ Name = 'BattlEye';     Services = @('BEService');                        Drivers = @('BEDaisy', 'BEGameup') }
        @{ Name = 'ESEA';         Services = @('ESEAService');                      Drivers = @('ESEADriver2', 'ESEADriver') }
    )
}

function Get-OptSecurityInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Security' -UnknownSkeleton (Get-OptSecuritySkeleton) -ScriptBlock {

        # --- Secure Boot ------------------------------------------------------
        # Confirm-SecureBootUEFI THROWS on a legacy BIOS rather than returning
        # false, and throws a different exception when access is denied. Those
        # two are not the same answer and must not collapse to "disabled".
        $secureBoot   = $null
        $sbSupported  = $null
        try {
            $secureBoot  = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
            $sbSupported = $true
        }
        catch [System.PlatformNotSupportedException] {
            $secureBoot = $null; $sbSupported = $false      # legacy BIOS
        }
        catch {
            if ($_.Exception.Message -match 'not supported|legacy|BIOS') { $sbSupported = $false }
            $secureBoot = $null
        }

        # --- TPM --------------------------------------------------------------
        $tpmPresent = $null; $tpmReady = $null; $tpmVersion = $null
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            if ($tpm) {
                $tpmPresent = [bool]$tpm.TpmPresent
                $tpmReady   = [bool]$tpm.TpmReady
                $tpmVersion = [string]$tpm.ManufacturerVersion
            }
        }
        catch { }

        # --- Device Guard / VBS ----------------------------------------------
        $dg = Get-OptCimSafe -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' | Select-Object -First 1

        $vbsStatus = $null; $servicesRunning = @(); $availableProps = @()
        if ($dg) {
            if ($null -ne $dg.VirtualizationBasedSecurityStatus) { $vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus }
            $servicesRunning = @($dg.SecurityServicesRunning     | ForEach-Object { [int]$_ })
            $availableProps  = @($dg.AvailableSecurityProperties | ForEach-Object { [int]$_ })
        }

        # VirtualizationBasedSecurityStatus: 0 off, 1 configured, 2 running.
        $vbsRunning = $(if ($null -ne $vbsStatus) { ($vbsStatus -eq 2) } else { $null })
        # SecurityServicesRunning: 1 Credential Guard, 2 HVCI/Memory Integrity.
        $hvci       = $(if ($dg) { ($servicesRunning -contains 2) } else { $null })
        $credGuard  = $(if ($dg) { ($servicesRunning -contains 1) } else { $null })

        # --- bcdedit hypervisor settings -------------------------------------
        $hvLaunch = $null; $iommuPolicy = $null
        $bcd = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/enum', '{current}') -ReadOnly
        if ($bcd.Success) {
            foreach ($line in (Get-OptCommandLines -Text $bcd.StdOut)) {
                # Anchor on the token: 'hypervisorlaunchtype' is a prefix of
                # nothing, but 'hypervisoriommupolicy' also starts with
                # 'hypervisor', so a loose -match would cross-contaminate.
                if ($line -match '^\s*hypervisorlaunchtype\s+(\S+)')  { $hvLaunch    = $Matches[1] }
                if ($line -match '^\s*hypervisoriommupolicy\s+(\S+)') { $iommuPolicy = $Matches[1] }
            }
        }

        # --- IOMMU: deliberately TRI-STATE ------------------------------------
        # There is no clean API for "IOMMU is on". $true only on a positive
        # signal; otherwise $null meaning indeterminate. This matters because a
        # false negative here sends the user into their BIOS for nothing, and
        # spec 10.2 would have it reported as a hard FACEIT compliance failure.
        $iommu = $null
        $evidence = @()

        if ($iommuPolicy -and $iommuPolicy -match '^Enable') {
            $iommu = $true; $evidence += "bcdedit hypervisoriommupolicy=$iommuPolicy"
        }

        $dmaGuard = Get-OptCimSafe -ClassName MSFT_DmaGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' | Select-Object -First 1
        $kernelDma = $null
        if ($dmaGuard -and $null -ne $dmaGuard.DmaGuardState) {
            $kernelDma = ([int]$dmaGuard.DmaGuardState -eq 1)
            if ($kernelDma) { $iommu = $true; $evidence += 'Kernel DMA Protection on' }
        }

        # FACEIT ships a dedicated IOMMU-check driver. If it loaded and is
        # running, the platform satisfied FACEIT's own IOMMU requirement -
        # which is a stronger signal for our purposes than any WMI property.
        $faceitIommu = Get-OptCimSafe -ClassName Win32_SystemDriver -Filter "Name='FACEIT_IOMMU'" | Select-Object -First 1
        if ($faceitIommu -and $faceitIommu.State -eq 'Running') {
            $iommu = $true; $evidence += 'FACEIT_IOMMU driver running'
        }

        if ($availableProps -contains 3) { $evidence += 'DMA protection listed as available' }

        # --- BitLocker --------------------------------------------------------
        $blProtected = @()
        $blEscrowed  = $null
        try {
            foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
                if ([string]$v.ProtectionStatus -eq 'On') {
                    $protectors = @($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
                    $blProtected += [ordered]@{
                        MountPoint   = [string]$v.MountPoint
                        VolumeStatus = [string]$v.VolumeStatus
                        Protectors   = $protectors
                    }
                    if ($protectors -contains 'RecoveryPassword') { $blEscrowed = $true }
                }
            }
            if ($blProtected.Count -gt 0 -and $null -eq $blEscrowed) { $blEscrowed = $false }
        }
        catch { }

        # --- anti-cheat -------------------------------------------------------
        $allServices = @()
        try { $allServices = @(Get-Service -ErrorAction SilentlyContinue) } catch { }
        $allDrivers = @(Get-OptCimSafe -ClassName Win32_SystemDriver)

        $found = @()
        foreach ($ac in (Get-OptAntiCheatTable)) {
            $svc = @($allServices | Where-Object { $ac.Services -contains $_.Name })
            $drv = @($allDrivers  | Where-Object { $ac.Drivers  -contains $_.Name })
            if ($svc.Count -eq 0 -and $drv.Count -eq 0) { continue }

            $found += [ordered]@{
                Name           = $ac.Name
                ServiceNames   = @($svc | ForEach-Object { $_.Name })
                # Deliberately record StartType and Status separately. These
                # services are Stopped/Manual by design - they start on demand
                # when the client launches. A postflight assertion of "Running"
                # would false-fail on every single run.
                ServiceStates  = @($svc | ForEach-Object { "$($_.Name)=$($_.Status)/$($_.StartType)" })
                ServicePresent = ($svc.Count -gt 0)
                ServiceEnabled = [bool](@($svc | Where-Object { [string]$_.StartType -ne 'Disabled' }).Count)
                DriverNames    = @($drv | ForEach-Object { $_.Name })
                DriverStates   = @($drv | ForEach-Object { "$($_.Name)=$($_.State)/$($_.StartMode)" })
                DriverPresent  = ($drv.Count -gt 0)
                DriverRunning  = [bool](@($drv | Where-Object { $_.State -eq 'Running' }).Count)
            }
        }

        [ordered]@{
            SecureBootEnabled            = $secureBoot
            SecureBootSupported          = $sbSupported
            TpmPresent                   = $tpmPresent
            TpmReady                     = $tpmReady
            TpmVersion                   = $tpmVersion
            VbsStatus                    = $vbsStatus
            VbsRunning                   = $vbsRunning
            HvciRunning                  = $hvci
            CredentialGuardRunning       = $credGuard
            SecurityServicesRunning      = $servicesRunning
            AvailableSecurityProperties  = $availableProps
            HypervisorLaunchType         = $hvLaunch
            HypervisorIommuPolicy        = $iommuPolicy
            IommuEnabled                 = $iommu
            IommuEvidence                = $evidence
            KernelDmaProtection          = $kernelDma
            BitLockerProtected           = $blProtected
            BitLockerAnyProtected        = ($blProtected.Count -gt 0)
            BitLockerRecoveryKeyEscrowed = $blEscrowed
            AntiCheat                    = $found
            HasKernelAntiCheat           = ($found.Count -gt 0)
            HasFaceitAc                  = [bool](@($found | Where-Object { $_.Name -eq 'FACEIT AC' }).Count)
        }
    }
}
