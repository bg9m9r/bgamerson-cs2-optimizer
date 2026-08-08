function Get-OptOsSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Caption = $null; BuildNumber = $null; DisplayVersion = $null; UBR = $null
        IsWin11 = $null; Is22H2OrLater = $null; Edition = 'Unknown'
        IsCopilotPlusPc = $null; HasNpu = $null
        IsDomainJoined = $null; IsAzureAdJoined = $null; IsMdmEnrolled = $null
        IsManaged = $null; HasGroupPolicy = $null
    }
}

function Get-OptOsInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'OS' -UnknownSkeleton (Get-OptOsSkeleton) -ScriptBlock {
        $os = Get-OptCimSafe -ClassName Win32_OperatingSystem | Select-Object -First 1
        $cs = Get-OptCimSafe -ClassName Win32_ComputerSystem  | Select-Object -First 1

        $build = 0
        if ($os -and $os.BuildNumber) { [void][int]::TryParse($os.BuildNumber, [ref]$build) }

        $cvKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

        # Windows 11 must be detected from the build number, never from
        # ProductName or Caption: on Windows 11 the ProductName registry value
        # still literally reads "Windows 10 Pro" (verified on this machine,
        # build 26200). Caption from Win32_OperatingSystem is correct, but the
        # build check is the one that cannot be fooled.
        $isWin11 = ($build -ge 22000)

        $edition = 'Unknown'
        if ($os -and $os.Caption) {
            $caption = $os.Caption
            if     ($caption -match 'Enterprise')  { $edition = 'Enterprise' }
            elseif ($caption -match 'Education')   { $edition = 'Education' }
            elseif ($caption -match 'Pro')         { $edition = 'Pro' }
            elseif ($caption -match 'Home')        { $edition = 'Home' }
            if ($caption -match '\bN\b') { $edition = "${edition}N" }
        }

        # --- management state -------------------------------------------------
        # Domain / Azure-AD / MDM joined machines must skip every
        # HKLM\SOFTWARE\Policies\* write (spec 1.5.4): the management channel
        # reverts them on the next policy refresh and may raise compliance
        # alerts. This drives the PolicyWrites capability.
        $isDomain = $null
        if ($cs) { $isDomain = ConvertTo-OptBool -Value $cs.PartOfDomain }

        $isAzureAd = $null
        $isMdm     = $null
        try {
            $dsreg = & "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null
            if ($LASTEXITCODE -eq 0 -and $dsreg) {
                $text = $dsreg -join "`n"
                if ($text -match 'AzureAdJoined\s*:\s*(\w+)')    { $isAzureAd = ($Matches[1] -eq 'YES') }
                if ($text -match 'WorkplaceJoined\s*:\s*(\w+)')  { if ($Matches[1] -eq 'YES') { $isMdm = $true } }
                if ($text -match 'MDMUrl\s*:\s*(\S+)')           { $isMdm = $true }
                if ($null -eq $isMdm) { $isMdm = $false }
            }
        }
        catch { }

        # --- NPU / Copilot+ ---------------------------------------------------
        # Recall and the on-device AI surfaces only exist on Copilot+ hardware.
        # Without an NPU they are NOT INSTALLED, so section 8.5 must report
        # "not present, nothing to disable" rather than writing policy keys and
        # claiming a win.
        $npu = @(Get-PnpDevice -Class 'ComputeAccelerator' -ErrorAction SilentlyContinue |
                 Where-Object { $_.Status -eq 'OK' })
        $hasNpu = ($npu.Count -gt 0)

        [ordered]@{
            Caption         = if ($os) { $os.Caption } else { $null }
            BuildNumber     = $build
            DisplayVersion  = Get-OptRegValueSafe -Hive HKLM -SubKey $cvKey -Name 'DisplayVersion'
            UBR             = Get-OptRegValueSafe -Hive HKLM -SubKey $cvKey -Name 'UBR'
            IsWin11         = $isWin11
            Is22H2OrLater   = ($build -ge 22621)
            Edition         = $edition
            IsCopilotPlusPc = $hasNpu
            HasNpu          = $hasNpu
            IsDomainJoined  = $isDomain
            IsAzureAdJoined = $isAzureAd
            IsMdmEnrolled   = $isMdm
            IsManaged       = ([bool]$isDomain -or [bool]$isAzureAd -or [bool]$isMdm)
            # Home lacks gpedit.msc, but the HKLM\...\Policies keys still work
            # via the registry - so this only controls whether the report
            # references Group Policy UI paths.
            HasGroupPolicy  = ($edition -notlike '*Home*')
        }
    }
}
