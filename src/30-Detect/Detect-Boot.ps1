function Get-OptBootSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        FirmwareType = 'Unknown'; IsDualBoot = $null; BootEntries = @()
        NonWindowsPartitions = @(); DualBootEvidence = @()
        FastStartupEnabled = $null; HibernationEnabled = $null
    }
}

function Get-OptBootInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$StorageInfo
    )

    return Invoke-OptDetector -State $State -Name 'Boot' -UnknownSkeleton (Get-OptBootSkeleton) -ScriptBlock {
        $firmware = 'Unknown'
        try {
            # PEFirmwareType: 1 = BIOS, 2 = UEFI.
            $fw = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType
            if ($fw) { $firmware = [string]$fw }
        }
        catch {
            if ($env:firmware_type) { $firmware = $env:firmware_type }
        }

        $evidence = @()

        # --- BCD firmware entries --------------------------------------------
        # Only half the story. On the reference machine Linux boots from its own
        # ESP via the firmware boot menu, so `bcdedit /enum firmware` lists ONLY
        # Windows Boot Manager even though the machine is genuinely dual-boot.
        $entries = @()
        $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/enum', 'firmware') -ReadOnly
        if ($r.Success) {
            $currentDesc = $null
            foreach ($line in (Get-OptCommandLines -Text $r.StdOut)) {
                if ($line -match '^\s*description\s+(.+)$') {
                    $currentDesc = $Matches[1].Trim()
                    $entries += $currentDesc
                }
            }
            $nonWindows = @($entries | Where-Object { $_ -notmatch 'Windows|Firmware Application|UEFI OS Boot' })
            if ($nonWindows.Count -gt 0) {
                $evidence += "BCD firmware entries: $($nonWindows -join ', ')"
            }
        }

        # --- partition heuristic ---------------------------------------------
        # This is the half that actually fires here. A partition Windows cannot
        # recognise (ext4/btrfs/xfs) shows up with no drive letter and an
        # unrecognised type - that is the Linux install.
        $foreign = @()
        try {
            foreach ($part in (Get-Partition -ErrorAction Stop)) {
                $sizeGb = [int][math]::Round($part.Size / 1GB)
                if ($part.DriveLetter) { continue }
                if ($sizeGb -lt 8) { continue }              # ignore ESP/MSR/recovery
                $type = [string]$part.Type
                if ($type -match 'Basic|Reserved|Recovery|System') { continue }

                $foreign += [ordered]@{
                    DiskNumber      = [int]$part.DiskNumber
                    PartitionNumber = [int]$part.PartitionNumber
                    Type            = $type
                    SizeGB          = $sizeGb
                }
            }
        }
        catch { }

        if ($foreign.Count -gt 0) {
            $evidence += ("unrecognised partition(s): " + (($foreign | ForEach-Object { "disk $($_.DiskNumber) part $($_.PartitionNumber) $($_.Type) $($_.SizeGB)GB" }) -join '; '))
        }

        # --- hibernation / Fast Startup --------------------------------------
        $hiberFileSize = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateFileSizePercent'
        $hiberEnabled  = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
        $hiberboot     = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled'

        # Both registry values are absent on current builds when hibernation was
        # never explicitly toggled, so fall back to the artefact itself: the
        # presence of hiberfil.sys is the ground truth for "hibernation is on".
        $hibernation = $null
        if ($null -ne $hiberEnabled)       { $hibernation = ([int]$hiberEnabled -ne 0) }
        elseif ($null -ne $hiberFileSize)  { $hibernation = ([int]$hiberFileSize -gt 0) }
        else {
            $hiberFile = Join-Path $env:SystemDrive 'hiberfil.sys'
            # Needs -Force: hiberfil.sys is hidden + system.
            $hibernation = [bool](Get-Item -LiteralPath $hiberFile -Force -ErrorAction SilentlyContinue)
        }

        [ordered]@{
            FirmwareType         = $firmware
            BootEntries          = $entries
            NonWindowsPartitions = $foreign
            DualBootEvidence     = $evidence
            IsDualBoot           = ($evidence.Count -gt 0)
            HibernationEnabled   = $hibernation
            # Fast Startup defaults to ON when the value is absent.
            FastStartupEnabled   = $(if ($null -ne $hiberboot) { ([int]$hiberboot -ne 0) } else { $true })
        }
    }
}
