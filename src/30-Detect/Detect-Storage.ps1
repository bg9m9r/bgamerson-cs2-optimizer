function Get-OptStorageSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Volumes = @(); Disks = @(); BootBusType = 'Unknown'; BootMediaType = 'Unknown'
        TrimEnabled = $null; HasHdd = $null; HasNonBootFixedVolume = $null
    }
}

function Get-OptStorageInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Storage' -UnknownSkeleton (Get-OptStorageSkeleton) -ScriptBlock {
        $bootLetter = ($env:SystemDrive).TrimEnd(':')

        $physical = @()
        try {
            $physical = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    DeviceId     = $_.DeviceId
                    FriendlyName = $_.FriendlyName
                    BusType      = [string]$_.BusType
                    MediaType    = [string]$_.MediaType
                    SizeGB       = [int][math]::Round($_.Size / 1GB)
                    SerialNumber = $_.SerialNumber
                }
            })
        }
        catch { }

        # Map each lettered volume back to its physical disk so BusType and
        # MediaType can be attributed per drive letter. Disk -> Partition ->
        # Volume, because Get-Volume alone does not carry bus type.
        $volumes = @()
        try {
            foreach ($part in (Get-Partition -ErrorAction Stop | Where-Object { $_.DriveLetter })) {
                $disk = $physical | Where-Object { $_.DeviceId -eq [string]$part.DiskNumber } | Select-Object -First 1
                $vol  = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue

                $volumes += [ordered]@{
                    DriveLetter = [string]$part.DriveLetter
                    DiskNumber  = [int]$part.DiskNumber
                    BusType     = $(if ($disk) { $disk.BusType }   else { 'Unknown' })
                    MediaType   = $(if ($disk) { $disk.MediaType } else { 'Unknown' })
                    FileSystem  = $(if ($vol)  { [string]$vol.FileSystem } else { $null })
                    Label       = $(if ($vol)  { [string]$vol.FileSystemLabel } else { $null })
                    SizeGB      = $(if ($vol -and $vol.Size) { [int][math]::Round($vol.Size / 1GB) } else { $null })
                    FreeGB      = $(if ($vol -and $vol.SizeRemaining) { [int][math]::Round($vol.SizeRemaining / 1GB) } else { $null })
                    IsBoot      = ([string]$part.DriveLetter -eq $bootLetter)
                }
            }
        }
        catch { }

        $boot = $volumes | Where-Object { $_.IsBoot } | Select-Object -First 1

        # --- TRIM -------------------------------------------------------------
        # DisableDeleteNotify=0 means TRIM is ON. The command reports separate
        # NTFS and ReFS lines on current builds, so match the value rather than
        # assuming a single line.
        $trim = $null
        $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
             -ArgumentList @('behavior', 'query', 'DisableDeleteNotify') -ReadOnly
        if ($r.Success) {
            $lines = Get-OptCommandLines -Text $r.StdOut
            $ntfs  = $lines | Where-Object { $_ -match 'NTFS' } | Select-Object -First 1
            $any   = $lines | Where-Object { $_ -match 'DisableDeleteNotify\s*=\s*(\d)' } | Select-Object -First 1
            $line  = if ($ntfs) { $ntfs } else { $any }
            if ($line -and $line -match '=\s*(\d)') { $trim = ([int]$Matches[1] -eq 0) }
        }

        $nonBootFixed = @($volumes | Where-Object { -not $_.IsBoot -and $_.FileSystem -eq 'NTFS' })

        [ordered]@{
            Volumes               = $volumes
            Disks                 = $physical
            BootBusType           = $(if ($boot) { $boot.BusType }   else { 'Unknown' })
            BootMediaType         = $(if ($boot) { $boot.MediaType } else { 'Unknown' })
            BootFreeGB            = $(if ($boot) { $boot.FreeGB }    else { $null })
            TrimEnabled           = $trim
            HasHdd                = ([bool](@($physical | Where-Object { $_.MediaType -eq 'HDD' }).Count))
            # On the reference machine this is FALSE: C: is the only lettered
            # volume (disk 1 holds the EFI system partition and a Linux
            # partition Windows reports as Unknown). Section 5.1 therefore has
            # no non-boot candidate for the pagefile even before the
            # crash-dump argument applies.
            HasNonBootFixedVolume = ($nonBootFixed.Count -gt 0)
            NonBootFixedVolumes   = $nonBootFixed
        }
    }
}
