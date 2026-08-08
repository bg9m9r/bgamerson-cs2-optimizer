<#
    Profile orchestration.

    Detection happens ONCE, is logged once, and is serialized into the manifest
    so a failed run can be diagnosed from the log alone (spec 1.5). No section
    may call CIM/WMI directly - they all read $State.Profile.
#>

function Resolve-OptTargetUser {
    <#
        Determines whose HKCU the user-scope tweaks must land in.

        Thirteen blocks in the spec write HKCU (3.1, 3.3, 6.1, 6.2, 8.2, 8.3,
        8.5, 8.6, 8.7). If the script is elevated as a DIFFERENT admin account
        than the interactive user, HKCU in this process is the admin's hive and
        every one of those tweaks silently lands in the wrong place. Nothing
        errors, and the report looks perfect.

        Resolve the interactive user from explorer.exe's owner and compare.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentSid = $current.User.Value

    $result = [ordered]@{
        Sid        = $currentSid
        Name       = $current.Name
        IsCurrent  = $true
        HiveLoaded = $false
        HkcuRoot   = 'HKCU'
        Warning    = $null
    }

    try {
        $explorer = Get-OptCimSafe -ClassName Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
        if (-not $explorer) {
            $result.Warning = 'explorer.exe not running - assuming the elevated identity is the interactive user'
            return $result
        }

        $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -ne 0) { return $result }

        $account = "$($owner.Domain)\$($owner.User)"
        $sid = (New-Object System.Security.Principal.NTAccount($owner.Domain, $owner.User)).
                    Translate([System.Security.Principal.SecurityIdentifier]).Value

        $result.Name = $account
        if ($sid -eq $currentSid) { return $result }

        # Different user. Redirect HKCU writes to that user's hive.
        $result.Sid       = $sid
        $result.IsCurrent = $false

        $usersBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::Users,
                        [Microsoft.Win32.RegistryView]::Registry64)
        $loaded = @($usersBase.GetSubKeyNames()) -contains $sid
        $usersBase.Dispose()

        if ($loaded) {
            $result.HiveLoaded = $true
            $result.HkcuRoot   = "HKU\$sid"
        }
        else {
            # Refuse rather than write to the wrong hive.
            $result.Warning = "interactive user $account ($sid) hive is not loaded - HKCU tweaks will be skipped"
            $State.Capabilities.HkcuWrites = $false
        }
    }
    catch {
        $result.Warning = "could not resolve interactive user: $($_.Exception.Message)"
    }

    return $result
}

function Assert-OptSerializable {
    <#
        Recursive walk that throws on any leaf which is not a JSON-safe
        primitive. Catches a CimInstance or DateTime smuggled into the profile,
        which would otherwise produce hundreds of KB of garbage or throw during
        manifest write - after changes had already been applied.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Object,
        [string]$Path = '$Profile',
        [int]$Depth = 0
    )

    if ($Depth -gt 20) { throw "Profile nesting deeper than 20 at $Path" }
    if ($null -eq $Object) { return }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) {
            Assert-OptSerializable -Object $Object[$k] -Path "$Path.$k" -Depth ($Depth + 1)
        }
        return
    }

    if ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [string]) {
        $i = 0
        foreach ($item in $Object) {
            Assert-OptSerializable -Object $item -Path "$Path[$i]" -Depth ($Depth + 1)
            $i++
        }
        return
    }

    # WMI hands back plenty of unsigned/short numeric types - Win32_Processor
    # .Family is a UInt16, for instance - and they serialize to JSON perfectly
    # well. The point of this assertion is to catch CimInstance, DateTime,
    # TimeSpan and other reference types that would explode the manifest, not to
    # police integer width.
    $ok = $Object -is [string]  -or $Object -is [bool]    -or
          $Object -is [int]     -or $Object -is [long]    -or
          $Object -is [double]  -or $Object -is [decimal] -or
          $Object -is [single]  -or
          $Object -is [uint16]  -or $Object -is [uint32]  -or $Object -is [uint64] -or
          $Object -is [byte]    -or $Object -is [sbyte]   -or
          $Object -is [int16]   -or $Object -is [char]

    if (-not $ok) {
        throw "Profile contains a non-serializable value at ${Path}: [$($Object.GetType().FullName)]"
    }
}

function Get-OptProfileFingerprint {
    <#
        Hash only STABLE hardware identity (spec 1.5.6).

        Deliberately excludes display refresh and virtual NIC MACs: a monitor
        asleep at scan time or a VPN adapter appearing would otherwise change
        the fingerprint and raise a false "hardware changed" alarm on every
        other run. Refresh is carried separately as a soft signal.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$ProfileData)

    $parts = [ordered]@{
        CpuName    = [string]$ProfileData.CPU.Name
        GpuIds     = (@($ProfileData.GPU.Adapters | ForEach-Object { $_.PnpDeviceId }) | Sort-Object) -join '|'
        BootDisk   = ''
        NicMacs    = (@($ProfileData.Network.Adapters | Where-Object { -not $_.IsVirtual } |
                        ForEach-Object { $_.MacAddress }) | Sort-Object) -join '|'
        Baseboard  = ''
    }

    $bootVol = $ProfileData.Storage.Volumes | Where-Object { $_.IsBoot } | Select-Object -First 1
    if ($bootVol) {
        $disk = $ProfileData.Storage.Disks | Where-Object { $_.DeviceId -eq [string]$bootVol.DiskNumber } | Select-Object -First 1
        if ($disk) { $parts.BootDisk = [string]$disk.SerialNumber }
    }

    $bb = Get-OptCimSafe -ClassName Win32_BaseBoard | Select-Object -First 1
    if ($bb) { $parts.Baseboard = [string]$bb.SerialNumber }

    $material = ($parts.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = [System.BitConverter]::ToString(
                    $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($material))
                ).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }

    return [ordered]@{ Hash = "sha256:$hash"; Components = $parts }
}

function Get-OptProfile {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Seeded first so Invoke-OptDetector has somewhere to record failures.
    $State.Profile = [ordered]@{
        SchemaVersion     = 1
        CapturedUtc       = (Get-Date).ToUniversalTime().ToString('o')
        DetectionErrors   = New-Object System.Collections.ArrayList
        DetectionTimings  = [ordered]@{}
    }
    $p = $State.Profile

    $State.TargetUser = Resolve-OptTargetUser -State $State

    $p.OS             = Get-OptOsInfo             -State $State
    $p.CPU            = Get-OptCpuInfo            -State $State
    $p.Memory         = Get-OptMemoryInfo         -State $State
    $p.Storage        = Get-OptStorageInfo        -State $State

    # GPU needs the interop display list to resolve which adapter drives the
    # primary display; Display then needs the GPU list for the iGPU-cable gate.
    $displayAdapters  = @()
    if ($State.Capabilities.Interop) { $displayAdapters = Get-OptDisplayAdapters }

    $p.GPU            = Get-OptGpuInfo            -State $State -DisplayAdapters $displayAdapters
    $p.Display        = Get-OptDisplayInfo        -State $State -GpuInfo $p.GPU
    $p.Network        = Get-OptNetworkInfo        -State $State
    $p.Audio          = Get-OptAudioInfo          -State $State
    $p.Input          = Get-OptInputInfo          -State $State
    $p.Power          = Get-OptPowerInfo          -State $State
    $p.Security       = Get-OptSecurityInfo       -State $State
    $p.Games          = Get-OptGamesInfo          -State $State -StorageInfo $p.Storage
    $p.Boot           = Get-OptBootInfo           -State $State -StorageInfo $p.Storage
    $p.Virtualization = Get-OptVirtualizationInfo -State $State

    $p.Fingerprint = Get-OptProfileFingerprint -ProfileData $p

    # DetectionErrors stays an ArrayList on purpose - reassigning the key in
    # place throws, and both Assert-OptSerializable and ConvertTo-Json iterate
    # it perfectly well, so there is nothing to convert.
    #
    # ArrayList rather than List[object] throughout: on Windows PowerShell 5.1
    # the array subexpression @() applied to a List[object] throws
    # "Argument types do not match". List[string] and ArrayList are unaffected.

    return $p
}

function Export-OptProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ProfileData,
        [Parameter(Mandatory)][string]$Path
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    # -Depth is mandatory, not stylistic: ConvertTo-Json defaults to depth 2,
    # and this object is far deeper than that. Without it the profile silently
    # serializes to the literal string "System.Collections.Hashtable".
    $ProfileData | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Import-OptProfile {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Profile file not found: $Path" }

    $json = Get-Content -LiteralPath $Path -Raw
    # 5.1's ConvertFrom-Json has no -AsHashtable, so convert the PSCustomObject
    # graph back to hashtables to keep every consumer's access pattern identical
    # between a live profile and a loaded fixture.
    return ConvertTo-OptHashtable -Object ($json | ConvertFrom-Json)
}

function ConvertTo-OptHashtable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Object)

    if ($null -eq $Object) { return $null }

    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($prop in $Object.PSObject.Properties) {
            $h[$prop.Name] = ConvertTo-OptHashtable -Object $prop.Value
        }
        return $h
    }

    if ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [string]) {
        # Leading comma keeps a one-element JSON array an array on the way back
        # out, so a loaded fixture has the same shape as a live profile.
        return , @(foreach ($item in $Object) { ConvertTo-OptHashtable -Object $item })
    }

    return $Object
}
