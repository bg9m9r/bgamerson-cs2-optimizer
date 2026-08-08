<#
    Detector framework.

    Every detector runs inside Invoke-OptDetector, which times it, catches
    everything, and on failure returns a COMPLETE "unknown skeleton" - the same
    shape with every field $null / @() / 'Unknown'.

    That is what makes spec 1.5.3's fail-safe rule structural rather than a
    discipline each of forty gate predicates has to remember. With the skeleton,
    $p.CPU.HasVCache on a totally failed CPU detection returns $null (which
    every tri-state gate handles), instead of throwing PropertyNotFound under
    StrictMode and killing the run.
#>

function Invoke-OptDetector {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][System.Collections.IDictionary]$UnknownSkeleton
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $ScriptBlock
        $sw.Stop()

        if ($null -eq $result) {
            [void]$State.Profile.DetectionErrors.Add(@{
                Detector = $Name
                Message  = 'detector returned null'
                Fatal    = $false
            })
            return (Copy-OptSkeleton -Skeleton $UnknownSkeleton)
        }

        $State.Profile.DetectionTimings[$Name] = $sw.ElapsedMilliseconds
        return $result
    }
    catch {
        $sw.Stop()
        # Detection failures are warnings, not fatal errors (spec 1.5.3). The
        # only fatal checks are the section 0 security ones, which run later.
        [void]$State.Profile.DetectionErrors.Add(@{
            Detector = $Name
            Message  = $_.Exception.Message
            Fatal    = $false
        })
        $State.Profile.DetectionTimings[$Name] = $sw.ElapsedMilliseconds
        return (Copy-OptSkeleton -Skeleton $UnknownSkeleton)
    }
}

function Copy-OptSkeleton {
    <#
        Deep copy so a mutated skeleton can never leak between detectors.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Skeleton)

    $copy = [ordered]@{}
    foreach ($k in $Skeleton.Keys) {
        $v = $Skeleton[$k]
        if ($v -is [hashtable]) {
            $copy[$k] = Copy-OptSkeleton -Skeleton $v
        }
        elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            $copy[$k] = @()
        }
        else {
            $copy[$k] = $v
        }
    }
    return $copy
}

function ConvertTo-OptBool {
    <#
        Tri-state coercion. Returns $true, $false, or $null for "indeterminate".

        This is the backbone of the gating matrix. A gate predicate that
        returns $null must be handled by its row's explicit OnIndeterminate
        policy rather than collapsing to $false, because `-not $null` is $true -
        which would apply a tweak on unknown hardware, exactly inverting the
        fail-safe rule.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        if ($Value -match '^(1|true|yes|on|enabled)$')  { return $true }
        if ($Value -match '^(0|false|no|off|disabled)$') { return $false }
        return $null
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32]) {
        return ([int]$Value -ne 0)
    }
    return [bool]$Value
}

function Get-OptCimSafe {
    <#
        CIM query that returns @() instead of throwing. Several classes used
        here are simply absent on some machines (Win32_Battery on a desktop,
        MSFT_DmaGuard on older builds, Win32_PhysicalMemory in some VMs).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClassName,
        [string]$Namespace = 'root\cimv2',
        [string]$Filter,
        [string[]]$Property
    )

    try {
        $splat = @{ ClassName = $ClassName; Namespace = $Namespace; ErrorAction = 'Stop' }
        if ($Filter)   { $splat['Filter']   = $Filter }
        if ($Property) { $splat['Property'] = $Property }

        # Returns unrolled (a single instance comes back as a scalar). That is
        # deliberate: this function is frequently PIPED directly into
        # Select-Object/Where-Object, and the array-preserving `return ,@()`
        # idiom breaks piping - the pipeline would see the whole array as ONE
        # item. Callers that need .Count or indexing wrap the call in @(...)
        # themselves, which is the idiomatic side to solve it on.
        return @(Get-CimInstance @splat)
    }
    catch {
        return @()
    }
}

function Get-OptRegValueSafe {
    <#
        Plain registry read for detection. Uses the RegistryKey API rather than
        Get-ItemProperty because -Name there is treated as a WILDCARD pattern,
        which breaks on the NIC keyword names ('*InterruptModeration') and on
        Steam library paths containing brackets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('HKLM', 'HKCU', 'HKCR', 'HKU')][string]$Hive,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$Name
    )

    $baseName = switch ($Hive) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKCR' { [Microsoft.Win32.RegistryHive]::ClassesRoot }
        'HKU'  { [Microsoft.Win32.RegistryHive]::Users }
    }

    $base = $null
    $key  = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($baseName, [Microsoft.Win32.RegistryView]::Registry64)
        $key  = $base.OpenSubKey($SubKey)
        if (-not $key) { return $null }
        return $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    catch {
        return $null
    }
    finally {
        if ($key)  { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }
}
