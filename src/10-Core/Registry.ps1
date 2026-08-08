<#
    The registry mutation chokepoint.

    Everything goes through the [Microsoft.Win32.RegistryKey] API rather than
    the PowerShell registry provider, for three concrete reasons:

      1. Get-ItemProperty treats -Name as a WILDCARD pattern. Section 7.1's NIC
         keywords are literally named '*InterruptModeration', and section 3.3
         writes a value whose NAME is a filesystem path that can contain [ ].
      2. The provider decorates results with PSPath/PSParentPath/PSChildName,
         which collide with real value names.
      3. Explicit Registry64 protects against a 32-bit host silently landing in
         the WOW6432Node view.
#>

function Resolve-OptRegistryPath {
    <#
        'HKLM\SOFTWARE\Foo' or 'HKLM:\SOFTWARE\Foo' -> @{ Hive; SubKey }

        Applies, in order:
          - HKCU -> HKU\<interactive-sid> redirection when the elevated identity
            is not the interactive user
          - the test root map
          - the fail-closed interlock
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Path
    )

    $normalized = $Path -replace '^([A-Za-z_]+):\\', '$1\'
    $parts = $normalized -split '\\', 2
    $hive = $parts[0].ToUpperInvariant()
    $sub  = if ($parts.Count -gt 1) { $parts[1] } else { '' }

    switch ($hive) {
        'HKEY_LOCAL_MACHINE' { $hive = 'HKLM' }
        'HKEY_CURRENT_USER'  { $hive = 'HKCU' }
        'HKEY_USERS'         { $hive = 'HKU' }
        'HKEY_CLASSES_ROOT'  { $hive = 'HKCR' }
    }

    # Redirect user-scope writes to the interactive user's hive when they are
    # not the elevated identity. Without this, thirteen blocks of user tweaks
    # land in the wrong hive silently and the report still looks perfect.
    if ($hive -eq 'HKCU' -and $State.TargetUser -and -not $State.TargetUser.IsCurrent -and $State.TargetUser.HiveLoaded) {
        $hive = 'HKU'
        $sub  = "$($State.TargetUser.Sid)\$sub"
    }

    # Capture the LOGICAL location before any sandbox redirection. Capability
    # rules ("is this a Group Policy path?") are properties of the logical path
    # and must not be defeated by a test harness rewriting the physical one.
    $logicalHive   = $hive
    $logicalSubKey = $sub

    # Test sandbox redirection.
    if ($State.RegistryRootMap -and $State.RegistryRootMap.Count -gt 0) {
        $key = "$hive`:"
        if ($State.RegistryRootMap.Contains($key)) {
            $target = [string]$State.RegistryRootMap[$key]
            $tparts = ($target -replace '^([A-Za-z_]+):\\', '$1\') -split '\\', 2
            $hive = $tparts[0].ToUpperInvariant()
            $sub  = if ($tparts.Count -gt 1) { "$($tparts[1])\$sub" } else { $sub }
        }
    }

    # Fail-closed interlock. If a test harness set a sandbox root, a write that
    # resolves OUTSIDE it is a bug in the test, not something to tolerate - so
    # throw rather than write to the real hive.
    if ($env:CS2OPT_TEST_ROOT) {
        $resolved = "$hive\$sub"
        if (-not $resolved.StartsWith($env:CS2OPT_TEST_ROOT, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Registry sandbox interlock: '$resolved' resolves outside CS2OPT_TEST_ROOT ('$env:CS2OPT_TEST_ROOT')."
        }
    }

    return @{
        Hive          = $hive
        SubKey        = $sub
        Display       = "$hive\$sub"
        LogicalHive   = $logicalHive
        LogicalSubKey = $logicalSubKey
    }
}

function Get-OptRegistryHiveKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Hive)

    $h = switch ($Hive) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKU'  { [Microsoft.Win32.RegistryHive]::Users }
        'HKCR' { [Microsoft.Win32.RegistryHive]::ClassesRoot }
        default { throw "Unsupported registry hive '$Hive'" }
    }
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, [Microsoft.Win32.RegistryView]::Registry64)
}

function Test-OptRegistryPathAllowed {
    <#
        Capability enforcement at the write chokepoint.

        Putting the domain/Azure-AD/MDM policy rule here rather than in the gate
        matrix collapses what would otherwise be one gate row per policy key
        (sections 3.1, 8.2, 8.5, 8.6, 8.7 all write HKLM\SOFTWARE\Policies) into
        a single predicate - while still logging every skipped key individually
        so the report stays complete.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$SubKey
    )

    if ($Hive -eq 'HKLM' -and $SubKey -like 'SOFTWARE\Policies\*' -and -not $State.Capabilities.PolicyWrites) {
        return @{ Allowed = $false; Reason = 'policy writes blocked - machine is domain/Azure-AD/MDM managed and this would be reverted by policy refresh' }
    }

    if ($Hive -in @('HKCU', 'HKU') -and -not $State.Capabilities.HkcuWrites) {
        return @{ Allowed = $false; Reason = 'user-hive writes blocked - the interactive user profile could not be resolved' }
    }

    return @{ Allowed = $true; Reason = $null }
}

function ConvertTo-OptDWordInt32 {
    <#
        DWORD values are stored as Int32 by the .NET registry API, but plenty of
        real settings are written as unsigned - section 4.1 sets
        NetworkThrottlingIndex to 0xFFFFFFFF, which reads back as -1.

        A naive `-eq 4294967295` is therefore false forever: the script would
        rewrite the value on every run (idempotency broken) and the manifest
        would store -1, which then cannot be written back without a cast.
        Convert through the raw bytes so the bit pattern is preserved in both
        directions.
    #>
    [CmdletBinding()][OutputType([int])]
    param([Parameter(Mandatory)]$Value)

    if ($Value -is [int]) { return $Value }

    $u = [uint32]0
    if ([uint32]::TryParse([string]$Value, [ref]$u)) {
        return [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($u), 0)
    }
    return [int]$Value
}

function ConvertTo-OptRegistryData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][AllowNull()]$Value
    )

    switch ($Type) {
        'DWord'        { return ConvertTo-OptDWordInt32 -Value $Value }
        'QWord'        { return [long]$Value }
        'String'       { return [string]$Value }
        'ExpandString' { return [string]$Value }
        'MultiString'  { return [string[]]@($Value) }
        'Binary'       { return [byte[]]$Value }
        default        { return $Value }
    }
}

function Compare-OptRegistryData {
    <#
        Type-aware equality. Returns $true when current already equals desired.
    #>
    [CmdletBinding()][OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][AllowNull()]$Current,
        [Parameter(Mandatory)][AllowNull()]$Desired
    )

    if ($null -eq $Current -and $null -eq $Desired) { return $true }
    if ($null -eq $Current -or  $null -eq $Desired) { return $false }

    switch ($Type) {
        'DWord' {
            # Compare the bit patterns, so -1 and 4294967295 match.
            return ((ConvertTo-OptDWordInt32 -Value $Current) -eq (ConvertTo-OptDWordInt32 -Value $Desired))
        }
        'QWord'       { return ([long]$Current -eq [long]$Desired) }
        'MultiString' {
            $a = @($Current); $b = @($Desired)
            if ($a.Count -ne $b.Count) { return $false }
            for ($i = 0; $i -lt $a.Count; $i++) {
                if ([string]$a[$i] -ne [string]$b[$i]) { return $false }
            }
            return $true
        }
        'Binary' {
            $a = [byte[]]$Current; $b = [byte[]]$Desired
            if ($a.Length -ne $b.Length) { return $false }
            for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
            return $true
        }
        default { return ([string]$Current -eq [string]$Desired) }
    }
}

function Get-OptRegistryValueInfo {
    <#
        Tri-state read: KeyAbsent / Absent / Present.

        ExistedBefore is decided by whether the NAME appears in GetValueNames(),
        not by whether GetValue() returned $null - an empty REG_SZ is a
        legitimate existing value and must not be mistaken for an absent one,
        or rollback would delete something it should have restored.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$Name
    )

    $base = $null; $key = $null
    try {
        $base = Get-OptRegistryHiveKey -Hive $Hive
        $key  = $base.OpenSubKey($SubKey)

        if (-not $key) {
            return @{ State = 'KeyAbsent'; Value = $null; Kind = $null; KeyExists = $false; ValueExists = $false }
        }

        $names = @($key.GetValueNames())
        $exists = $false
        foreach ($n in $names) {
            if ([string]::Equals($n, $Name, [StringComparison]::OrdinalIgnoreCase)) { $exists = $true; break }
        }

        if (-not $exists) {
            return @{ State = 'Absent'; Value = $null; Kind = $null; KeyExists = $true; ValueExists = $false }
        }

        $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind  = $key.GetValueKind($Name)

        return @{ State = 'Present'; Value = $value; Kind = [string]$kind; KeyExists = $true; ValueExists = $true }
    }
    catch {
        return @{ State = 'Error'; Value = $null; Kind = $null; KeyExists = $false; ValueExists = $false; Error = $_.Exception.Message }
    }
    finally {
        if ($key)  { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }
}

function Set-OptRegistryValue {
    <#
        Idempotent registry setter. NEVER throws on an expected condition -
        returns a result object so one failed tweak cannot abort a section.

        Returns Action = Applied | AlreadyCorrect | Skipped | DryRun | Failed
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')]
        [string]$Type,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()]$Value,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][ValidateSet('Safe', 'Aggressive', 'Experimental')][string]$Tier,
        [string]$Id,
        [string]$Title,
        [switch]$RequiresReboot,
        [ValidateSet('Immediate', 'PostReboot', 'None')][string]$VerifyMode = 'Immediate'
    )

    if (-not $Id) { $Id = "S-$Section-$Name" }

    # 1. section gate
    if (-not (Test-OptSectionEnabled -State $State -Section $Section)) {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Off' `
            -Title $Title -Reason 'section gated off')
        return @{ Action = 'Skipped'; Reason = 'section gated off' }
    }

    # 2. tier gate
    if (-not (Test-OptTier -State $State -Required $Tier)) {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Off' `
            -Title $Title -Reason "requires tier $Tier (run tier is $($State.Tier))")
        return @{ Action = 'Skipped'; Reason = "tier $Tier" }
    }

    # 3. resolve + capability check
    try   { $resolved = Resolve-OptRegistryPath -State $State -Path $Path }
    catch {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Failed' `
            -Title $Title -Reason $_.Exception.Message -Severity 'Error')
        return @{ Action = 'Failed'; Reason = $_.Exception.Message }
    }

    $allowed = Test-OptRegistryPathAllowed -State $State -Hive $resolved.LogicalHive -SubKey $resolved.LogicalSubKey
    if (-not $allowed.Allowed) {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Off' `
            -Title $Title -Reason "$($allowed.Reason): $($resolved.Display)\$Name" -Severity 'Warning')
        return @{ Action = 'Skipped'; Reason = $allowed.Reason }
    }

    # 4. read current
    $info = Get-OptRegistryValueInfo -State $State -Hive $resolved.Hive -SubKey $resolved.SubKey -Name $Name
    if ($info.State -eq 'Error') {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Failed' `
            -Title $Title -Reason "read failed: $($info.Error)" -Severity 'Error')
        return @{ Action = 'Failed'; Reason = $info.Error }
    }

    $desired = ConvertTo-OptRegistryData -Type $Type -Value $Value

    # 5. already correct? -> NoOp decision, and crucially NO change record.
    if ($info.ValueExists -and (Compare-OptRegistryData -Type $Type -Current $info.Value -Desired $desired)) {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'NoOp' `
            -Title $Title -Reason "already set to the desired value ($($resolved.Display)\$Name)")
        return @{ Action = 'AlreadyCorrect'; Reason = 'already correct' }
    }

    # 6. back up the exact key
    $backupFile = Backup-OptRegistryKey -State $State -Hive $resolved.Hive -SubKey $resolved.SubKey

    # 7. dry run stops here, having done all the real reading
    if ($State.DryRun) {
        $change = New-OptChangeRecord -State $State -Type 'Registry' -Section $Section -Tier $Tier `
            -Path $resolved.Display -Name $Name `
            -Target @{ Hive = $resolved.Hive; SubKey = $resolved.SubKey; Name = $Name; ValueKind = $Type; OldValueKind = $info.Kind } `
            -OldValue $info.Value -NewValue $desired `
            -ExistedBefore $info.ValueExists -KeyExistedBefore $info.KeyExists `
            -BackupFile $backupFile -RequiresReboot:$RequiresReboot -VerifyMode $VerifyMode
        [void]$State.Changes.Add($change)
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Applied' `
            -Title $Title -Reason "would set $($resolved.Display)\$Name = $(Format-OptValueForLog $desired)")
        return @{ Action = 'DryRun'; Change = $change }
    }

    # 8. apply
    $base = $null; $key = $null
    try {
        $base = Get-OptRegistryHiveKey -Hive $resolved.Hive
        $key  = $base.CreateSubKey($resolved.SubKey)
        if (-not $key) { throw "could not open or create $($resolved.Display)" }

        $key.SetValue($Name, $desired, [Microsoft.Win32.RegistryValueKind]::$Type)
    }
    catch {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Failed' `
            -Title $Title -Reason "write failed: $($_.Exception.Message)" -Severity 'Error')
        return @{ Action = 'Failed'; Reason = $_.Exception.Message }
    }
    finally {
        if ($key)  { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }

    $change = New-OptChangeRecord -State $State -Type 'Registry' -Section $Section -Tier $Tier `
        -Path $resolved.Display -Name $Name `
        -Target @{ Hive = $resolved.Hive; SubKey = $resolved.SubKey; Name = $Name; ValueKind = $Type; OldValueKind = $info.Kind } `
        -OldValue $info.Value -NewValue $desired `
        -ExistedBefore $info.ValueExists -KeyExistedBefore $info.KeyExists `
        -BackupFile $backupFile -RequiresReboot:$RequiresReboot -VerifyMode $VerifyMode

    [void](Add-OptChange -State $State -Change $change)
    [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Applied' `
        -Title $Title -Reason "$($resolved.Display)\$Name = $(Format-OptValueForLog $desired)")

    return @{ Action = 'Applied'; Change = $change }
}

function Remove-OptRegistryValue {
    <#
        Needed for section 3.2's MPO rollback and section 13's revert of bad
        tweaks left behind by other optimization scripts.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][ValidateSet('Safe', 'Aggressive', 'Experimental')][string]$Tier,
        [string]$Id,
        [string]$Title,
        [string]$Reason,
        [switch]$RequiresReboot
    )

    if (-not $Id) { $Id = "S-$Section-$Name-remove" }

    if (-not (Test-OptSectionEnabled -State $State -Section $Section)) {
        return @{ Action = 'Skipped'; Reason = 'section gated off' }
    }
    if (-not (Test-OptTier -State $State -Required $Tier)) {
        return @{ Action = 'Skipped'; Reason = "tier $Tier" }
    }

    $resolved = Resolve-OptRegistryPath -State $State -Path $Path
    $info = Get-OptRegistryValueInfo -State $State -Hive $resolved.Hive -SubKey $resolved.SubKey -Name $Name

    if (-not $info.ValueExists) {
        [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'NoOp' `
            -Title $Title -Reason "not present, nothing to remove ($($resolved.Display)\$Name)")
        return @{ Action = 'AlreadyCorrect'; Reason = 'not present' }
    }

    $backupFile = Backup-OptRegistryKey -State $State -Hive $resolved.Hive -SubKey $resolved.SubKey

    if (-not $State.DryRun) {
        $base = $null; $key = $null
        try {
            $base = Get-OptRegistryHiveKey -Hive $resolved.Hive
            $key  = $base.OpenSubKey($resolved.SubKey, $true)
            if ($key) { $key.DeleteValue($Name, $false) }
        }
        catch {
            [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Failed' `
                -Title $Title -Reason "delete failed: $($_.Exception.Message)" -Severity 'Error')
            return @{ Action = 'Failed'; Reason = $_.Exception.Message }
        }
        finally {
            if ($key)  { $key.Dispose() }
            if ($base) { $base.Dispose() }
        }
    }

    $change = New-OptChangeRecord -State $State -Type 'RegistryValueDelete' -Section $Section -Tier $Tier `
        -Path $resolved.Display -Name $Name `
        -Target @{ Hive = $resolved.Hive; SubKey = $resolved.SubKey; Name = $Name; ValueKind = $info.Kind } `
        -OldValue $info.Value -NewValue $null `
        -ExistedBefore $true -KeyExistedBefore $info.KeyExists `
        -BackupFile $backupFile -RequiresReboot:$RequiresReboot

    if ($State.DryRun) { [void]$State.Changes.Add($change) }
    else { [void](Add-OptChange -State $State -Change $change) }

    [void](Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Applied' `
        -Title $Title -Reason $(if ($Reason) { $Reason } else { "removed $($resolved.Display)\$Name" }))

    return @{ Action = 'Applied'; Change = $change }
}

function Format-OptValueForLog {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) { return '<absent>' }
    if ($Value -is [byte[]])   { return "<$($Value.Length) bytes>" }
    if ($Value -is [string[]]) { return ($Value -join '; ') }
    return [string]$Value
}
