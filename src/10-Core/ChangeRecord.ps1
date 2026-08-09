<#
    Change records and the append-only journal.

    THE MOST IMPORTANT RULE IN THIS FILE: never emit a change record when the
    value was already correct. Emit a NoOp decision instead.

    On the reference machine sections 2.1, 4.3, 5.4 and part of 9 are already in
    their desired state. Recording those as "changes" would mean -Rollback
    re-enables the memory compression the user had already disabled - i.e. the
    rollback would move the machine to a state it has never been in. That is the
    single most dangerous correctness bug available in this design.
#>

function New-OptChangeRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Tier,

        [string]$Path,
        [string]$Name,
        [System.Collections.IDictionary]$Target,

        [AllowNull()]$OldValue,
        [AllowNull()]$NewValue,

        [bool]$ExistedBefore = $true,
        [bool]$KeyExistedBefore = $true,
        [string]$BackupFile,

        [switch]$RequiresReboot,
        [ValidateSet('Immediate', 'PostReboot', 'None')][string]$VerifyMode = 'Immediate',
        [ValidateSet('Full', 'Partial', 'None')][string]$Reversible = 'Full',
        [string]$Note
    )

    $State.ChangeOrdinal = [int]$State.ChangeOrdinal + 1

    return [ordered]@{
        Id               = '{0:D4}' -f $State.ChangeOrdinal   # ordinal == apply order
        Type             = $Type
        Section          = $Section
        Tier             = $Tier
        Path             = $Path
        Name             = $Name
        Target           = $Target
        OldValue         = ConvertTo-OptStorableValue -Value $OldValue
        NewValue         = ConvertTo-OptStorableValue -Value $NewValue
        ExistedBefore    = $ExistedBefore
        KeyExistedBefore = $KeyExistedBefore
        BackupFile       = $BackupFile
        Applied          = $true
        RequiresReboot   = [bool]$RequiresReboot
        VerifyMode       = $VerifyMode
        Reversible       = $Reversible
        Timestamp        = (Get-Date).ToUniversalTime().ToString('o')
        Note             = $Note
    }
}

function ConvertTo-OptStorableValue {
    <#
        Makes a value safe to round-trip through JSON.

        REG_BINARY is the case that forces this. ConvertTo-Json turns a byte[]
        into an array of integers, and ConvertFrom-Json hands back Object[] - so
        a naive rollback would write garbage or throw. No section currently
        WRITES a binary value, but rollback restores the OLD value of whatever a
        section replaces, and any pre-existing value can be REG_BINARY - so the
        round-trip has to survive it regardless.

        Binary is stored as a tagged base64 envelope that survives the round trip
        unambiguously.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [byte[]]) {
        return [ordered]@{
            '__type' = 'binary'
            'base64' = [System.Convert]::ToBase64String($Value)
        }
    }

    if ($Value -is [string[]]) {
        return [ordered]@{
            '__type' = 'multistring'
            'items'  = @($Value)
        }
    }

    return $Value
}

function ConvertFrom-OptStorableValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Value)

    if ($null -eq $Value) { return $null }

    # After a JSON round trip this arrives as PSCustomObject, not a hashtable.
    $typeTag = $null
    if ($Value -is [System.Collections.IDictionary]) {
        if ($Value.Contains('__type')) { $typeTag = [string]$Value['__type'] }
    }
    elseif ($Value -is [System.Management.Automation.PSCustomObject]) {
        $prop = $Value.PSObject.Properties['__type']
        if ($prop) { $typeTag = [string]$prop.Value }
    }

    if (-not $typeTag) { return $Value }

    switch ($typeTag) {
        'binary' {
            $b64 = if ($Value -is [System.Collections.IDictionary]) { $Value['base64'] } else { $Value.base64 }
            return [System.Convert]::FromBase64String([string]$b64)
        }
        'multistring' {
            $items = if ($Value -is [System.Collections.IDictionary]) { $Value['items'] } else { $Value.items }
            return [string[]]@($items)
        }
        default { return $Value }
    }
}

function Add-OptChange {
    <#
        Records an applied change: appends to the JSONL journal SYNCHRONOUSLY,
        then adds to the in-memory list.

        Journal-first is deliberate. This script restarts the network adapter
        and changes display mode; a hang or BSOD mid-run is a real possibility.
        A manifest written only at the end would leave changes applied and
        unrollbackable, which is the worst failure mode available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Change
    )

    if (-not $State.DryRun -and $State.Paths -and $State.Paths.Journal) {
        try {
            $line = $Change | ConvertTo-Json -Depth 12 -Compress
            # Append-and-flush. Add-Content opens/writes/closes per call, which
            # is exactly the durability we want here.
            Add-Content -LiteralPath $State.Paths.Journal -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-OptLog -Level Warn "Could not append to change journal: $($_.Exception.Message)"
        }
    }

    [void]$State.Changes.Add($Change)

    if ($Change.RequiresReboot) { $State.RebootRequired = $true }

    return $Change
}

function Read-OptChangeJournal {
    <#
        Crash recovery: rebuild the change list from the JSONL journal when the
        consolidated manifest is missing or corrupt.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    $changes = @()
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try   { $changes += ($line | ConvertFrom-Json) }
        catch { Write-Warning "Skipping unparseable journal line: $($line.Substring(0, [Math]::Min(60, $line.Length)))" }
    }
    return $changes
}
