<#
    Section 7 - Network.

    Adapter selection comes FIRST, and it is not "the first adapter": machines
    routinely enumerate Hyper-V vSwitches, VPN tunnels, Tailscale, Bluetooth PAN
    and a disconnected second NIC all at once. Tuning the wrong one does nothing
    and looks exactly like the tweak failed.
#>

function Invoke-OptSection07 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 7 - Network'

    Invoke-OptSection71Nic   -State $State
    Invoke-OptSection72Tcp   -State $State
    Invoke-OptSection73Nagle -State $State
}

function Get-OptNicIntentValue {
    <#
        Resolves an intent ('Disabled'/'Enabled') to the driver's NUMERIC
        registry value by zipping ValidDisplayValues with ValidRegistryValues.

        Never set by DisplayValue: those strings are LOCALIZED. And never assume
        Disabled == 0 - verified on this Realtek driver, '*JumboPacket' has
        ValidRegistryValues 1514|4088|9014|16128 and "Disabled" maps to 1514,
        while '*PriorityVlanTag' has four values with Disabled = 0.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]$Property,
        [Parameter(Mandatory)][string]$Intent
    )

    $validDisplay  = @($Property.ValidDisplayValues)
    $validRegistry = @($Property.ValidRegistryValues)

    if ($validRegistry.Count -eq 0) {
        # An EMPTY ValidRegistryValues means a free numeric range (verified on
        # '*ReceiveBuffers'), not "nothing is valid".
        if ($Intent -match '^\d+$') { return @{ Ok = $true; Value = $Intent } }
        return @{ Ok = $false; Reason = 'free-range numeric keyword with no enum mapping' }
    }

    if ($Intent -match '^\d+$') {
        if ($validRegistry -contains $Intent) { return @{ Ok = $true; Value = $Intent } }
        return @{ Ok = $false; Reason = "value '$Intent' is not one of $($validRegistry -join '|')" }
    }

    $synonyms = switch ($Intent) {
        'Disabled' { @('disabled', 'off', 'disable', 'no') }
        'Enabled'  { @('enabled', 'on', 'enable', 'yes') }
        default    { @($Intent.ToLowerInvariant()) }
    }

    for ($i = 0; $i -lt $validDisplay.Count -and $i -lt $validRegistry.Count; $i++) {
        $display = [string]$validDisplay[$i]
        $lower = $display.ToLowerInvariant()
        foreach ($syn in $synonyms) {
            # Exact match first, then a contains-match for compound labels such
            # as "Priority & VLAN Disabled".
            if ($lower -eq $syn -or $lower -like "*$syn") {
                return @{ Ok = $true; Value = [string]$validRegistry[$i]; Display = $display }
            }
        }
    }

    # No confident mapping -> skip. Never guess (spec 1.5.3).
    return @{ Ok = $false; Reason = "could not map intent '$Intent' to any of: $($validDisplay -join '|')" }
}

function Set-OptNetAdapterProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)]$Adapter,
        [Parameter(Mandatory)][string[]]$RegistryKeyword,
        [string[]]$DisplayNamePattern,
        [Parameter(Mandatory)][string]$Intent,
        [Parameter(Mandatory)][string]$Title
    )

    $props = @($Adapter.AdvancedProperties)

    # Match on RegistryKeyword first, DisplayName second.
    $match = $null
    foreach ($kw in $RegistryKeyword) {
        $match = $props | Where-Object { [string]$_.RegistryKeyword -eq $kw } | Select-Object -First 1
        if ($match) { break }
    }
    if (-not $match -and $DisplayNamePattern) {
        foreach ($pat in $DisplayNamePattern) {
            $match = $props | Where-Object { [string]$_.DisplayName -like $pat } | Select-Object -First 1
            if ($match) { break }
        }
    }

    if (-not $match) {
        # The canonical case on this Realtek driver is '*RSS', which genuinely
        # does not exist here. Reported distinctly from section 7.2's
        # netsh-level RSS, which is a different and available setting - without
        # that distinction the report reads as "RSS is off".
        [void](Add-OptDecision -State $State -Id "S-7.1-$($RegistryKeyword[0])" -Section '7.1' -Decision 'NoOp' `
            -Title $Title -Reason "keyword not supported by this driver (tried: $($RegistryKeyword -join ', ')) - skipped, not failed")
        return
    }

    $resolved = Get-OptNicIntentValue -Property $match -Intent $Intent
    if (-not $resolved.Ok) {
        [void](Add-OptDecision -State $State -Id "S-7.1-$($match.RegistryKeyword)" -Section '7.1' -Decision 'NoOp' `
            -Title $Title -Reason $resolved.Reason)
        return
    }

    $current = [string]$match.RegistryValue
    if ($current -eq [string]$resolved.Value) {
        [void](Add-OptDecision -State $State -Id "S-7.1-$($match.RegistryKeyword)" -Section '7.1' -Decision 'NoOp' `
            -Title $Title -Reason "already $($match.DisplayValue)")
        return
    }

    $adapterName = [string]$Adapter.Name
    $keyword     = [string]$match.RegistryKeyword
    $newValue    = [string]$resolved.Value

    # -NoRestart on every property; ONE Restart-NetAdapter after the whole block.
    # Without that you get roughly ten link flaps, each a few seconds of no
    # network - which kills in-flight Add-MpPreference calls and the Steam session.
    $r = Invoke-OptCmdletChange -State $State -Description "set $adapterName $keyword = $newValue" -Action {
        Set-NetAdapterAdvancedProperty -Name $adapterName -RegistryKeyword $keyword `
            -RegistryValue $newValue -NoRestart -ErrorAction Stop
    }

    if (-not $r.Success -and -not $r.DryRun) {
        [void](Add-OptDecision -State $State -Id "S-7.1-$keyword" -Section '7.1' -Decision 'Failed' `
            -Title $Title -Severity 'Warning' -Reason $r.Error)
        return
    }

    $change = New-OptChangeRecord -State $State -Type 'NetAdapterProperty' -Section '7.1' -Tier 'Aggressive' `
        -Path $adapterName -Name $keyword `
        -Target @{ AdapterName = $adapterName; Keyword = $keyword } `
        -OldValue $current -NewValue $newValue
    if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

    $State['NicChanged'] = $true

    [void](Add-OptDecision -State $State -Id "S-7.1-$keyword" -Section '7.1' -Decision 'Applied' `
        -Title $Title -Reason "$($match.DisplayName): $($match.DisplayValue) -> $($resolved.Display) [$current -> $newValue]")
}

function Invoke-OptSection71Nic {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '7.1')) {
        [void](Add-OptDecision -State $State -Id 'S-7.1' -Section '7.1' -Decision 'Off' `
            -Title 'NIC advanced properties' -Reason 'section gated off')
        return
    }
    if (-not (Test-OptTier -State $State -Required 'Aggressive')) { return }

    $p = $State.Profile
    $adapter = $p.Network.Adapters | Where-Object { $_.Name -eq $p.Network.ActiveAdapterName } | Select-Object -First 1
    if (-not $adapter) { return }

    Write-OptLog -Level Info "Tuning $($adapter.Description) ($($adapter.Name)) - the adapter carrying the default route"

    foreach ($skipped in @($p.Network.Adapters | Where-Object { $_.Name -ne $adapter.Name -and $_.IsActive })) {
        [void](Add-OptDecision -State $State -Id "S-7.1-SKIP-$($skipped.Name)" -Section '7.1' -Decision 'NoOp' `
            -Title "Adapter $($skipped.Name)" `
            -Reason "not tuned - $(if ($skipped.IsVirtual) { 'virtual adapter' } else { 'does not carry the default route' })")
    }

    $targets = @(
        @{ K = @('*InterruptModeration'); D = @('Interrupt Moderation', 'Interrupt Throttle Rate'); I = 'Disabled'; T = 'Interrupt moderation off' }
        @{ K = @('*EEE');                 D = @('Energy-Efficient Ethernet');                       I = 'Disabled'; T = 'Energy-Efficient Ethernet off' }
        @{ K = @('AdvancedEEE');          D = @('Advanced EEE');                                    I = 'Disabled'; T = 'Advanced EEE off' }
        @{ K = @('EnableGreenEthernet');  D = @('Green Ethernet');                                  I = 'Disabled'; T = 'Green Ethernet off' }
        @{ K = @('PowerSavingMode');      D = @('Power Saving Mode');                               I = 'Disabled'; T = 'Power saving mode off' }
        @{ K = @('GigaLite');             D = @('Gigabit Lite');                                    I = 'Disabled'; T = 'Gigabit Lite off' }
        @{ K = @('*FlowControl');         D = @('Flow Control');                                    I = 'Disabled'; T = 'Flow control off' }
        @{ K = @('*RSS');                 D = @('Receive Side Scaling');                            I = 'Enabled';  T = 'Receive Side Scaling on' }
        @{ K = @('*LsoV2IPv4');           D = @('Large Send Offload v2 (IPv4)');                    I = 'Disabled'; T = 'LSO v2 IPv4 off' }
        @{ K = @('*LsoV2IPv6');           D = @('Large Send Offload v2 (IPv6)');                    I = 'Disabled'; T = 'LSO v2 IPv6 off' }
        @{ K = @('*JumboPacket');         D = @('Jumbo Frame', 'Jumbo Packet');                     I = 'Disabled'; T = 'Jumbo frames off' }
        @{ K = @('*PriorityVlanTag');     D = @('Priority & VLAN');                                 I = 'Disabled'; T = 'Priority and VLAN tagging off' }
    )

    foreach ($t in $targets) {
        Set-OptNetAdapterProperty -State $State -Adapter $adapter `
            -RegistryKeyword $t.K -DisplayNamePattern $t.D -Intent $t.I -Title $t.T
    }

    # One restart for the whole block, and only if something changed.
    if ($State['NicChanged'] -and -not $State.DryRun) {
        if ($env:SESSIONNAME -like 'RDP-*') {
            [void](Add-OptDecision -State $State -Id 'S-7.1-RESTART' -Section '7.1' -Decision 'NoOp' `
                -Title 'Adapter restart' -Severity 'Warning' `
                -Reason 'remote session detected - adapter NOT restarted. The changes take effect at next boot or manual restart.')
            $State.RebootRequired = $true
        }
        elseif ($State.Parameters['AllowNetworkRestart']) {
            $r = Invoke-OptCmdletChange -State $State -Description "restart adapter $($adapter.Name)" -Action {
                Restart-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            }
            [void](Add-OptDecision -State $State -Id 'S-7.1-RESTART' -Section '7.1' `
                -Decision $(if ($r.Success) { 'Applied' } else { 'Failed' }) -Title 'Adapter restart' `
                -Reason $(if ($r.Success) { 'adapter restarted once for the whole block (expect a brief link bounce)' } else { [string]$r.Error }))
        }
        else {
            [void](Add-OptDecision -State $State -Id 'S-7.1-RESTART' -Section '7.1' -Decision 'NoOp' `
                -Title 'Adapter restart' `
                -Reason 'NIC properties changed but the adapter was not restarted - re-run with -AllowNetworkRestart, or simply reboot. Changes are inert until then.')
            $State.RebootRequired = $true
        }
    }

    # Report-only observation with real value on this machine: a 2.5GbE NIC
    # linking at 1 Gbps is usually Green Ethernet / Gigabit Lite / EEE, which is
    # exactly what this block just turned off.
    if ($adapter.Description -match '2\.5|5G|10G' -and $adapter.LinkSpeed -match '^1 Gbps') {
        [void](Add-OptDecision -State $State -Id 'S-7.1-LINKSPEED' -Section '7.1' -Decision 'Finding' `
            -Title 'Link speed below adapter capability' -Severity 'Warning' `
            -Reason "adapter reports $($adapter.LinkSpeed) but the hardware is multi-gigabit. Green Ethernet / Gigabit Lite / EEE are the usual cause and were just disabled - re-check the link speed after the adapter restart or reboot. If it stays at 1 Gbps, it is the cable or the switch.")
    }
}

function Invoke-OptSection72Tcp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '7.2')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    $show = Invoke-OptNativeCommand -State $State -FilePath 'netsh.exe' -ArgumentList @('int', 'tcp', 'show', 'global') -ReadOnly
    $lines = Get-OptCommandLines -Text $show.StdOut

    $currentOf = {
        param($label)
        foreach ($line in $lines) {
            if ($line -match "^\s*$label\s*:\s*(\S+)") { return $Matches[1] }
        }
        return $null
    }

    $settings = @(
        # autotuninglevel=normal is DELIBERATE. Many optimization scripts set it
        # to 'disabled', which is a genuine throughput regression - if this run
        # finds it disabled, the correct action is to FIX it.
        @{ Name = 'autotuninglevel'; Value = 'normal';   Label = 'Receive Window Auto-Tuning Level'; Title = 'TCP auto-tuning back to normal' }
        @{ Name = 'ecncapability';   Value = 'disabled'; Label = 'ECN Capability';                   Title = 'ECN capability off' }
        @{ Name = 'rss';             Value = 'enabled';  Label = 'Receive-Side Scaling State';       Title = 'TCP Receive-Side Scaling on' }
        @{ Name = 'timestamps';      Value = 'disabled'; Label = 'RFC 1323 Timestamps';              Title = 'TCP timestamps off' }
    )

    foreach ($s in $settings) {
        $current = & $currentOf $s.Label
        if ($current -and $current -eq $s.Value) {
            [void](Add-OptDecision -State $State -Id "S-7.2-$($s.Name)" -Section '7.2' -Decision 'NoOp' `
                -Title $s.Title -Reason "already $($s.Value)")
            continue
        }

        $r = Invoke-OptNativeCommand -State $State -FilePath 'netsh.exe' `
             -ArgumentList @('int', 'tcp', 'set', 'global', "$($s.Name)=$($s.Value)") -Purpose $s.Title

        if ($State.DryRun) {
            $planned = New-OptChangeRecord -State $State -Type 'NetshTcpGlobal' -Section '7.2' -Tier 'Safe' `
                -Path 'netsh int tcp' -Name $s.Name -Target @{ Setting = $s.Name } `
                -OldValue $current -NewValue $s.Value -VerifyMode 'None'
            [void]$State.Changes.Add($planned)

            [void](Add-OptDecision -State $State -Id "S-7.2-$($s.Name)" -Section '7.2' -Decision 'Applied' `
                -Title $s.Title -Reason "would set to $($s.Value) (currently $current)")
            continue
        }
        if (-not $r.Success) {
            [void](Add-OptDecision -State $State -Id "S-7.2-$($s.Name)" -Section '7.2' -Decision 'Failed' `
                -Title $s.Title -Severity 'Warning' -Reason $r.StdErr.Trim())
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'NetshTcpGlobal' -Section '7.2' -Tier 'Safe' `
            -Path 'netsh int tcp' -Name $s.Name -Target @{ Setting = $s.Name } `
            -OldValue $current -NewValue $s.Value -VerifyMode 'None'
        [void](Add-OptChange -State $State -Change $change)

        $note = if ($s.Name -eq 'autotuninglevel' -and $current -eq 'disabled') {
            ' - this was DISABLED, which is a real throughput regression commonly introduced by other optimization scripts'
        } else { '' }

        [void](Add-OptDecision -State $State -Id "S-7.2-$($s.Name)" -Section '7.2' -Decision 'Applied' `
            -Title $s.Title -Reason "set to $($s.Value) (was $current)$note")
    }
}

function Invoke-OptSection73Nagle {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '7.3')) { return }
    if (-not (Test-OptTier -State $State -Required 'Experimental')) {
        [void](Add-OptDecision -State $State -Id 'S-7.3' -Section '7.3' -Decision 'Off' `
            -Title 'Nagle disable' -Reason 'requires tier Experimental')
        return
    }

    $p = $State.Profile
    $adapter = $p.Network.Adapters | Where-Object { $_.Name -eq $p.Network.ActiveAdapterName } | Select-Object -First 1
    if (-not $adapter) { return }

    # Resolve the specific interface GUID - do NOT blanket-apply to every
    # interface under Tcpip\Parameters\Interfaces.
    $guid = $null
    try {
        $nic = Get-NetAdapter -Name $adapter.Name -ErrorAction Stop
        $guid = [string]$nic.InterfaceGuid
    }
    catch { }

    if (-not $guid) {
        [void](Add-OptDecision -State $State -Id 'S-7.3' -Section '7.3' -Decision 'Off' `
            -Title 'Nagle disable' -Reason 'could not resolve the interface GUID for the active adapter')
        return
    }

    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
    Set-OptRegistryValue -State $State -Path $key -Name 'TcpAckFrequency' -Type DWord -Value 1 `
        -Section '7.3' -Tier 'Experimental' -Title 'TcpAckFrequency' -RequiresReboot -VerifyMode PostReboot | Out-Null
    Set-OptRegistryValue -State $State -Path $key -Name 'TCPNoDelay' -Type DWord -Value 1 `
        -Section '7.3' -Tier 'Experimental' -Title 'TCPNoDelay' -RequiresReboot -VerifyMode PostReboot | Out-Null

    [void](Add-OptDecision -State $State -Id 'S-7.3-NOTE' -Section '7.3' -Decision 'NoOp' `
        -Title 'Nagle expectations' `
        -Reason "CS2's game traffic is UDP and Nagle affects TCP only. This influences the Steam client and matchmaking sockets, not in-game netcode. Included because it is harmless and on every list - do not expect a tick-rate improvement.")
}
