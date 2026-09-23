<#
    Section 2 - Power and CPU.
#>

function Invoke-OptSection02 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 2 - Power and CPU'

    Invoke-OptSection21Scheme      -State $State
    Invoke-OptSection22Values      -State $State
    Invoke-OptSection23FastStartup -State $State
    Invoke-OptSection24DevicePower -State $State
}

function Invoke-OptSection21Scheme {
    <#
        The idempotency trap in this section is real and live on the reference
        machine: Ultimate Performance ALREADY exists at the canonical GUID and is
        already active. A blind `powercfg -duplicatescheme` creates a second
        "Ultimate Performance" every single run.

        Resolution order: canonical GUID -> a GUID a prior run recorded ->
        duplicate and parse the new GUID from stdout. Name matching is the last
        resort only, because a duplicated scheme inherits a LOCALIZED name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '2.1')) {
        [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'Off' `
            -Title 'Ultimate Performance power plan' -Reason 'section gated off')
        return
    }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    $p = $State.Profile
    $ultimateTemplate = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
    $canonical        = '682abefa-2beb-44cf-ad85-84c45fd50e03'

    $targetGuid  = $null
    $createdByUs = $false

    if ($p.Power.UltimatePerformanceExists) {
        $targetGuid = $canonical
    }
    else {
        $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
             -ArgumentList @('-duplicatescheme', $ultimateTemplate) -Purpose 'create Ultimate Performance'

        if ($State.DryRun) {
            [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'Applied' `
                -Title 'Ultimate Performance power plan' -Reason 'would duplicate the Ultimate Performance scheme and activate it')
            return
        }

        if ($r.Success -and $r.StdOut -match '([0-9a-fA-F-]{36})') {
            $targetGuid  = $Matches[1].ToLowerInvariant()
            $createdByUs = $true
            $change = New-OptChangeRecord -State $State -Type 'PowerCfgScheme' -Section '2.1' -Tier 'Safe' `
                -Path 'powercfg' -Name 'UltimatePerformance' -Target @{ CreatedByUs = $true } `
                -OldValue $null -NewValue $targetGuid -ExistedBefore $false
            [void](Add-OptChange -State $State -Change $change)
        }
        else {
            [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'Failed' `
                -Title 'Ultimate Performance power plan' -Severity 'Warning' `
                -Reason "could not duplicate the scheme: $($r.StdErr.Trim())")
            return
        }
    }

    if ([string]$p.Power.ActiveSchemeGuid -eq $targetGuid) {
        [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'NoOp' `
            -Title 'Ultimate Performance power plan' `
            -Reason "already active ($targetGuid) - reused rather than duplicated")
        $State['ActiveSchemeGuid'] = $targetGuid
        return
    }

    $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/setactive', $targetGuid)
    if ($State.DryRun) {
        [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'Applied' `
            -Title 'Ultimate Performance power plan' -Reason "would activate $targetGuid")
        $State['ActiveSchemeGuid'] = $targetGuid
        return
    }

    if (-not $r.Success) {
        [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'Failed' `
            -Title 'Ultimate Performance power plan' -Severity 'Warning' -Reason $r.StdErr.Trim())
        return
    }

    $change = New-OptChangeRecord -State $State -Type 'PowerCfgActive' -Section '2.1' -Tier 'Safe' `
        -Path 'powercfg' -Name 'ActiveScheme' -Target @{ CreatedByUs = $createdByUs } `
        -OldValue $p.Power.ActiveSchemeGuid -NewValue $targetGuid
    [void](Add-OptChange -State $State -Change $change)

    [void](Add-OptDecision -State $State -Id 'S-2.1' -Section '2.1' -Decision 'Applied' `
        -Title 'Ultimate Performance power plan' -Reason "activated $targetGuid")

    $State['ActiveSchemeGuid'] = $targetGuid
}

function Invoke-OptPowerCfgSetting {
    <#
        Reads the current AC index, skips when already correct, sets otherwise.
        Several of these subgroups are hidden by default and must be unhidden
        with -ATTRIB_HIDE before they can be set.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$SubGroup,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)][string]$Title,
        [string]$Section = '2.2',
        [string]$Tier = 'Safe'
    )

    if (-not (Test-OptSectionEnabled -State $State -Section $Section)) { return }
    if (-not (Test-OptTier -State $State -Required $Tier)) { return }

    $scheme = [string]$State['ActiveSchemeGuid']
    if (-not $scheme) { $scheme = [string]$State.Profile.Power.ActiveSchemeGuid }
    if (-not $scheme) { return }

    [void](Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
        -ArgumentList @('-attributes', $SubGroup, $Setting, '-ATTRIB_HIDE') -Purpose 'unhide setting')

    $query = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
             -ArgumentList @('/query', $scheme, $SubGroup, $Setting) -ReadOnly

    $currentAc = $null
    foreach ($line in (Get-OptCommandLines -Text $query.StdOut)) {
        if ($line -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') {
            $currentAc = [Convert]::ToInt32($Matches[1], 16)
        }
    }

    if ($null -ne $currentAc -and $currentAc -eq $Value) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Setting" -Section $Section -Decision 'NoOp' `
            -Title $Title -Reason "already set to $Value")
        return
    }

    $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
         -ArgumentList @('/setacvalueindex', $scheme, $SubGroup, $Setting, [string]$Value) -Purpose $Title

    if ($State.DryRun) {
        # Record the planned change too, so the dry-run manifest is a COMPLETE
        # picture of what a real run would do rather than registry writes only.
        $planned = New-OptChangeRecord -State $State -Type 'PowerCfgSetting' -Section $Section -Tier $Tier `
            -Path "powercfg $SubGroup" -Name $Setting `
            -Target @{ Scheme = $scheme; SubGroup = $SubGroup; Setting = $Setting } `
            -OldValue $currentAc -NewValue $Value -VerifyMode 'None'
        [void]$State.Changes.Add($planned)

        [void](Add-OptDecision -State $State -Id "S-$Section-$Setting" -Section $Section -Decision 'Applied' `
            -Title $Title -Reason "would set to $Value (currently $currentAc)")
        return
    }

    if (-not $r.Success) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Setting" -Section $Section -Decision 'Failed' `
            -Title $Title -Severity 'Warning' -Reason $r.StdErr.Trim())
        return
    }

    $change = New-OptChangeRecord -State $State -Type 'PowerCfgSetting' -Section $Section -Tier $Tier `
        -Path "powercfg $SubGroup" -Name $Setting `
        -Target @{ Scheme = $scheme; SubGroup = $SubGroup; Setting = $Setting } `
        -OldValue $currentAc -NewValue $Value -VerifyMode 'None'
    [void](Add-OptChange -State $State -Change $change)

    [void](Add-OptDecision -State $State -Id "S-$Section-$Setting" -Section $Section -Decision 'Applied' `
        -Title $Title -Reason "set to $Value (was $currentAc)")
}

function Invoke-OptSection22Values {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '2.2')) {
        [void](Add-OptDecision -State $State -Id 'S-2.2' -Section '2.2' -Decision 'Off' `
            -Title 'Power scheme values' -Reason 'section gated off')
        return
    }

    # Spec 1.5.4's laptop row: "Skip 2.1 and the whole of 2.2 EXCEPT USB
    # selective suspend." So on a laptop only that one setting proceeds - the
    # throttle floors, core parking and ASPM changes are a thermal-throttling
    # trap on battery-cooled hardware. The DC-value (/setdcvalueindex) opt-in
    # path the spec mentions is deliberately not implemented; the AC-value
    # writes below apply when plugged in, which is the only state a laptop
    # should be competing in anyway.
    $isLaptop = (ConvertTo-OptBool -Value $State.Profile.Power.IsLaptop) -eq $true
    if ($isLaptop) {
        [void](Add-OptDecision -State $State -Id 'S-2.2-LAPTOP' -Section '2.2' -Decision 'Off' `
            -Title 'Processor / PCIe / disk power values' -Severity 'Warning' `
            -Reason 'laptop - skipped except USB selective suspend, per the spec laptop rule')

        Invoke-OptPowerCfgSetting -State $State -SubGroup '2a737441-1930-4402-8d77-b2bebba308a3' `
            -Setting '48e6b7a6-50f5-4782-a5d4-53bb8f07e226' -Value 0 -Title 'USB selective suspend off'
        return
    }

    Invoke-OptPowerCfgSetting -State $State -SubGroup 'SUB_PROCESSOR' -Setting 'PROCTHROTTLEMIN' -Value 100 -Title 'Minimum processor state 100%'
    Invoke-OptPowerCfgSetting -State $State -SubGroup 'SUB_PROCESSOR' -Setting 'PROCTHROTTLEMAX' -Value 100 -Title 'Maximum processor state 100%'

    # Core parking. Skipped on hybrid parts, where Thread Director manages
    # placement and overriding it forces work onto E-cores.
    if (Test-OptSectionEnabled -State $State -Section '2.2.CPMINCORES') {
        Invoke-OptPowerCfgSetting -State $State -SubGroup 'SUB_PROCESSOR' `
            -Setting '0cc5b647-c1df-4637-891a-dec35c318583' -Value 100 -Title 'Core parking minimum cores 100%'
    }

    # IDLEDISABLE is deliberately NEVER set, on any path. It is named here only
    # so it is explicit that the script does not touch it: blocking idle states
    # raises the thermal floor and REDUCES sustained boost residency on X3D
    # parts, which are cache-limited rather than clock-limited.
    [void](Add-OptDecision -State $State -Id 'S-2.2-IDLEDISABLE' -Section '2.2' -Decision 'NoOp' `
        -Title 'Processor idle disable' `
        -Reason 'left at 0 on every path by design - idle-blocking costs boost residency and helps nothing here')

    Invoke-OptPowerCfgSetting -State $State -SubGroup '2a737441-1930-4402-8d77-b2bebba308a3' `
        -Setting '48e6b7a6-50f5-4782-a5d4-53bb8f07e226' -Value 0 -Title 'USB selective suspend off'

    Invoke-OptPowerCfgSetting -State $State -SubGroup '501a4d13-42af-4429-9fd1-a8218c268e20' `
        -Setting 'ee12f906-d277-404b-b6da-e5fa1a576df5' -Value 0 -Title 'PCIe link state power management off'

    Invoke-OptPowerCfgSetting -State $State -SubGroup 'SUB_DISK'  -Setting 'DISKIDLE'  -Value 0 -Title 'Never turn off hard disk'

    # VIDEOIDLE (the display-off timeout) is deliberately LEFT ALONE. The spec
    # table says "0 (or leave to preference)", and this takes the second option:
    # the timeout only ever fires while nobody is at the PC, so forcing the
    # panel to stay on has zero in-game benefit while burning an OLED-class
    # competitive monitor at idle. A tweak with no upside and a real downside
    # does not belong in the Safe tier.
    [void](Add-OptDecision -State $State -Id 'S-2.2-VIDEOIDLE' -Section '2.2' -Decision 'NoOp' `
        -Title 'Display-off timeout' `
        -Reason 'left at your preference by design - it only fires when you are away from the PC, so changing it buys nothing in-game and would keep the panel lit at idle')

    # Commit the scheme once at the end of the block, not per setting.
    $scheme = [string]$State['ActiveSchemeGuid']
    if (-not $scheme) { $scheme = [string]$State.Profile.Power.ActiveSchemeGuid }
    if ($scheme) {
        [void](Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
            -ArgumentList @('/setactive', $scheme) -Purpose 'commit power scheme values')
    }

    if ($State.Profile.Power.SupportsModernStandby) {
        [void](Add-OptDecision -State $State -Id 'S-2.2-S0IX' -Section '2.2' -Decision 'Unverified' `
            -Title 'Legacy power timeouts on a Modern Standby platform' `
            -Reason 'this is an S0ix platform, so some of these timeouts are ignored by the platform - applied, but not claimed as effective')
    }
}

function Invoke-OptSection23FastStartup {
    <#
        Escalated from Safe to mandatory on dual-boot machines: Fast Startup
        leaves NTFS in a dirty state, so the other OS either refuses to mount the
        partition or mounts it read-only - and mounting it read-write anyway
        risks corruption.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '2.3')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    $p = $State.Profile

    if ($p.Boot.HibernationEnabled) {
        $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/hibernate', 'off') -Purpose 'disable hibernation'
        if ($State.DryRun) {
            [void](Add-OptDecision -State $State -Id 'S-2.3-HIBER' -Section '2.3' -Decision 'Applied' `
                -Title 'Hibernation' -Reason 'would disable hibernation and reclaim hiberfil.sys')
        }
        elseif ($r.Success) {
            [void](Add-OptDecision -State $State -Id 'S-2.3-HIBER' -Section '2.3' -Decision 'Applied' `
                -Title 'Hibernation' -Reason 'disabled - reclaims disk and removes the hiberfil NTFS lock')
        }
        else {
            [void](Add-OptDecision -State $State -Id 'S-2.3-HIBER' -Section '2.3' -Decision 'Failed' `
                -Title 'Hibernation' -Severity 'Warning' -Reason $r.StdErr.Trim())
        }
    }
    else {
        [void](Add-OptDecision -State $State -Id 'S-2.3-HIBER' -Section '2.3' -Decision 'NoOp' `
            -Title 'Hibernation' -Reason 'already disabled')
    }

    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' `
        -Name 'HiberbootEnabled' -Type DWord -Value 0 -Section '2.3' -Tier 'Safe' `
        -Title 'Fast Startup off' -RequiresReboot -VerifyMode PostReboot | Out-Null

    if ($p.Boot.IsDualBoot) {
        [void](Add-OptDecision -State $State -Id 'S-2.3-DUALBOOT' -Section '2.3' -Decision 'NoOp' `
            -Title 'Fast Startup on a dual-boot machine' `
            -Reason 'this is the change in section 2 that genuinely matters here - it stops Windows leaving NTFS dirty for the other OS')
    }
}

function Invoke-OptSection24DevicePower {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '2.4')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    $p = $State.Profile

    # Skip entirely on a laptop running on battery (spec 2.4).
    if ($p.Power.IsLaptop -and $p.Power.OnAcPower -eq $false) {
        [void](Add-OptDecision -State $State -Id 'S-2.4' -Section '2.4' -Decision 'Off' `
            -Title 'Device power management' -Reason 'laptop on battery - leaving device power saving alone')
        return
    }

    # NIC: clear "allow the computer to turn off this device to save power" on
    # the adapter that actually carries the default route. Read before and
    # after: the cmdlet returns success on adapters whose driver never exposes
    # the setting, and recording that as a change made every run re-apply it.
    $adapterName = [string]$p.Network.ActiveAdapterName
    if ($adapterName) {
        $before = Get-OptNicPowerState -AdapterName $adapterName
        if ($before -in @('Disabled', 'Unsupported')) {
            [void](Add-OptDecision -State $State -Id 'S-2.4-NIC' -Section '2.4' -Decision 'NoOp' `
                -Title 'NIC power management' `
                -Reason $(if ($before -eq 'Disabled') { "power saving already disabled on $adapterName" } else { "$adapterName's driver does not expose the setting - nothing to change" }))
        }
        else {
            $r = Invoke-OptCmdletChange -State $State -Description "Disable-NetAdapterPowerManagement $adapterName" -Action {
                Disable-NetAdapterPowerManagement -Name $adapterName -ErrorAction Stop -Confirm:$false
            }
            $after = $null
            if ($r.Success -and -not $State.DryRun) { $after = Get-OptNicPowerState -AdapterName $adapterName }

            $outcome = Resolve-OptDevicePowerOutcome -Before $before -After $after -Success $r.Success -DryRun $State.DryRun -ErrorText ([string]$r.Error)
            if ($outcome.Record) {
                $nicChange = New-OptChangeRecord -State $State -Type 'NetAdapterPowerMgmt' -Section '2.4' -Tier 'Safe' `
                    -Path $adapterName -Name 'AllowComputerToTurnOffDevice' `
                    -Target @{ AdapterName = $adapterName } `
                    -OldValue $(if ($before) { $before } else { 'Enabled' }) -NewValue 'Disabled' -VerifyMode 'None'
                if ($State.DryRun) { [void]$State.Changes.Add($nicChange) } else { [void](Add-OptChange -State $State -Change $nicChange) }
            }
            [void](Add-OptDecision -State $State -Id 'S-2.4-NIC' -Section '2.4' -Decision $outcome.Decision `
                -Title 'NIC power management' -Severity $outcome.Severity -Reason ($outcome.Reason -f $adapterName))
        }
    }

    # USB endpoints. The set is DERIVED from the detected profile rather than a
    # fixed list: HID pointing devices and keyboards, plus any USB audio
    # endpoint. If no USB audio device exists, that item is simply absent from
    # the run - not a failure.
    $targets = @()
    try {
        $targets = @(Get-PnpDevice -Class 'HIDClass', 'Mouse', 'Keyboard' -Status OK -ErrorAction Stop |
                     Where-Object { $_.InstanceId -like 'USB\*' })
    }
    catch { }

    # USB root hubs too (spec 2.4's second bullet): a hub that idles takes its
    # downstream mouse and keyboard with it, so clearing power saving only on
    # the endpoints leaves the failure mode in place one level up.
    try {
        $targets += @(Get-PnpDevice -Class 'USB' -Status OK -ErrorAction Stop |
                      Where-Object { $_.FriendlyName -match 'Root Hub|USB Hub' })
    }
    catch { }

    if ($p.Audio.HasUsbDac) {
        [void](Add-OptDecision -State $State -Id 'S-2.4-USBAUDIO' -Section '2.4' -Decision 'NoOp' `
            -Title 'USB audio endpoint' `
            -Reason "USB audio device detected ($($p.Audio.DefaultName)) - included in the USB power-management sweep")
    }

    $ids = @($targets | ForEach-Object { [string]$_.InstanceId } | Select-Object -Unique)
    $sweep = Invoke-OptUsbPowerSweep -State $State -InstanceIds $ids

    $changed = @($sweep.Changed).Count
    $off     = @($sweep.AlreadyOff).Count
    $refused = @($sweep.Refused).Count
    $failed  = @($sweep.Failed).Count

    if ($changed -gt 0) {
        # Recorded as a single bulk entry listing ONLY the endpoints that
        # actually changed, so the sweep is neither an unrecorded mutation nor
        # a recorded no-op. Reversible='Partial' is honest: rollback re-enables
        # power management on the endpoints still present and silently skips
        # any device that has since been unplugged.
        $usbChange = New-OptChangeRecord -State $State -Type 'UsbPowerMgmt' -Section '2.4' -Tier 'Safe' `
            -Path 'MSPower_DeviceEnable' -Name 'UsbEndpoints' `
            -Target @{ InstanceIds = @($sweep.Changed) } `
            -OldValue $true -NewValue $false -Reversible 'Partial' -VerifyMode 'None'
        if ($State.DryRun) { [void]$State.Changes.Add($usbChange) } else { [void](Add-OptChange -State $State -Change $usbChange) }
    }

    $refusedNote = if ($refused -gt 0) {
        "; $refused refused - the driver reported the setting still enabled right after the write. Composite devices (a mouse or DAC exposing several USB interfaces) commonly accept it only on the parent device; Device Manager shows the same"
    } else { '' }
    $failedNote = if ($failed -gt 0) { "; $failed failed (see log)" } else { '' }

    if ($State.DryRun) {
        [void](Add-OptDecision -State $State -Id 'S-2.4-USB' -Section '2.4' -Decision 'Applied' `
            -Title 'USB device power management' `
            -Reason "would disable power saving on $changed of $($ids.Count) USB endpoint(s); $off already off")
    }
    elseif ($changed -gt 0 -and $refused -eq 0 -and $failed -eq 0) {
        [void](Add-OptDecision -State $State -Id 'S-2.4-USB' -Section '2.4' -Decision 'Applied' `
            -Title 'USB device power management' `
            -Reason "power saving disabled on $changed USB endpoint(s); $off already off")
    }
    elseif ($changed -gt 0 -or $refused -gt 0 -or $failed -gt 0) {
        [void](Add-OptDecision -State $State -Id 'S-2.4-USB' -Section '2.4' -Decision 'Unverified' `
            -Title 'USB device power management' -Severity 'Warning' `
            -Reason "power saving disabled on $changed USB endpoint(s); $off already off$refusedNote$failedNote")
    }
    else {
        [void](Add-OptDecision -State $State -Id 'S-2.4-USB' -Section '2.4' -Decision 'NoOp' `
            -Title 'USB device power management' `
            -Reason "all $off detected USB endpoint(s) already have power saving off")
    }
}

function Get-OptNicPowerState {
    <#
        'Enabled' / 'Disabled' / 'Unsupported' as the adapter's driver reports
        it, or $null when the query itself fails.
    #>
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][string]$AdapterName)
    try {
        $pm = Get-NetAdapterPowerManagement -Name $AdapterName -ErrorAction Stop
        $v = [string]$pm.AllowComputerToTurnOffDevice
        if ($v) { return $v }
        return $null
    }
    catch { return $null }
}

function Resolve-OptDevicePowerOutcome {
    <#
        Turns a before/after read around a "disable" command into a decision.
        Pure, so the honesty rules are testable: a change is recorded only when
        the after-state confirms it (or cannot be read at all, where recording
        keeps rollback able to re-enable), never merely because the command
        returned success. '{0}' in Reason is the adapter name.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [AllowNull()][string]$Before,
        [AllowNull()][string]$After,
        [bool]$Success,
        [bool]$DryRun,
        [AllowNull()][AllowEmptyString()][string]$ErrorText
    )

    $was = if ($Before) { $Before } else { 'unknown' }
    if (-not $Success -and -not $DryRun) {
        return @{ Record = $false; Decision = 'Failed'; Severity = 'Warning'; Reason = "could not disable power saving on {0}: $ErrorText" }
    }
    if ($DryRun) {
        return @{ Record = $true; Decision = 'Applied'; Severity = 'Info'; Reason = "would disable power saving on {0} (currently $was)" }
    }
    if ($After -eq 'Disabled') {
        return @{ Record = $true; Decision = 'Applied'; Severity = 'Info'; Reason = "power saving disabled on {0} (was $was)" }
    }
    if (-not $After) {
        return @{ Record = $true; Decision = 'Unverified'; Severity = 'Warning'; Reason = "the disable command succeeded on {0} but the state could not be read back; recorded so -Rollback can re-enable it" }
    }
    return @{ Record = $false; Decision = 'Unverified'; Severity = 'Warning'; Reason = "the disable command succeeded but {0} still reports '$After' - the driver did not accept the setting; nothing recorded" }
}

function Invoke-OptUsbPowerSweep {
    <#
        Disables "allow the computer to turn off this device" on each USB
        endpoint, reading the WMI node before and after so the result says
        what actually happened: Changed (confirmed off), AlreadyOff, Refused
        (write succeeded, driver still reports enabled), Missing (no WMI node
        for that instance), Failed (the write threw).

        Matching is by prefix on the PnP instance id: MSPower_DeviceEnable
        names an endpoint as '<InstanceId>_0'. The node lookup and the write
        are injectable so the sweep is testable without hardware.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$InstanceIds,
        [scriptblock]$GetNodes = {
            param($id)
            @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop |
              Where-Object { ([string]$_.InstanceName).StartsWith($id, [StringComparison]::OrdinalIgnoreCase) })
        },
        [scriptblock]$DisableNode = {
            param($n)
            Set-CimInstance -InputObject $n -Property @{ Enable = $false } -ErrorAction Stop
        }
    )

    $result = @{
        Changed = New-Object System.Collections.ArrayList; AlreadyOff = New-Object System.Collections.ArrayList
        Refused = New-Object System.Collections.ArrayList; Missing    = New-Object System.Collections.ArrayList
        Failed  = New-Object System.Collections.ArrayList
    }

    foreach ($id in $InstanceIds) {
        $nodes = @()
        try { $nodes = @(& $GetNodes $id) } catch { $nodes = @() }
        if ($nodes.Count -eq 0) { [void]$result.Missing.Add($id); continue }

        $needs = @($nodes | Where-Object { $_.Enable })
        if ($needs.Count -eq 0) { [void]$result.AlreadyOff.Add($id); continue }

        if ($State.DryRun) { [void]$result.Changed.Add($id); continue }

        $r = Invoke-OptCmdletChange -State $State -Description "disable USB power saving for $id" -Action {
            foreach ($n in $needs) { & $DisableNode $n }
        }
        if (-not $r.Success) { [void]$result.Failed.Add($id); continue }

        $check = @()
        try { $check = @(& $GetNodes $id) } catch { $check = @() }
        if (@($check | Where-Object { $_.Enable }).Count -gt 0) { [void]$result.Refused.Add($id) }
        else { [void]$result.Changed.Add($id) }
    }

    return $result
}
