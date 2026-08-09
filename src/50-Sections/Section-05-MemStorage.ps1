<#
    Section 5 - Memory and storage.
#>

function Invoke-OptSection05 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 5 - Memory and storage'

    Invoke-OptSection51Pagefile   -State $State
    Invoke-OptSection52Filesystem -State $State
    Invoke-OptSection53Indexing   -State $State
    Invoke-OptSection54MMAgent    -State $State
    Invoke-OptSection55SysMain    -State $State
}

function Invoke-OptSection51Pagefile {
    <#
        Fixed-size pagefile, min = max, so there are no mid-match resize stalls.
        NEVER disabled: CS2 and the FACEIT client both benefit from committed
        backing store, and disabling it kills crash dumps.

        DEVIATION FROM SPEC 5.1, deliberate: the spec prefers "the fastest
        non-boot fixed drive", but a pagefile off the boot volume BREAKS KERNEL
        CRASH DUMPS, which require a pagefile on the boot volume sized at least
        as large as the dump. On the reference machine it is moot anyway - C: is
        the only lettered volume - but the rule is wrong in general, so the
        pagefile stays on the boot volume unless the user asks otherwise.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '5.1')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    $p = $State.Profile
    $totalMb = [int]$p.Memory.TotalMB
    if ($totalMb -le 0) {
        [void](Add-OptDecision -State $State -Id 'S-5.1' -Section '5.1' -Decision 'Off' `
            -Title 'Pagefile' -Reason 'installed memory could not be determined - skipping rather than guessing a size')
        return
    }

    $sizeMb = if ($totalMb -le 8192)      { [int]($totalMb * 1.5) }
              elseif ($totalMb -le 16384) { 8192 }
              else                        { 16384 }

    $bootFreeGb = [int]$p.Storage.BootFreeGB
    if ($bootFreeGb -gt 0 -and $bootFreeGb -lt 20) {
        [void](Add-OptDecision -State $State -Id 'S-5.1' -Section '5.1' -Decision 'Off' `
            -Title 'Pagefile' -Severity 'Warning' `
            -Reason "only ${bootFreeGb} GB free on the boot volume - not reconfiguring the pagefile")
        return
    }

    $drive = $env:SystemDrive
    $desired = "$drive\pagefile.sys $sizeMb $sizeMb"

    # PagingFiles (REG_MULTI_SZ) is the authoritative mechanism. Win32_PageFileSetting
    # cannot create instances while AutomaticManagedPagefile is $true, and
    # Set-CimInstance silently no-ops in some states.
    $cs = Get-OptCimSafe -ClassName Win32_ComputerSystem | Select-Object -First 1
    if ($cs -and $cs.AutomaticManagedPagefile) {
        $r = Invoke-OptCmdletChange -State $State -Description 'disable AutomaticManagedPagefile' -Action {
            $inst = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            Set-CimInstance -InputObject $inst -Property @{ AutomaticManagedPagefile = $false } -ErrorAction Stop
        }
        if (-not $r.Success -and -not $r.DryRun) {
            [void](Add-OptDecision -State $State -Id 'S-5.1-AUTO' -Section '5.1' -Decision 'Failed' `
                -Title 'System-managed pagefile' -Severity 'Warning' -Reason $r.Error)
            return
        }
        $autoChange = New-OptChangeRecord -State $State -Type 'AutomaticPagefile' -Section '5.1' -Tier 'Safe' `
            -Path 'Win32_ComputerSystem' -Name 'AutomaticManagedPagefile' -Target @{ Property = 'AutomaticManagedPagefile' } `
            -OldValue $true -NewValue $false -RequiresReboot -VerifyMode 'PostReboot'
        if ($State.DryRun) { [void]$State.Changes.Add($autoChange) } else { [void](Add-OptChange -State $State -Change $autoChange) }

        [void](Add-OptDecision -State $State -Id 'S-5.1-AUTO' -Section '5.1' -Decision 'Applied' `
            -Title 'System-managed pagefile' -Reason 'turned off so a fixed size can be set')
    }

    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Name 'PagingFiles' -Type MultiString -Value @($desired) -Section '5.1' -Tier 'Safe' `
        -Title "Fixed pagefile ${sizeMb} MB on $drive" -RequiresReboot -VerifyMode PostReboot | Out-Null

    [void](Add-OptDecision -State $State -Id 'S-5.1-NOTE' -Section '5.1' -Decision 'NoOp' `
        -Title 'Pagefile placement' `
        -Reason 'kept on the boot volume on purpose - kernel crash dumps require it there, which is why this deviates from the spec preference for a non-boot drive')
}

function Invoke-OptSection52Filesystem {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '5.2')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    # 8.3 name creation is deliberately NOT done through fsutil. The spec spells
    # it 'disable8dot3name', but on current builds the behavior-query option is
    # named 'disable8dot3' - the spec's spelling makes the tool print its usage
    # text, so the query parsed nothing, the already-correct check could never
    # pass, and the setting re-planned on every run without ever applying.
    # Verified live: the registry value was still at its default of 2 after a
    # real run. Writing the underlying value directly gets typed comparison,
    # manifest, rollback and verification from the registry engine for free.
    # (1 = disable 8.3 names on all volumes.)
    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' `
        -Name 'NtfsDisable8dot3NameCreation' -Type DWord -Value 1 -Section '5.2' -Tier 'Safe' `
        -Title 'Disable 8.3 name creation' | Out-Null

    # These two query cleanly through fsutil, so they stay on it.
    $settings = @(
        @{ Name = 'disablelastaccess';   Value = 1; Title = 'Disable last-access timestamps' }
        @{ Name = 'DisableDeleteNotify'; Value = 0; Title = 'Ensure TRIM is enabled' }
    )

    foreach ($s in $settings) {
        $q = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
             -ArgumentList @('behavior', 'query', $s.Name) -ReadOnly

        $current = $null
        foreach ($line in (Get-OptCommandLines -Text $q.StdOut)) {
            # Accept both output shapes: "DisableLastAccess = 1 (...)" and
            # "The registry state is: 2 (...)".
            if ($line -match '[=:]\s*(\d+)') { $current = [int]$Matches[1]; break }
        }

        if ($null -ne $current -and $current -eq $s.Value) {
            [void](Add-OptDecision -State $State -Id "S-5.2-$($s.Name)" -Section '5.2' -Decision 'NoOp' `
                -Title $s.Title -Reason "already $($s.Value)")
            continue
        }

        $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
             -ArgumentList @('behavior', 'set', $s.Name, [string]$s.Value) -Purpose $s.Title

        if ($State.DryRun) {
            $planned = New-OptChangeRecord -State $State -Type 'FsutilBehavior' -Section '5.2' -Tier 'Safe' `
                -Path 'fsutil behavior' -Name $s.Name -Target @{ Setting = $s.Name } `
                -OldValue $current -NewValue $s.Value -RequiresReboot
            [void]$State.Changes.Add($planned)

            [void](Add-OptDecision -State $State -Id "S-5.2-$($s.Name)" -Section '5.2' -Decision 'Applied' `
                -Title $s.Title -Reason "would set to $($s.Value) (currently $current)")
            continue
        }
        if (-not $r.Success) {
            [void](Add-OptDecision -State $State -Id "S-5.2-$($s.Name)" -Section '5.2' -Decision 'Failed' `
                -Title $s.Title -Severity 'Warning' -Reason $r.StdErr.Trim())
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'FsutilBehavior' -Section '5.2' -Tier 'Safe' `
            -Path 'fsutil behavior' -Name $s.Name -Target @{ Setting = $s.Name } `
            -OldValue $current -NewValue $s.Value -RequiresReboot
        [void](Add-OptChange -State $State -Change $change)

        [void](Add-OptDecision -State $State -Id "S-5.2-$($s.Name)" -Section '5.2' -Decision 'Applied' `
            -Title $s.Title -Reason "set to $($s.Value) (was $current)")
    }

    if ($State.Profile.Storage.HasHdd) {
        [void](Add-OptDecision -State $State -Id 'S-5.2-HDD' -Section '5.2' -Decision 'NoOp' `
            -Title 'Last-access timestamps on HDD' `
            -Reason 'a spinning disk is present - the disablelastaccess benefit claim applies to it, but moving the CS2 library to SSD matters far more')
    }
}

function Invoke-OptSection53Indexing {
    <#
        Excludes the Steam libraries from Windows Search.

        Deliberately does NOT disable the WSearch service: Start menu search
        degrades badly and it is not a measurable in-game cost.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '5.3')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    $libs = @($State.Profile.Games.LibraryPaths)
    if ($libs.Count -eq 0) { return }

    # The indexer's scope rules live under this key as URL-shaped rules.
    $rulesKey = 'HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\WorkingSetRules'

    $i = 0
    foreach ($lib in $libs) {
        $url = "file:///$($lib -replace '\\','/')"
        $sub = "$rulesKey\CS2Opt$i"

        Set-OptRegistryValue -State $State -Path $sub -Name 'URL' -Type String -Value $url `
            -Section '5.3' -Tier 'Safe' -Title "Search exclusion rule for $lib" | Out-Null
        Set-OptRegistryValue -State $State -Path $sub -Name 'Include' -Type DWord -Value 0 `
            -Section '5.3' -Tier 'Safe' -Title "Search exclusion (exclude) for $lib" | Out-Null
        $i++
    }

    [void](Add-OptDecision -State $State -Id 'S-5.3-WSEARCH' -Section '5.3' -Decision 'NoOp' `
        -Title 'WSearch service' `
        -Reason 'left running by design - disabling it wrecks Start menu search for no measurable in-game gain')

    [void](Add-OptDecision -State $State -Id 'S-5.3-TIMING' -Section '5.3' -Decision 'NoOp' `
        -Title 'Indexer exclusion timing' `
        -Reason 'the crawl-scope rules are read when WSearch next restarts (or at reboot) - the service is deliberately not bounced mid-run, and already-indexed files age out rather than being purged instantly')
}

function Set-OptMMAgentField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Field,
        [Parameter(Mandatory)][bool]$Enable,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Title
    )

    if (-not (Test-OptSectionEnabled -State $State -Section $Section)) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Field" -Section $Section -Decision 'Off' `
            -Title $Title -Reason 'section gated off')
        return
    }
    if (-not (Test-OptTier -State $State -Required 'Experimental')) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Field" -Section $Section -Decision 'Off' `
            -Title $Title -Reason 'requires tier Experimental')
        return
    }

    $mm = $State.Profile.Memory.MMAgent
    if (-not $mm.Available) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Field" -Section $Section -Decision 'Off' `
            -Title $Title -Severity 'Warning' -Reason 'Get-MMAgent unavailable')
        return
    }

    $current = [bool]$mm.$Field

    # Record the ACTUAL pre-state. On the reference machine both fields are
    # already False, so a rollback that assumed Windows defaults would ENABLE
    # them - a state the user has never been in.
    if ($current -eq $Enable) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Field" -Section $Section -Decision 'NoOp' `
            -Title $Title -Reason "already $Enable - nothing to change, and nothing recorded for rollback")
        return
    }

    $r = Invoke-OptCmdletChange -State $State -Description "$(if ($Enable) { 'Enable' } else { 'Disable' })-MMAgent -$Field" -Action {
        if ($Enable) { Enable-MMAgent  -$Field -ErrorAction Stop }
        else         { Disable-MMAgent -$Field -ErrorAction Stop }
    }

    if (-not $r.Success -and -not $r.DryRun) {
        [void](Add-OptDecision -State $State -Id "S-$Section-$Field" -Section $Section -Decision 'Failed' `
            -Title $Title -Severity 'Warning' -Reason $r.Error)
        return
    }

    $change = New-OptChangeRecord -State $State -Type 'MMAgent' -Section $Section -Tier 'Experimental' `
        -Path 'MMAgent' -Name $Field -Target @{ Field = $Field } `
        -OldValue $current -NewValue $Enable -RequiresReboot -VerifyMode 'PostReboot'
    if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

    [void](Add-OptDecision -State $State -Id "S-$Section-$Field" -Section $Section -Decision 'Applied' `
        -Title $Title -Reason "set to $Enable (was $current) - reboot required before this is genuinely in effect")
}

function Invoke-OptSection54MMAgent {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Set-OptMMAgentField -State $State -Field 'MemoryCompression' -Enable $false -Section '5.4.1' `
        -Title 'Memory compression disable'
    Set-OptMMAgentField -State $State -Field 'PageCombining' -Enable $false -Section '5.4.2' `
        -Title 'Page combining disable'

    # Honest expectation setting, verbatim from spec 5.4.3.
    if (Test-OptTier -State $State -Required 'Experimental') {
        [void](Add-OptDecision -State $State -Id 'S-5.4-EXPECT' -Section '5.4' -Decision 'NoOp' `
            -Title 'MMAgent expectations' `
            -Reason 'neither of these will move average fps. Page combining disable MAY remove a source of intermittent frame-time spikes on a memory-rich system - that is a 1%/0.1% low story needing a long capture, not an average-fps story. If the before/after shows nothing, that is the expected result, not a failed application.')
    }

    # ApplicationLaunchPrefetching / ApplicationPreLaunch / OperationAPI are
    # deliberately LEFT ALONE (spec 5.4): prefetch is handled in one place
    # (section 5.5), and the OperationAPI fields have no measured gaming effect.
}

function Invoke-OptSection55SysMain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '5.5')) {
        [void](Add-OptDecision -State $State -Id 'S-5.5' -Section '5.5' -Decision 'Off' `
            -Title 'SysMain disable' -Reason 'section gated off')
        return
    }
    if (-not (Test-OptTier -State $State -Required 'Experimental')) {
        [void](Add-OptDecision -State $State -Id 'S-5.5' -Section '5.5' -Decision 'Off' `
            -Title 'SysMain disable' -Reason 'requires tier Experimental')
        return
    }

    $svc = Get-Service -Name 'SysMain' -ErrorAction SilentlyContinue
    if (-not $svc) {
        [void](Add-OptDecision -State $State -Id 'S-5.5' -Section '5.5' -Decision 'NoOp' `
            -Title 'SysMain disable' -Reason 'service not present')
        return
    }

    if ([string]$svc.StartType -eq 'Disabled') {
        [void](Add-OptDecision -State $State -Id 'S-5.5' -Section '5.5' -Decision 'NoOp' `
            -Title 'SysMain disable' -Reason 'already disabled')
        return
    }

    # Capture DelayedAutostart separately: Set-Service alone cannot restore
    # "Automatic (Delayed Start)", which is what SysMain normally runs as, so a
    # rollback would silently downgrade it to plain Automatic.
    $delayed = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Services\SysMain' -Name 'DelayedAutostart'
    $oldStart = [string]$svc.StartType

    $r = Invoke-OptCmdletChange -State $State -Description 'disable SysMain' -Action {
        Set-Service -Name 'SysMain' -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name 'SysMain' -Force -ErrorAction SilentlyContinue
    }

    if (-not $r.Success -and -not $r.DryRun) {
        [void](Add-OptDecision -State $State -Id 'S-5.5' -Section '5.5' -Decision 'Failed' `
            -Title 'SysMain disable' -Severity 'Warning' -Reason $r.Error)
        return
    }

    $change = New-OptChangeRecord -State $State -Type 'Service' -Section '5.5' -Tier 'Experimental' `
        -Path 'services' -Name 'SysMain' `
        -Target @{ ServiceName = 'SysMain'; DelayedAutoStart = [bool]$delayed } `
        -OldValue $oldStart -NewValue 'Disabled'
    if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

    [void](Add-OptDecision -State $State -Id 'S-5.5' -Section '5.5' -Decision 'Applied' `
        -Title 'SysMain disable' -Reason "disabled (was $oldStart$(if ($delayed) { ', delayed start' }))")
}
