<#
    Section 8 - Background load, telemetry, scheduled tasks, shell surfaces.

    Honest framing for the report: telemetry and inbox apps cost disk, RAM and
    boot time - NOT frame rate. Nothing in this section should be presented as
    an fps win.
#>

function Invoke-OptSection08 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 8 - Background load and telemetry'

    Invoke-OptSection81Tasks       -State $State
    Invoke-OptSection82Background  -State $State
    Invoke-OptSection83VisualFx    -State $State
    Invoke-OptSection84Startup     -State $State
    Invoke-OptSection85Ai          -State $State
    Invoke-OptSection86Telemetry   -State $State
    Invoke-OptSection87Shell       -State $State
    Invoke-OptSection88Apps        -State $State
    Invoke-OptSection89OneDrive    -State $State
}

function Disable-OptScheduledTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$TaskPath,
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Tier
    )

    # Hardcoded deny-list, enforced HERE and independent of the caller's list.
    # Belt and braces: disabling any of these breaks servicing that anti-cheat
    # depends on, or stops TRIM/defragmentation outright.
    $forbidden = @(
        '\Microsoft\Windows\UpdateOrchestrator\'
        '\Microsoft\Windows\WindowsUpdate\'
        '\Microsoft\Windows\Windows Defender\'
        '\Microsoft\Windows\Defrag\'
    )
    foreach ($f in $forbidden) {
        if ($TaskPath -like "$f*") {
            [void](Add-OptDecision -State $State -Id "S-$Section-$TaskName" -Section $Section -Decision 'Off' `
                -Title "Scheduled task $TaskName" -Severity 'Warning' `
                -Reason 'refused - this task path is on the hardcoded keep-list (servicing / TRIM / Defender)')
            return
        }
    }

    if (-not (Test-OptSectionEnabled -State $State -Section $Section)) { return }
    if (-not (Test-OptTier -State $State -Required $Tier)) { return }

    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        # Several tasks in the spec's list (MareBackup, Retail Demo) simply do
        # not exist on current builds. "Not present" is distinct from
        # "we disabled it" and must not be reported as a win.
        [void](Add-OptDecision -State $State -Id "S-$Section-$TaskName" -Section $Section -Decision 'NoOp' `
            -Title "Scheduled task $TaskName" -Reason 'not present on this build')
        return
    }

    if ([string]$task.State -eq 'Disabled') {
        [void](Add-OptDecision -State $State -Id "S-$Section-$TaskName" -Section $Section -Decision 'NoOp' `
            -Title "Scheduled task $TaskName" -Reason 'already disabled')
        return
    }

    $oldState = [string]$task.State
    $r = Invoke-OptCmdletChange -State $State -Description "disable task $TaskPath$TaskName" -Action {
        Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
    }

    if (-not $r.Success -and -not $r.DryRun) {
        # Some tasks are SYSTEM-ACL'd and throw Access Denied even elevated.
        [void](Add-OptDecision -State $State -Id "S-$Section-$TaskName" -Section $Section -Decision 'Failed' `
            -Title "Scheduled task $TaskName" -Severity 'Warning' -Reason $r.Error)
        return
    }

    $change = New-OptChangeRecord -State $State -Type 'ScheduledTask' -Section $Section -Tier $Tier `
        -Path $TaskPath -Name $TaskName `
        -Target @{ TaskPath = $TaskPath; TaskName = $TaskName } `
        -OldValue $oldState -NewValue 'Disabled'
    if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

    [void](Add-OptDecision -State $State -Id "S-$Section-$TaskName" -Section $Section -Decision 'Applied' `
        -Title "Scheduled task $TaskName" -Reason "disabled (was $oldState)")
}

function Invoke-OptSection81Tasks {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Disabled, never deleted: deletion breaks rollback and servicing recreates
    # them anyway.
    $tasks = @(
        @{ P = '\Microsoft\Windows\Application Experience\'; N = 'Microsoft Compatibility Appraiser' }
        @{ P = '\Microsoft\Windows\Application Experience\'; N = 'ProgramDataUpdater' }
        @{ P = '\Microsoft\Windows\Application Experience\'; N = 'StartupAppTask' }
        @{ P = '\Microsoft\Windows\Application Experience\'; N = 'PcaPatchDbTask' }
        @{ P = '\Microsoft\Windows\Application Experience\'; N = 'MareBackup' }
        @{ P = '\Microsoft\Windows\Customer Experience Improvement Program\'; N = 'Consolidator' }
        @{ P = '\Microsoft\Windows\Customer Experience Improvement Program\'; N = 'UsbCeip' }
        @{ P = '\Microsoft\Windows\Customer Experience Improvement Program\'; N = 'Uploader' }
        @{ P = '\Microsoft\Windows\Autochk\'; N = 'Proxy' }
        @{ P = '\Microsoft\Windows\DiskDiagnostic\'; N = 'Microsoft-Windows-DiskDiagnosticDataCollector' }
        @{ P = '\Microsoft\Windows\Feedback\Siuf\'; N = 'DmClient' }
        @{ P = '\Microsoft\Windows\Feedback\Siuf\'; N = 'DmClientOnScenarioDownload' }
        @{ P = '\Microsoft\Windows\Windows Error Reporting\'; N = 'QueueReporting' }
        @{ P = '\Microsoft\Windows\Maps\'; N = 'MapsToastTask' }
        @{ P = '\Microsoft\Windows\Maps\'; N = 'MapsUpdateTask' }
        @{ P = '\Microsoft\Windows\Retail Demo\'; N = 'CleanupOfflineContent' }
        @{ P = '\Microsoft\Windows\CloudExperienceHost\'; N = 'CreateObjectTask' }
        @{ P = '\Microsoft\Windows\Shell\'; N = 'FamilySafetyMonitor' }
        @{ P = '\Microsoft\Windows\Shell\'; N = 'FamilySafetyRefreshTask' }
        @{ P = '\Microsoft\Windows\Power Efficiency Diagnostics\'; N = 'AnalyzeSystem' }
        @{ P = '\Microsoft\Windows\Registry\'; N = 'RegIdleBackup' }
        @{ P = '\Microsoft\Windows\Windows Media Sharing\'; N = 'UpdateLibrary' }
    )

    foreach ($t in $tasks) {
        Disable-OptScheduledTask -State $State -TaskPath $t.P -TaskName $t.N -Section '8.1' -Tier 'Aggressive'
    }

    [void](Add-OptDecision -State $State -Id 'S-8.1-KEEP' -Section '8.1' -Decision 'NoOp' `
        -Title 'Tasks deliberately left enabled' `
        -Reason 'ScheduledDefrag (issues TRIM on SSD, real defragmentation on HDD), everything under UpdateOrchestrator (driver/servicing delivery that FACEIT AC depends on), and all Windows Defender tasks')
}

function Invoke-OptSection82Background {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' `
        -Name 'GlobalUserDisabled' -Type DWord -Value 1 -Section '8.2' -Tier 'Aggressive' `
        -Title 'Background apps off' | Out-Null

    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' `
        -Name 'LetAppsRunInBackground' -Type DWord -Value 2 -Section '8.2' -Tier 'Aggressive' `
        -Title 'Background apps policy' | Out-Null

    foreach ($n in @('SilentInstalledAppsEnabled', 'SubscribedContent-338388Enabled',
                     'SubscribedContent-338389Enabled', 'SubscribedContent-353698Enabled',
                     'SystemPaneSuggestionsEnabled', 'PreInstalledAppsEnabled')) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
            -Name $n -Type DWord -Value 0 -Section '8.2' -Tier 'Aggressive' -Title "Content delivery: $n" | Out-Null
    }

    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1 -Section '8.2' -Tier 'Aggressive' `
        -Title 'Consumer features off' | Out-Null

    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' `
        -Name 'DODownloadMode' -Type DWord -Value 0 -Section '8.2' -Tier 'Aggressive' `
        -Title 'Delivery Optimization P2P off' | Out-Null

    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        -Name 'AllowTelemetry' -Type DWord -Value 0 -Section '8.2' -Tier 'Aggressive' `
        -Title 'Telemetry off' | Out-Null

    # Worth calling out in the report: this stops Windows Update replacing your
    # chosen GPU driver with a generic WHQL one mid-season.
    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' `
        -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1 -Section '8.2' -Tier 'Aggressive' `
        -Title 'Exclude drivers from Windows Update quality updates' | Out-Null
}

function Invoke-OptSection83VisualFx {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $fx = Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' `
        -Name 'VisualFXSetting' -Type DWord -Value 2 -Section '8.3' -Tier 'Aggressive' `
        -Title 'Visual effects: adjust for best performance'

    # Honesty about mechanism: VisualFXSetting selects the radio button in the
    # Performance Options dialog; the shell reads it and applies the individual
    # effect toggles at the next sign-in. Claiming it "took effect" immediately
    # would be wrong, so flag the logoff instead.
    if ($fx.Action -in @('Applied', 'DryRun')) {
        $State.LogoffRequired = $true
        [void](Add-OptDecision -State $State -Id 'S-8.3-LOGON' -Section '8.3' -Decision 'NoOp' `
            -Title 'Visual effects timing' `
            -Reason 'takes effect at the next sign-in - the shell applies the individual effect toggles from this setting at logon')
    }

    Set-OptRegistryValue -State $State -Path 'HKCU:\Control Panel\Desktop' `
        -Name 'MenuShowDelay' -Type String -Value '0' -Section '8.3' -Tier 'Aggressive' `
        -Title 'Menu show delay 0' | Out-Null

    # Transparency off genuinely reduces DWM compositing cost.
    Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' `
        -Name 'EnableTransparency' -Type DWord -Value 0 -Section '8.3' -Tier 'Aggressive' `
        -Title 'Window transparency off' | Out-Null

    [void](Add-OptDecision -State $State -Id 'S-8.3-FONTS' -Section '8.3' -Decision 'NoOp' `
        -Title 'Font smoothing' `
        -Reason 'left ON deliberately - "adjust for best performance" would disable ClearType, which costs readability for no in-game gain')
}

function Invoke-OptSection84Startup {
    <#
        Report-only by design (spec 8.4). The script cannot know which startup
        entries are anti-cheat components or peripheral drivers, so it enumerates
        and recommends rather than disabling anything.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '8.4')) { return }

    $entries = New-Object System.Collections.ArrayList

    foreach ($hive in @('HKLM', 'HKCU')) {
        foreach ($sub in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                           'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
            $base = $null; $key = $null
            try {
                $base = Get-OptRegistryHiveKey -Hive $hive
                $key = $base.OpenSubKey($sub)
                if (-not $key) { continue }
                foreach ($name in $key.GetValueNames()) {
                    [void]$entries.Add([pscustomobject]@{
                        Source = "$hive\$sub"; Name = $name; Command = [string]$key.GetValue($name)
                    })
                }
            }
            catch { }
            finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
        }
    }

    foreach ($folder in @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    )) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue)) {
            [void]$entries.Add([pscustomobject]@{ Source = 'Startup folder'; Name = $f.Name; Command = $f.FullName })
        }
    }

    $State['StartupInventory'] = @($entries)

    [void](Add-OptDecision -State $State -Id 'S-8.4' -Section '8.4' -Decision 'Manual' `
        -Title 'Startup inventory' `
        -Reason "$($entries.Count) startup entries found - listed in the report. Nothing was disabled automatically: the script cannot tell an anti-cheat component or peripheral driver from bloat.")
}

function Invoke-OptSection85Ai {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile

    # Policy keys in this area move between builds more than anything else in
    # the spec. Each row carries the build it was verified against; beyond that
    # the write still happens as future-proofing but is marked Unverified rather
    # than counted as an applied optimization.
    $verifiedOnBuild = 26100
    $currentBuild = [int]$p.OS.BuildNumber

    $keys = @(
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';    N = 'DisableAIDataAnalysis';  T = 'Recall (machine)' }
        @{ P = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';    N = 'DisableAIDataAnalysis';  T = 'Recall (user)' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';    N = 'DisableClickToDo';       T = 'Click to Do' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI';    N = 'TurnOffWindowsCopilot';  T = 'Copilot' }
        @{ P = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; N = 'TurnOffWindowsCopilot'; T = 'Copilot (legacy path)' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint';        N = 'DisableCocreator';       T = 'Paint Cocreator' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint';        N = 'DisableImageCreator';    T = 'Paint image creator' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Paint';        N = 'DisableGenerativeFill';  T = 'Paint generative fill' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Notepad';      N = 'DisableAIFeatures';      T = 'Notepad AI' }
    )

    foreach ($k in $keys) {
        Set-OptRegistryValue -State $State -Path $k.P -Name $k.N -Type DWord -Value 1 `
            -Section '8.5' -Tier 'Aggressive' -Title $k.T | Out-Null
    }

    Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        -Name 'ShowCopilotButton' -Type DWord -Value 0 -Section '8.5' -Tier 'Aggressive' `
        -Title 'Copilot taskbar button' | Out-Null

    # Edge: StartupBoostEnabled and BackgroundModeEnabled are the two with an
    # actual measurable effect - they stop Edge preloading renderer processes at
    # boot and keeping them resident after close.
    foreach ($n in @('HubsSidebarEnabled', 'StartupBoostEnabled', 'BackgroundModeEnabled', 'CopilotPageContext')) {
        Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' `
            -Name $n -Type DWord -Value 0 -Section '8.5' -Tier 'Aggressive' -Title "Edge $n" | Out-Null
    }

    if (-not $p.OS.HasNpu) {
        [void](Add-OptDecision -State $State -Id 'S-8.5-NPU' -Section '8.5' -Decision 'NoOp' `
            -Title 'Recall and on-device AI' `
            -Reason 'no NPU on this machine, so Recall and the on-device AI surfaces are NOT INSTALLED. The policy keys above are future-proofing only and are not counted as an applied optimization.')
    }

    if ($currentBuild -gt $verifiedOnBuild) {
        [void](Add-OptDecision -State $State -Id 'S-8.5-BUILD' -Section '8.5' -Decision 'Unverified' `
            -Title 'AI policy key validity' `
            -Reason "these keys were last verified against build $verifiedOnBuild and this machine is build $currentBuild - they are written, but check the current Policy CSP documentation before treating them as effective")
    }
}

function Invoke-OptSection86Telemetry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    foreach ($v in @(
        @{ N = 'DoNotShowFeedbackNotifications'; V = 1 }
        @{ N = 'AllowDeviceNameInTelemetry';     V = 0 }
        @{ N = 'LimitDiagnosticLogCollection';   V = 1 }
        @{ N = 'LimitDumpCollection';            V = 1 }
        @{ N = 'DisableOneSettingsDownloads';    V = 1 }
    )) {
        Set-OptRegistryValue -State $State -Path $dc -Name $v.N -Type DWord -Value $v.V `
            -Section '8.6' -Tier 'Aggressive' -Title "DataCollection $($v.N)" | Out-Null
    }

    foreach ($v in @(
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules';                              N = 'NumberOfSIUFInPeriod';                     V = 0 }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy';          N = 'TailoredExperiencesWithDiagnosticDataEnabled'; V = 0 }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo';  N = 'Enabled';                                  V = 0 }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo';        N = 'DisabledByGroupPolicy';                    V = 1 }
        @{ P = 'HKCU:\Control Panel\International\User Profile';                   N = 'HttpAcceptLanguageOptOut';                 V = 1 }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                 N = 'EnableActivityFeed';                       V = 0 }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                 N = 'PublishUserActivities';                    V = 0 }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';                 N = 'UploadUserActivities';                     V = 0 }
    )) {
        Set-OptRegistryValue -State $State -Path $v.P -Name $v.N -Type DWord -Value $v.V `
            -Section '8.6' -Tier 'Aggressive' -Title "Telemetry: $($v.N)" | Out-Null
    }

    # ETW autologgers are the part of this section with an actual measurable
    # cost: kernel trace sessions run continuously from boot, writing to disk.
    $autologgers = @('AutoLogger-Diagtrack-Listener', 'SQMLogger', 'Circular Kernel Context Logger')
    if (-not $State.Profile.Network.ActiveIsWireless) { $autologgers += 'WiFiSession' }

    foreach ($logger in $autologgers) {
        Set-OptRegistryValue -State $State -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$logger" `
            -Name 'Start' -Type DWord -Value 0 -Section '8.6' -Tier 'Aggressive' `
            -Title "ETW autologger $logger" -RequiresReboot -VerifyMode PostReboot | Out-Null
    }

    [void](Add-OptDecision -State $State -Id 'S-8.6-KEEPLOGGERS' -Section '8.6' -Decision 'NoOp' `
        -Title 'Autologgers left alone' `
        -Reason 'EventLog-* and DefenderApiLogger / DefenderAuditLogger are deliberately untouched - Defender and anti-cheat both consume those trace sessions')

    # DiagTrack. Experimental, with the caveat logged rather than buried.
    if ((Test-OptSectionEnabled -State $State -Section '8.6') -and (Test-OptTier -State $State -Required 'Experimental')) {
        foreach ($svcName in @('DiagTrack', 'dmwappushservice')) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) { continue }
            if ([string]$svc.StartType -eq 'Disabled') {
                [void](Add-OptDecision -State $State -Id "S-8.6-$svcName" -Section '8.6' -Decision 'NoOp' `
                    -Title "$svcName service" -Reason 'already disabled')
                continue
            }

            $old = [string]$svc.StartType
            $r = Invoke-OptCmdletChange -State $State -Description "disable $svcName" -Action {
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            }
            if (-not $r.Success -and -not $r.DryRun) {
                [void](Add-OptDecision -State $State -Id "S-8.6-$svcName" -Section '8.6' -Decision 'Failed' `
                    -Title "$svcName service" -Severity 'Warning' -Reason $r.Error)
                continue
            }

            $change = New-OptChangeRecord -State $State -Type 'Service' -Section '8.6' -Tier 'Experimental' `
                -Path 'services' -Name $svcName -Target @{ ServiceName = $svcName } `
                -OldValue $old -NewValue 'Disabled'
            if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

            [void](Add-OptDecision -State $State -Id "S-8.6-$svcName" -Section '8.6' -Decision 'Applied' `
                -Title "$svcName service" `
                -Reason "disabled (was $old). Nothing breaks functionally, but it feeds Windows Update reliability signals - if you later troubleshoot an update failure with Microsoft support, this is the first thing they will ask about.")
        }
    }
}

function Invoke-OptSection87Shell {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $values = @(
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh';                                    N = 'AllowNewsAndInterests';           V = 0; T = 'Widgets / News and Interests' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';        N = 'TaskbarDa';                       V = 0; T = 'Widgets taskbar button' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';        N = 'TaskbarMn';                       V = 0; T = 'Chat/Teams button' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search';                   N = 'SearchboxTaskbarMode';            V = 0; T = 'Taskbar search box' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings';           N = 'IsDynamicSearchBoxEnabled';       V = 0; T = 'Search highlights' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings';           N = 'IsMSACloudSearchEnabled';         V = 0; T = 'Cloud search (MSA)' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings';           N = 'IsAADCloudSearchEnabled';         V = 0; T = 'Cloud search (AAD)' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings';           N = 'IsDeviceSearchHistoryEnabled';    V = 0; T = 'Device search history' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                 N = 'DisableWebSearch';                V = 1; T = 'Web search in Start' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search';                 N = 'AllowCortana';                    V = 0; T = 'Cortana' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer';                       N = 'HideRecommendedSection';          V = 1; T = 'Start recommendations' }
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer';                       N = 'HideRecommendedPersonalizedSites'; V = 1; T = 'Start personalized sites' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';        N = 'Start_IrisRecommendations';       V = 0; T = 'Start Iris suggestions' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';        N = 'Start_TrackDocs';                 V = 0; T = 'Recent docs tracking' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager';   N = 'RotatingLockScreenOverlayEnabled'; V = 0; T = 'Lock screen fun facts' }
        @{ P = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced';        N = 'ShowSyncProviderNotifications';   V = 0; T = 'Sync provider ads in Explorer' }
    )

    foreach ($v in $values) {
        Set-OptRegistryValue -State $State -Path $v.P -Name $v.N -Type DWord -Value $v.V `
            -Section '8.7' -Tier 'Aggressive' -Title $v.T | Out-Null
    }

    # Explorer restart is deliberately NOT performed. Restarting the shell from
    # an elevated process can relaunch it ELEVATED, which is a genuinely bad
    # state to leave a machine in. A logoff achieves the same thing safely.
    if (@($State.Changes | Where-Object { $_.Section -eq '8.7' }).Count -gt 0) {
        $State.LogoffRequired = $true
        [void](Add-OptDecision -State $State -Id 'S-8.7-EXPLORER' -Section '8.7' -Decision 'NoOp' `
            -Title 'Explorer restart' `
            -Reason 'not restarting Explorer from an elevated process - doing so can relaunch the shell elevated. Sign out and back in to pick these up.')
    }
}

function Invoke-OptSection88Apps {
    <#
        REPORT-ONLY in this build, by decision.

        Remove-AppxProvisionedPackage genuinely cannot be rolled back: the
        payload usually does not survive, so Add-AppxPackage -Register has
        nothing to point at. The honest framing is that this buys disk space and
        a handful of background tasks - not frames.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '8.8')) { return }

    $candidates = @(
        'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingSearch'
        'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.WindowsFeedbackHub'
        'Microsoft.MicrosoftOfficeHub', 'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.People', 'Microsoft.Todos', 'Microsoft.WindowsMaps'
        'Microsoft.YourPhone', 'MicrosoftTeams', 'MSTeams', 'Microsoft.SkypeApp'
        'Clipchamp.Clipchamp', 'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo'
        'Microsoft.WindowsSoundRecorder', 'Microsoft.MicrosoftStickyNotes'
        'Microsoft.549981C3F5F10', 'Microsoft.Copilot', 'Microsoft.Windows.Ai.Copilot.Provider'
        'MicrosoftWindows.Client.WebExperience', 'Microsoft.Windows.DevHome'
        'Microsoft.OutlookForWindows', 'Microsoft.MixedReality.Portal', 'Microsoft.3DBuilder'
        'Microsoft.LinkedIn', 'Microsoft.Family', 'MicrosoftCorporationII.QuickAssist'
    )

    # Enforced AFTER pattern expansion, and re-checked against a hardcoded
    # never-list. The GPU control panels are the important ones: Adrenalin, the
    # NVIDIA control panel and Intel Graphics Experience all ship as appx, and a
    # startling number of debloat scripts uninstall the user's driver UI.
    $keepList = @(
        '*DesktopAppInstaller*', '*WindowsStore*', '*StorePurchaseApp*'
        '*VCLibs*', '*UI.Xaml*', '*NET.Native*', '*WebView2*', '*SecHealthUI*'
        '*AMDRadeonSoftware*', '*NVIDIAControlPanel*', '*IntelGraphicsExperience*'
        '*XboxIdentityProvider*', '*Windows.Photos*', '*WindowsNotepad*', '*WindowsCalculator*'
        '*XboxGamingOverlay*'
    )

    $installed = @()
    try { $installed = @(Get-AppxPackage -ErrorAction Stop) } catch { }

    $found = New-Object System.Collections.ArrayList
    foreach ($c in $candidates) {
        foreach ($pkg in @($installed | Where-Object { $_.Name -like "*$c*" })) {
            $keep = $false
            foreach ($k in $keepList) { if ($pkg.Name -like $k) { $keep = $true; break } }
            if ($keep) { continue }
            [void]$found.Add($pkg.Name)
        }
    }

    $State['AppxCandidates'] = @($found | Sort-Object -Unique)

    [void](Add-OptDecision -State $State -Id 'S-8.8' -Section '8.8' -Decision 'Manual' `
        -Title 'Inbox app removal' `
        -Reason "$(@($State['AppxCandidates']).Count) removable inbox package(s) found - listed in the report, NOT removed. Provisioned package removal is not reliably reversible, and it buys disk space and a few background tasks, not frames.")

    [void](Add-OptDecision -State $State -Id 'S-8.8-XBOX' -Section '8.8' -Decision 'NoOp' `
        -Title 'Xbox Game Bar' `
        -Reason 'disabled via registry in section 3.1 rather than removed - removal breaks Game Mode registration on some builds and Windows reinstalls it anyway')
}

function Invoke-OptSection89OneDrive {
    <#
        REPORT-ONLY in this build.

        "Local-only content" cannot be reliably distinguished from
        Files-On-Demand placeholders by file attributes alone, and this is the
        single most likely thing in the whole spec to destroy user data.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '8.9')) { return }

    $oneDrivePath = $env:OneDrive
    $running = @(Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue)

    if (-not $oneDrivePath -and $running.Count -eq 0) {
        [void](Add-OptDecision -State $State -Id 'S-8.9' -Section '8.9' -Decision 'NoOp' `
            -Title 'OneDrive' -Reason 'not configured on this machine')
        return
    }

    $fileCount = 0
    if ($oneDrivePath -and (Test-Path -LiteralPath $oneDrivePath)) {
        $fileCount = @(Get-ChildItem -LiteralPath $oneDrivePath -Recurse -File -Force -ErrorAction SilentlyContinue |
                       Select-Object -First 500).Count
    }

    [void](Add-OptDecision -State $State -Id 'S-8.9' -Section '8.9' -Decision 'Manual' `
        -Title 'OneDrive' `
        -Reason "OneDrive is present at '$oneDrivePath' with at least $fileCount file(s)$(if ($running.Count) { ' and is currently running' }). NOT removed: local-only content cannot be reliably distinguished from Files-On-Demand placeholders, and getting this wrong destroys data. Uninstall it yourself via Settings if this is genuinely a game-only machine.")
}
