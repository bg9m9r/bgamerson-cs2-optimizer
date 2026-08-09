<#
    Section 3 - GPU.

    3.1-3.3 and 3.7-3.8 are vendor-neutral. Exactly one of 3.4/3.5/3.6 produces
    a checklist, selected by the primary adapter's vendor; if the vendor is
    Unknown, none of them do.
#>

function Invoke-OptSection03 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 3 - GPU'

    Invoke-OptSection31Registry        -State $State
    Invoke-OptSection32Mpo             -State $State
    Invoke-OptSection33PerApp          -State $State
    Invoke-OptSection35NvidiaTelemetry -State $State
    Invoke-OptSection38Refresh         -State $State
}

function Invoke-OptSection35NvidiaTelemetry {
    <#
        The one NVIDIA-specific item the spec says the script CAN automate
        safely (3.5): the telemetry container service and its scheduled tasks.
        Everything else NVIDIA lives in the manual checklist because the driver
        profile store is a binary blob.

        No-ops entirely on non-NVIDIA machines.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if ($State.Profile.GPU.PrimaryVendor -ne 'NVIDIA') { return }
    if (-not (Test-OptSectionEnabled -State $State -Section '3.5')) { return }
    if (-not (Test-OptTier -State $State -Required 'Aggressive')) { return }

    $svc = Get-Service -Name 'NvTelemetryContainer' -ErrorAction SilentlyContinue
    if ($svc) {
        if ([string]$svc.StartType -eq 'Disabled') {
            [void](Add-OptDecision -State $State -Id 'S-3.5-TELEMETRY' -Section '3.5' -Decision 'NoOp' `
                -Title 'NVIDIA telemetry service' -Reason 'already disabled')
        }
        else {
            $old = [string]$svc.StartType
            $r = Invoke-OptCmdletChange -State $State -Description 'disable NvTelemetryContainer' -Action {
                Set-Service -Name 'NvTelemetryContainer' -StartupType Disabled -ErrorAction Stop
                Stop-Service -Name 'NvTelemetryContainer' -Force -ErrorAction SilentlyContinue
            }
            if ($r.Success -or $r.DryRun) {
                $change = New-OptChangeRecord -State $State -Type 'Service' -Section '3.5' -Tier 'Aggressive' `
                    -Path 'services' -Name 'NvTelemetryContainer' `
                    -Target @{ ServiceName = 'NvTelemetryContainer' } `
                    -OldValue $old -NewValue 'Disabled'
                if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }
                [void](Add-OptDecision -State $State -Id 'S-3.5-TELEMETRY' -Section '3.5' -Decision 'Applied' `
                    -Title 'NVIDIA telemetry service' -Reason "disabled (was $old)")
            }
            else {
                [void](Add-OptDecision -State $State -Id 'S-3.5-TELEMETRY' -Section '3.5' -Decision 'Failed' `
                    -Title 'NVIDIA telemetry service' -Severity 'Warning' -Reason $r.Error)
            }
        }
    }

    # The telemetry scheduled tasks live in the task root with GUID-suffixed
    # names, so enumerate-and-match rather than exact names.
    $nvTasks = @(Get-ScheduledTask -TaskPath '\' -ErrorAction SilentlyContinue |
                 Where-Object { $_.TaskName -match '^(NvTmRep|NvTmMon|NvTmRepOnLogon|NvProfileUpdater|NvDriverUpdateCheck)' })
    foreach ($t in $nvTasks) {
        Disable-OptScheduledTask -State $State -TaskPath ([string]$t.TaskPath) -TaskName ([string]$t.TaskName) `
            -Section '3.5' -Tier 'Aggressive'
    }
}

function Invoke-OptSection31Registry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Hardware-accelerated GPU scheduling. Required for AMD Anti-Lag and NVIDIA
    # Reflex low-latency paths to work correctly. Gated off for Intel Arc, where
    # behaviour is driver-version dependent - and skipped entirely when the
    # driver does not advertise support (spec 3.1: HwSchMode absent from
    # GraphicsDrivers after a clean driver install means the driver has no HAGS
    # path, and forcing the value does nothing but clutter the manifest).
    if (Test-OptSectionEnabled -State $State -Section '3.1.HwSchMode') {
        $hagsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
        $hagsResolved = Resolve-OptRegistryPath -State $State -Path $hagsPath
        $hagsInfo = Get-OptRegistryValueInfo -State $State -Hive $hagsResolved.Hive `
                        -SubKey $hagsResolved.SubKey -Name 'HwSchMode'

        if (-not $hagsInfo.ValueExists) {
            [void](Add-OptDecision -State $State -Id 'S-3.1-HAGS-UNSUP' -Section '3.1' -Decision 'Off' `
                -Title 'Hardware-accelerated GPU scheduling' `
                -Reason 'the driver does not advertise HAGS support (HwSchMode absent) - skipped rather than forced')
        }
        else {
            Set-OptRegistryValue -State $State -Path $hagsPath `
                -Name 'HwSchMode' -Type DWord -Value 2 -Section '3.1' -Tier 'Safe' `
                -Title 'Hardware-accelerated GPU scheduling' -RequiresReboot -VerifyMode PostReboot | Out-Null
        }
    }

    # Game DVR / capture off.
    Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' `
        -Name 'AppCaptureEnabled' -Type DWord -Value 0 -Section '3.1' -Tier 'Safe' -Title 'Game DVR capture' | Out-Null

    foreach ($v in @(
        @{ N = 'GameDVR_Enabled';                       V = 0 }
        @{ N = 'GameDVR_FSEBehaviorMode';               V = 2 }
        @{ N = 'GameDVR_HonorUserFSEBehaviorMode';      V = 1 }
        @{ N = 'GameDVR_DXGIHonorFSEWindowsCompatible'; V = 1 }
    )) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\System\GameConfigStore' `
            -Name $v.N -Type DWord -Value $v.V -Section '3.1' -Tier 'Safe' -Title "GameConfigStore $($v.N)" | Out-Null
    }

    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' `
        -Name 'AllowGameDVR' -Type DWord -Value 0 -Section '3.1' -Tier 'Safe' -Title 'Game DVR policy' | Out-Null

    # Game Mode ON. On Windows 11 this is net positive - it suppresses
    # background scheduler interference. Xbox Game Bar is DISABLED here rather
    # than removed (spec 8.8): removal breaks Game Mode registration on some
    # builds and Windows reinstalls it anyway.
    foreach ($v in @(
        @{ N = 'AutoGameModeEnabled'; V = 1 }
        @{ N = 'AllowAutoGameMode';   V = 1 }
        @{ N = 'ShowStartupPanel';    V = 0 }
    )) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameBar' `
            -Name $v.N -Type DWord -Value $v.V -Section '3.1' -Tier 'Safe' -Title "GameBar $($v.N)" | Out-Null
    }
}

function Invoke-OptSection32Mpo {
    <#
        Multi-Plane Overlay disable - symptom-driven, never automatic.

        Two things changed here after review:

        1. Spec 3.2 gates this behind "a detection of whether the symptom
           exists". Flicker cannot be detected from software, so the honest
           implementation of that gate is explicit opt-in: this only applies
           when the user names the section (-Sections 3.2), which is the user
           reporting the symptom. Running -Tier Experimental alone does NOT
           apply it.

        2. The Dwm\OverlayTestMode value the spec (and every guide) cites is no
           longer read on 24H2+ builds - writing it there is a silent no-op.
           The working mechanism on >= 26100 is
           GraphicsDrivers\DisableOverlays = 1 (community-verified via dxdiag
           reporting MPO "Not Supported" afterwards; no Microsoft doc exists
           for either key). Older builds keep the classic value.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '3.2')) { return }

    $explicitly = $false
    $only = $State.Parameters['Sections']
    if ($only -and $only.Count -gt 0) {
        $explicitly = Test-OptSectionMatch -Section '3.2' -Patterns $only
    }

    if (-not $explicitly) {
        if (Test-OptTier -State $State -Required 'Experimental') {
            [void](Add-OptDecision -State $State -Id 'S-3.2-OPTIN' -Section '3.2' -Decision 'NoOp' `
                -Title 'Disable Multi-Plane Overlay' `
                -Reason 'not applied - this is a fix for visible desktop flicker/micro-stutter, not a general optimization, and it can increase compositing cost. If you have the symptom, re-run with: -Tier Experimental -Sections 3.2')
        }
        return
    }

    $build = [int]$State.Profile.OS.BuildNumber
    if ($build -ge 26100) {
        Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' `
            -Name 'DisableOverlays' -Type DWord -Value 1 -Section '3.2' -Tier 'Experimental' `
            -Title 'Disable Multi-Plane Overlay (24H2+ mechanism)' -RequiresReboot -VerifyMode PostReboot | Out-Null

        [void](Add-OptDecision -State $State -Id 'S-3.2-VERIFY' -Section '3.2' -Decision 'NoOp' `
            -Title 'MPO disable verification' `
            -Reason 'after rebooting, dxdiag > Save All Information should show MultiplaneOverlay "Not Supported". The legacy Dwm\OverlayTestMode value is not written - builds 26100+ no longer read it.')
    }
    else {
        Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' `
            -Name 'OverlayTestMode' -Type DWord -Value 5 -Section '3.2' -Tier 'Experimental' `
            -Title 'Disable Multi-Plane Overlay' -RequiresReboot -VerifyMode PostReboot | Out-Null
    }
}

function Invoke-OptSection33PerApp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile
    if (-not $p.Games.Cs2Installed) { return }

    $exe = [string]$p.Games.Cs2ExePath

    # Disable fullscreen optimizations for cs2.exe. NOTE: the registry VALUE
    # NAME here is a full filesystem path - which is exactly why every read goes
    # through the RegistryKey API rather than Get-ItemProperty, whose -Name
    # parameter is a wildcard pattern.
    #
    # The value is a SPACE-SEPARATED FLAG LIST, not a single setting. Writing a
    # bare '~ DISABLEDXMAXIMIZEDWINDOWEDMODE' would silently discard any flag the
    # user already had - verified on this machine, where cs2.exe already carries
    # '~ HIGHDPIAWARE'. Merge instead of replacing.
    $layersPath = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
    $resolvedLayers = Resolve-OptRegistryPath -State $State -Path $layersPath
    $existing = Get-OptRegistryValueInfo -State $State -Hive $resolvedLayers.Hive `
                    -SubKey $resolvedLayers.SubKey -Name $exe

    $flags = New-Object System.Collections.ArrayList
    [void]$flags.Add('~')
    if ($existing.ValueExists -and $existing.Value) {
        foreach ($token in ([string]$existing.Value -split '\s+')) {
            if ($token -and $token -ne '~') { [void]$flags.Add($token) }
        }
    }
    if ($flags -notcontains 'DISABLEDXMAXIMIZEDWINDOWEDMODE') {
        [void]$flags.Add('DISABLEDXMAXIMIZEDWINDOWEDMODE')
    }

    Set-OptRegistryValue -State $State -Path $layersPath `
        -Name $exe -Type String -Value ($flags -join ' ') `
        -Section '3.3' -Tier 'Safe' -Title 'Disable fullscreen optimizations for cs2.exe' | Out-Null

    # GpuPreference=2 routes CS2 to the high-performance adapter; AutoHDREnable=0
    # because Auto HDR adds latency and skews colours. On a single-GPU system the
    # GpuPreference half is inert - written anyway for portability, and logged as
    # such rather than claimed as a win.
    Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences' `
        -Name $exe -Type String -Value 'GpuPreference=2;AutoHDREnable=0;' `
        -Section '3.3' -Tier 'Safe' -Title 'GPU preference + Auto HDR off for cs2.exe' | Out-Null

    if (-not $p.GPU.HasMultiple) {
        [void](Add-OptDecision -State $State -Id 'S-3.3-SINGLEGPU' -Section '3.3' -Decision 'NoOp' `
            -Title 'GpuPreference on a single-GPU system' `
            -Reason 'only one adapter present, so GpuPreference=2 is inert - written for portability, not counted as an optimization')
    }
}

function Invoke-OptSection38Refresh {
    <#
        The highest-value scriptable item in the whole spec, and one almost no
        optimization guide covers: Windows regularly lands on a lower mode than
        the panel supports after a driver update, cable renegotiation or
        DisplayPort wake. On a 540 Hz panel silently running at 60 Hz, nothing
        else here matters.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '3.8')) { return }
    if (-not $State.Capabilities.DisplayModeChange) {
        [void](Add-OptDecision -State $State -Id 'S-3.8-INTEROP' -Section '3.8' -Decision 'Off' `
            -Title 'Refresh rate enforcement' -Severity 'Warning' `
            -Reason 'display interop unavailable - cannot enumerate or change display modes')
        return
    }

    foreach ($d in $State.Profile.Display.Displays) {
        if (-not $d.RefreshBelowMax) { continue }

        $device = [string]$d.Device
        $target = [int]$d.MaxRefreshHz
        $current = [int]$d.CurrentRefreshHz

        # CDS_TEST first, always. Under -DryRun we stop after the test, which is
        # genuinely non-mutating AND more informative than skipping - it reports
        # whether the mode would actually validate.
        $test = [Cs2Opt.Display.Api]::TrySetRefresh($device, $target, $true)
        if (-not $test.TestPassed) {
            [void](Add-OptDecision -State $State -Id "S-3.8-$device" -Section '3.8' -Decision 'Failed' `
                -Title "Refresh rate $($d.MonitorName)" -Severity 'Warning' `
                -Reason "driver rejected ${target} Hz ($($test.CodeName)) - likely a cable or bandwidth limit (DP version, HDMI 2.0 vs 2.1) rather than something software can fix")
            continue
        }

        if ($State.DryRun) {
            [void](Add-OptDecision -State $State -Id "S-3.8-$device" -Section '3.8' -Decision 'Applied' `
                -Title "Refresh rate $($d.MonitorName)" `
                -Reason "would raise $current Hz -> $target Hz (mode validates)")
            continue
        }

        $result = [Cs2Opt.Display.Api]::TrySetRefresh($device, $target, $false)
        if (-not $result.Applied) {
            [void](Add-OptDecision -State $State -Id "S-3.8-$device" -Section '3.8' -Decision 'Failed' `
                -Title "Refresh rate $($d.MonitorName)" -Severity 'Warning' `
                -Reason "change did not stick ($($result.CodeName)) - report a likely cable/bandwidth limitation rather than retrying")
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'DisplayMode' -Section '3.8' -Tier 'Safe' `
            -Path $device -Name 'RefreshHz' `
            -Target @{ Device = $device; Width = $d.Width; Height = $d.Height; Bpp = $d.Bpp } `
            -OldValue $current -NewValue $target
        [void](Add-OptChange -State $State -Change $change)

        [void](Add-OptDecision -State $State -Id "S-3.8-$device" -Section '3.8' -Decision 'Applied' `
            -Title "Refresh rate $($d.MonitorName)" -Reason "raised $current Hz -> $target Hz")
    }
}
