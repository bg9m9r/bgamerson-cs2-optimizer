<#
    Manual checklists (spec 3.4/3.5/3.6, 11, 12).

    None of this is scriptable safely:
      - AMD's settings live in an opaque per-profile blob; the NVIDIA profile
        store is a binary .bin. Writing either can corrupt the profile store.
      - Steam caches localconfig.vdf in memory and overwrites it on exit, and a
        malformed VDF wipes the config.
      - BIOS settings are firmware.

    So these are GENERATED FROM THE DETECTED PROFILE with real values
    substituted, rather than printed as generic advice.
#>

function Invoke-OptManualChecklists {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Invoke-OptGpuChecklist   -State $State
    Invoke-OptSteamChecklist -State $State
    Invoke-OptAudioChecklist -State $State
    Invoke-OptBiosChecklist  -State $State
}

function Invoke-OptGpuChecklist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $vendor = $State.Profile.GPU.PrimaryVendor

    if ($vendor -eq 'AMD' -and (Test-OptSectionEnabled -State $State -Section '3.4')) {
        [void](Add-OptManual -State $State -Id 'M-3.4' -Section '3.4' -Title 'AMD Adrenalin settings' -Detail @'
  Latency: for CS2 specifically, enable ANTI-LAG 2 IN THE GAME's video settings
  (engine-integrated via a Valve partnership; needs Adrenalin 24.6.1+ and an
  RX 5000-series or newer card). It supersedes the driver-panel Anti-Lag for
  this title and is explicitly ban-safe. Driver-panel standard Anti-Lag is the
  fallback for older drivers only.

  Radeon Chill ................... Off
  Radeon Boost ................... Off
  Enhanced Sync .................. Off
  Wait for Vertical Refresh ...... Always Off
  Radeon Image Sharpening ........ Off (or low, to taste)
  Texture Filtering Quality ...... Performance
  Surface Format Optimization .... On
  Tessellation Mode .............. Override, 8x or Off
  FreeSync ....................... On at the display (inert when fps > refresh, harmless)
  Frame rate target .............. worth an A/B: a DRIVER-level cap at roughly
                                   your sustained fps gives flatter frame times
                                   than CS2's own fps_max, which paces poorly
  AMD Software ................... disable auto-start with Windows,
                                   disable "AMD User Experience Program" telemetry,
                                   disable the in-game overlay AND its hotkeys entirely

  WARNING: never enable Anti-Lag+ (the 2023 feature). It triggered VAC bans in
  CS2 in October 2023. Anti-Lag 2 is a different, game-integrated mechanism and
  is fine.
'@)
    }

    if ($vendor -eq 'NVIDIA' -and (Test-OptSectionEnabled -State $State -Section '3.5')) {
        [void](Add-OptManual -State $State -Id 'M-3.5' -Section '3.5' -Title 'NVIDIA Control Panel settings' -Detail @'
  Low Latency Mode ............... Ultra  (or in-game Reflex, which supersedes it)
  Power Management Mode .......... Prefer Maximum Performance
  Vertical Sync .................. Off
  Texture Filtering Quality ...... High Performance
  Threaded Optimization .......... On/Auto (forcing Off is a CS:GO-era myth)
  Shader Cache Size .............. Unlimited, or at least 10 GB
  Max Frame Rate ................. Off - cap in-game with fps_max instead
  G-Sync ......................... enable (inert when fps is far above refresh)
  GeForce Experience / NVIDIA App  disable the in-game overlay and its hotkeys

  The NVIDIA profile store (nvdrsdb*.bin) is a binary blob - this script will not
  write it. The one NVIDIA item that CAN be automated safely is disabling the
  "NVIDIA Telemetry Container" service and its scheduled tasks.
'@)
    }

    if ($vendor -eq 'Intel' -and (Test-OptSectionEnabled -State $State -Section '3.6')) {
        [void](Add-OptManual -State $State -Id 'M-3.6' -Section '3.6' -Title 'Intel Arc Control settings' -Detail @'
  Low Latency Mode ............... On
  Vertical Sync .................. Off
  Arc Control .................... disable the overlay and telemetry
  HAGS ........................... leave at the driver default (see section 3.1)

  Arc is not a well-characterized CS2 platform. Treat your own measured results
  as authoritative over any tweak in this document.
'@)
    }
}

function Invoke-OptSteamChecklist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile
    if (-not $p.Games.Cs2Installed) { return }

    $maxHz = [int]$p.Display.PrimaryMaxRefreshHz
    $w = 0; $h = 0
    $primary = @($p.Display.Displays | Where-Object { $_.IsPrimary }) | Select-Object -First 1
    if ($primary) { $w = [int]$primary.Width; $h = [int]$primary.Height }

    # fps_max advice depends on the DETECTED panel: uncapped rendering on a
    # low-refresh panel is heat and coil whine for no visible gain.
    $fpsAdvice = if ($maxHz -ge 200) {
        "fps_max 0            (uncapped - your $maxHz Hz panel will rarely be the limit)"
    }
    elseif ($maxHz -gt 0) {
        "fps_max $([int]($maxHz * 1.5))         (a cap slightly above your $maxHz Hz panel - uncapped here is heat for no visible gain)"
    }
    else { 'fps_max 0' }

    $latency = switch ($p.GPU.PrimaryVendor) {
        'AMD'    { 'Latency reduction: enable in-game ANTI-LAG 2 (needs Adrenalin 24.6.1+, RX 5000+; ban-safe, supersedes driver-panel Anti-Lag for CS2 - and NEVER Anti-Lag+)' }
        'NVIDIA' { 'Latency reduction: enable in-game NVIDIA Reflex' }
        'Intel'  { 'Latency reduction: use Arc Low Latency Mode' }
        default  { 'Latency reduction: GPU vendor unknown - no recommendation' }
    }

    [void](Add-OptManual -State $State -Id 'M-11' -Section '11' -Title 'Steam and CS2 settings' -Detail @"
  LAUNCH OPTIONS (Steam > CS2 > Properties):
      -nojoy -console

      -novid is deliberately absent: CS2 has no intro video, so it does nothing
      Do NOT add -high      : section 6.4 already sets priority correctly via IFEO
      Do NOT add -threads N : CS2's own scheduler handles this better
      -allow_third_party_software only if you genuinely need RTSS - it adds risk
      surface; prefer in-game cl_showfps

  IN-GAME:
      $fpsAdvice
      fps_max_ui 120       (caps the menu renderer - real thermal/power headroom)
      Display mode         Exclusive fullscreen, NOT borderless
                           (borderless routes through DWM and adds a frame of latency)
      Resolution           ${w}x${h} at $maxHz Hz - matches your detected panel
      $latency
      engine_no_focus_sleep 0   if you alt-tab during warmup
      mat_queue_mode       leave at default (-1); forcing it is a legacy CS:GO habit

  A/B EXPERIMENTS (test one at a time; anecdote-grade, not guaranteed):
      engine_low_latency_sleep_after_client_tick 1
                           reported to smooth input on tick frames; works best
                           WITH a frame cap, and can reduce fps when uncapped
      Driver-level fps cap at your sustained fps instead of CS2's fps_max -
                           CS2's own limiter paces poorly (fps bounces under
                           the target); a driver cap holds frame times flat

  STEAM CLIENT:
      Disable the Steam Overlay in-game (FACEIT does not require it)
      Disable Remote Play / In-Home Streaming host
      Disable "Run Steam when my computer starts" if you launch via FACEIT
      Downloads > disable "Allow downloads during gameplay"
      Shader pre-caching > leave ENABLED
"@)
}

function Invoke-OptAudioChecklist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Honour section blocking like every other checklist - G-CS2-ABSENT blocks
    # section 11, and the audio advice is CS2-specific.
    if (-not (Test-OptSectionEnabled -State $State -Section '11.4')) { return }

    $a = $State.Profile.Audio
    if (-not $a.DefaultName) { return }

    $flags = New-Object System.Collections.ArrayList
    if ($a.DefaultIsHdmi) {
        [void]$flags.Add('  !! Your default output is HDMI/DisplayPort audio through the GPU. That routes game audio through the display and adds latency - it is rarely intended.')
    }
    if ($a.UsbDacNotDefault) {
        [void]$flags.Add('  !! A USB DAC is present but is NOT the default output device. That is usually an accident.')
    }

    [void](Add-OptManual -State $State -Id 'M-11.4' -Section '11.4' -Title "Audio settings for '$($a.DefaultName)'" -Detail @"
  Audio positioning is competitively load-bearing in CS2. On your detected
  default endpoint - $($a.DefaultName) - set:

      Format ....................... 24-bit, 48000 Hz
                                     (matches CS2's engine rate; resampling adds
                                     latency and smears transients)
      Audio Enhancements ........... all off
      Spatial Sound ................ Off (Windows Sonic / Dolby)
                                     CS2's own HRTF is better for positional accuracy
      Exclusive mode ............... allow applications to take exclusive control

      In CS2: set the audio device to the DAC directly, not a virtual mixer.
$(if ($flags.Count) { "`n" + ($flags -join "`n") })
"@)
}

function Invoke-OptBiosChecklist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile

    $board = Get-OptCimSafe -ClassName Win32_BaseBoard | Select-Object -First 1
    $bios  = Get-OptCimSafe -ClassName Win32_BIOS | Select-Object -First 1

    $boardName = if ($board) { "$($board.Manufacturer) $($board.Product)" } else { 'unknown board' }
    $biosVer   = if ($bios) { [string]$bios.SMBIOSBIOSVersion } else { 'unknown' }

    $biosAge = ''
    if ($bios -and $bios.ReleaseDate) {
        try {
            $rd = [datetime]$bios.ReleaseDate
            $months = [int](((Get-Date) - $rd).Days / 30)
            $biosAge = " (released $($rd.ToString('yyyy-MM-dd')), ~$months months ago)"
            if ($months -gt 18) { $biosAge += ' - CONSIDER UPDATING' }
        }
        catch { }
    }

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("  Board: $boardName, BIOS $biosVer$biosAge")
    [void]$lines.Add('')

    if ($p.Memory.LooksLikeJedecBase) {
        [void]$lines.Add("  !! Memory is running at $($p.Memory.SpeedMTs) MT/s, which looks like JEDEC base speed.")
        [void]$lines.Add('     EXPO/XMP appears NOT to be enabled. This is worth more than most of this script.')
        [void]$lines.Add('')
    }

    if ($p.CPU.Vendor -eq 'AMD') {
        [void]$lines.Add('  AMD AM5 / Zen 4-5:')
        [void]$lines.Add("      EXPO profile ................. Enabled (verify DDR5 at rated speed, FCLK ~2000-2033 MHz)")
        [void]$lines.Add('      Resizable BAR ................ Enabled (plus Above 4G Decoding)')
        [void]$lines.Add('      Precision Boost Overdrive .... Enabled; Curve Optimizer negative offset')
        [void]$lines.Add('                                     X3D parts typically tolerate -20 to -30 all-core, but this is')
        [void]$lines.Add('                                     silicon-lottery dependent - ALWAYS validate with a stress run.')
        [void]$lines.Add('                                     Treat it as an experiment, not a setting.')
        [void]$lines.Add('      Global C-States .............. ENABLED (leave on - see section 2.2)')
        [void]$lines.Add('      Power Supply Idle Control .... Typical Current Idle')
        [void]$lines.Add('      CPPC / CPPC Preferred Cores .. Enabled')
        [void]$lines.Add('      IOMMU / AMD-Vi ............... ENABLED (plus SVM, which IOMMU depends on)')
        [void]$lines.Add('                                     Required by FACEIT alongside VBS. If the option is')
        [void]$lines.Add('                                     missing, update the BIOS.')
        [void]$lines.Add('      Secure Boot / fTPM ........... Enabled (required by any kernel anti-cheat)')
        [void]$lines.Add('      ErP .......................... Disabled (can interfere with USB power to peripherals)')
    }
    elseif ($p.CPU.Vendor -eq 'Intel') {
        [void]$lines.Add('  Intel:')
        [void]$lines.Add('      XMP profile .................. Enabled')
        [void]$lines.Add('      Resizable BAR ................ Enabled (plus Above 4G Decoding)')
        [void]$lines.Add('      C-States ..................... Enabled')
        [void]$lines.Add('      E-cores ...................... LEAVE ENABLED - disabling them for CS2 is a persistent')
        [void]$lines.Add('                                     myth; Thread Director handles placement and they absorb')
        [void]$lines.Add('                                     background work')
        [void]$lines.Add('      Thread Director / HW P-States  Enabled')
        [void]$lines.Add('      VT-d ......................... ENABLED (plus VT-x) - this is IOMMU on Intel and is')
        [void]$lines.Add('                                     required by FACEIT alongside VBS')
        [void]$lines.Add('      Secure Boot / TPM ............ Enabled')
        if ($p.CPU.Microarch -eq 'RaptorLake') {
            [void]$lines.Add('      Raptor Lake: verify the BIOS includes microcode 0x12B or later (instability')
            [void]$lines.Add('                   mitigation) and that no aggressive voltage override is applied.')
        }
    }

    [void]$lines.Add('')
    if ($p.Audio.HasUsbDac) {
        [void]$lines.Add('      Onboard audio ................ safe to disable - a USB DAC is your default endpoint')
        [void]$lines.Add('                                     (frees an IRQ and removes a driver)')
    }
    [void]$lines.Add('      Unused onboard controllers ... disable (extra SATA, secondary LAN)')

    if ($p.Boot.IsDualBoot) {
        [void]$lines.Add('')
        [void]$lines.Add('      DUAL-BOOT: if Secure Boot keys are externally managed (e.g. sbctl), do not')
        [void]$lines.Add('                 disturb the existing enrollment from the Windows side.')
    }

    [void](Add-OptManual -State $State -Id 'M-12' -Section '12' -Title 'BIOS checklist' -Detail ($lines -join "`n"))
}
