#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    One-shot, idempotent, detection-driven Windows 11 optimizer for competitive
    CS2 on FACEIT.

.DESCRIPTION
    Implements cs2-win11-optimization-spec.md. Every tweak is gated on a
    predicate over a detected hardware/software profile; a tweak whose
    preconditions are not met is skipped and logged with the reason, never
    applied blindly. Unknown hardware means skip, not guess.

    Nothing here disables Secure Boot, TPM, VBS or IOMMU. On a machine with a
    kernel anti-cheat installed those are dependencies, not optimization
    targets.

.PARAMETER Tier
    Cumulative. Aggressive includes Safe; Experimental includes both.

.PARAMETER DryRun
    Runs the full pipeline with every mutation chokepoint recording instead of
    writing, then emits the manifest that WOULD have been written. This
    deliberately goes further than spec 1.5.5 (which stops after the detection
    report) - detection is the part that is already safe, so stopping there
    exercises the wrong half.

.PARAMETER Rollback
    Replays a prior run's manifest in reverse.

.PARAMETER VerifyOnly
    Re-runs the verification pass against the last manifest without applying
    anything. This is how reboot-deferred changes (MMAgent, HwSchMode,
    HiberbootEnabled, pagefile, bcdedit) ever get a real PASS.

.PARAMETER CaptureProfile
    Writes the detected profile to a JSON file and exits. Attach it to bug
    reports; it doubles as a test fixture.

.PARAMETER ProfileFrom
    Loads a previously captured profile instead of probing hardware. Test
    injection - implies -DryRun.

.PARAMETER SkipRecovery
    Skips the belt-and-braces recovery artifacts: no System Restore point, and
    no per-key .reg exports. Implies -SkipRestorePoint.

    The change manifest and the append-and-flush journal are STILL written, so
    -Rollback continues to work exactly as before. That is deliberate: rollback
    is value-level from the manifest, and the .reg exports were never the undo
    mechanism - re-importing an exported key restores values deleted elsewhere
    and does not delete values added since.

    What you actually give up: the ability to recover if the manifest itself is
    lost or corrupted, and the coarse whole-system undo of a restore point.
    Worth it if you want a fast, quiet run; not worth it on a first run.

.EXAMPLE
    .\Optimize-CS2.ps1 -DryRun
    .\Optimize-CS2.ps1 -Tier Safe
    .\Optimize-CS2.ps1 -Tier Aggressive -Sections 7
    .\Optimize-CS2.ps1 -Rollback

.NOTES
    BGamerson's CS2 Optimizer Script
    https://github.com/bg9m9r/bgamerson-cs2-optimizer

    Copyright (c) 2026 BGamerson. Released under the MIT License.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. This script
    modifies system configuration. Review the -DryRun output before applying
    anything, and use it at your own risk.

    This notice lives in the script itself because the built file is designed to
    be downloaded and carried around on its own, with no LICENSE or README
    beside it.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Safe', 'Aggressive', 'Experimental')]
    [string]$Tier = 'Aggressive',

    [switch]$DryRun,
    [switch]$Rollback,
    [string]$ManifestPath = "$env:ProgramData\cs2-opt\manifest.json",
    [switch]$RemoveApps,
    [switch]$RemoveOneDrive,
    [switch]$BitLockerAcknowledged,
    [switch]$SkipRestorePoint,
    [switch]$SkipRecovery,
    [switch]$NoReboot,

    # --- additive (spec 1.1 contract preserved) ------------------------------
    [switch]$VerifyOnly,
    [string]$CaptureProfile,
    [string]$ProfileFrom,
    [string[]]$Sections,
    [string[]]$ExcludeSections,
    [switch]$AllowNetworkRestart
)

# StrictMode 3.0 rather than Latest: 3.0 still catches uninitialised variables
# and out-of-bounds indexing, but keeps property access on a hashtable
# non-fatal. That is what lets the detector "Unknown skeleton" pattern work -
# $p.CPU.HasVCache on a failed CPU detection must return $null, not throw.
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# '#Requires -Version 5.1' does NOT exclude PowerShell 7 - 7.x satisfies ">= 5.1".
# Under PS7 the Appx, DISM, MMAgent, NetAdapter, Defender, BitLocker,
# ScheduledTasks, Storage and PnpDevice modules all load through
# WindowsCompatibility implicit remoting, which returns deserialized objects
# (properties only, no methods), changes -ErrorAction semantics, and adds
# seconds per call. Chasing -UseWindowsPowerShell per module is a permanent
# maintenance tax for zero user benefit.
if ($PSVersionTable.PSEdition -eq 'Core') {
    throw @"
This script must run under Windows PowerShell 5.1, not PowerShell $($PSVersionTable.PSVersion).

Re-run with:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PSCommandPath"
"@
}

# ============================================================================
#  cs2-opt - built artifact. DO NOT EDIT THIS FILE.
#  Edit the sources under src\ and re-run build\Build-Script.ps1.
#
#  Source hash: sha256:19db4a0bda53dd03ff58f825fba6a8aa6fd8798b40f0159aa012a85db15d5b87
#  Files:
#    106CA43790D7593C  src\00-Header.ps1
#    5E85F066F791A29C  src\10-Core\State.ps1
#    567F9DA0D5E5A147  src\10-Core\Paths.ps1
#    D26A2EA65E13CF78  src\10-Core\Logging.ps1
#    B385F57CDF0828E9  src\10-Core\Decision.ps1
#    E5F0A4419CA30C86  src\10-Core\Invoke.ps1
#    998DABDDD49FCFCA  src\10-Core\Tier.ps1
#    FB14AF2C06EFD008  src\10-Core\ChangeRecord.ps1
#    27AC135E61F1124F  src\10-Core\RegistryBackup.ps1
#    6BB4BFDA6A178564  src\10-Core\Registry.ps1
#    663C47A14E71D20F  src\10-Core\Manifest.ps1
#    272EBCD9C93C2C26  src\10-Core\Verify.ps1
#    CE508ADBE21C91BB  src\10-Core\Rollback.ps1
#    237AA886E2279801  src\20-Interop\Interop-Bootstrap.ps1
#    9FBC799ADADB5E5D  src\20-Interop\Interop-Display.ps1
#    FA2945FA29982636  src\20-Interop\Interop-Mouse.ps1
#    8D701FE764D1153D  src\20-Interop\Interop-Cpu.ps1
#    B2108976E8C5A1DC  src\30-Detect\DetectorFramework.ps1
#    00C8862B6BB4EF13  src\30-Detect\Detect-Os.ps1
#    D56579C6BD6C2AC1  src\30-Detect\Detect-Cpu.ps1
#    5882AE88AABCB5C7  src\30-Detect\Detect-Gpu.ps1
#    7E9339B08586B833  src\30-Detect\Detect-Memory.ps1
#    F097AB5070C5C915  src\30-Detect\Detect-Storage.ps1
#    0A0675B06A0E73FB  src\30-Detect\Detect-Network.ps1
#    D7661D2E5643F48E  src\30-Detect\Detect-Display.ps1
#    8D482CFD73950FA8  src\30-Detect\Detect-Audio.ps1
#    4B8F3FCDDF680DEE  src\30-Detect\Detect-Input.ps1
#    42B5C57FFCA38292  src\30-Detect\Detect-Power.ps1
#    E49289BA51F049D2  src\30-Detect\Detect-Security.ps1
#    7507BA2D8085B539  src\30-Detect\Detect-Games.ps1
#    6564F352A187D794  src\30-Detect\Detect-Boot.ps1
#    4ED6CE74996C9084  src\30-Detect\Detect-Virtualization.ps1
#    54EEB73A25E4D044  src\30-Detect\Get-OptProfile.ps1
#    C4785743EB9F539E  src\40-Gates\GateMatrix.ps1
#    4870AEA35452CE13  src\40-Gates\Resolve-OptGates.ps1
#    192D86494DB34CDF  src\50-Sections\Section-00-SecurityFlight.ps1
#    0809E207CD0AA050  src\50-Sections\Section-02-Power.ps1
#    89E1D6528AFA2774  src\50-Sections\Section-03-Gpu.ps1
#    9ECDCE25A3C4903C  src\50-Sections\Section-04-Scheduler.ps1
#    AD055F0220275752  src\50-Sections\Section-05-MemStorage.ps1
#    76ACE5E56C01156B  src\50-Sections\Section-06-Input.ps1
#    BD9814E3F31DC9FA  src\50-Sections\Section-07-Network.ps1
#    ADC09C55E02AF0E5  src\50-Sections\Section-08-Background.ps1
#    BA7FCE35AB07DE0E  src\50-Sections\Section-09-Defender.ps1
#    9F124F0D27AB8655  src\50-Sections\Section-10-Vbs.ps1
#    39EFBF1A20B47008  src\50-Sections\Section-13-BadTweaks.ps1
#    A9B5B82735A3EAB5  src\50-Sections\Section-Manual.ps1
#    213C93034282CA0A  src\60-Report\Report-Detection.ps1
#    FB51DBE8B3A8034C  src\60-Report\Report-Console.ps1
#    55EB3AD05BBB5A18  src\60-Report\Report-Markdown.ps1
#    50FCA2676B57D171  src\90-Main.ps1
# ============================================================================
#region src\10-Core\State.ps1
<#
    Run-state container.

    One script-scope object, created once in 90-Main.ps1 and threaded
    implicitly. Named $script:Opt with the detected profile hanging off it as
    $script:Opt.Profile.

    Why not $Profile: $Profile is a PowerShell automatic variable holding the
    profile script path. It is not ReadOnly or Constant, so `$Profile = @{...}`
    SILENTLY SUCCEEDS and shadows the automatic in script scope - which is
    strictly worse than erroring, because downstream code reading $PROFILE
    quietly gets a hashtable. A build gate fails on any $Profile assignment.
#>

function New-OptState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Tier,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Parameters
    )

    $state = [ordered]@{
        RunId      = [guid]::NewGuid().ToString()
        StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
        Tier       = $Tier
        Parameters = $Parameters

        DryRun     = [bool]$Parameters['DryRun']

        Paths      = $null    # populated by Initialize-OptPaths
        Profile    = $null    # populated by Get-OptProfile

        # Capabilities are switched off by gate rows and then enforced at the
        # mutation chokepoints. This collapses roughly a dozen gating-matrix
        # rows (every "skip all HKLM\SOFTWARE\Policies\* writes" case) into a
        # single path predicate instead of one gate row per policy key.
        Capabilities = [ordered]@{
            Interop           = $true
            PolicyWrites      = $true
            HkcuWrites        = $true
            BcdEdit           = $true
            HypervisorOff     = $true
            AppxRemoval       = $false   # opt-in only, and report-only in v1
            ServiceDisable    = $true
            DisplayModeChange = $true
            NetworkRestart    = $false   # requires -AllowNetworkRestart
        }

        BlockedSections = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Decisions       = New-Object System.Collections.ArrayList
        Changes         = New-Object System.Collections.ArrayList
        Verification    = New-Object System.Collections.ArrayList
        Findings        = New-Object System.Collections.ArrayList
        Manual          = New-Object System.Collections.ArrayList

        RebootRequired  = $false
        LogoffRequired  = $false
        Aborted         = $false
        AbortReason     = $null

        # Resolved in Resolve-OptTargetUser. If the elevated identity is not
        # the interactive user, every HKCU write must be redirected to
        # HKU\<interactive-sid> or it lands in the wrong hive silently.
        TargetUser = [ordered]@{
            Sid        = $null
            Name       = $null
            IsCurrent  = $true
            HiveLoaded = $false
            HkcuRoot   = 'HKCU'
        }

        # Registry root redirection. Tests point these at a sandbox key; the
        # interlock in Resolve-OptRegistryPath refuses to write outside it.
        RegistryRootMap = @{}

        ChangeOrdinal = 0
        SectionStack  = New-Object 'System.Collections.Generic.List[string]'

        # Echo individual decisions to the console as they happen. Off by
        # default so the test suite stays quiet; 90-Main turns it on for real
        # runs. Without it a section prints its header and then nothing, which
        # reads as "this section did no work".
        ConsoleDecisions = $false
    }

    return $state
}

function Get-OptStateSnapshot {
    <#
        Serializable projection of the run state, for the manifest. Excludes
        the live .NET collections' identity and anything non-JSON-safe.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return [ordered]@{
        RunId          = $State.RunId
        StartedUtc     = $State.StartedUtc
        FinishedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        Tier           = $State.Tier
        DryRun         = $State.DryRun
        Parameters     = $State.Parameters
        Capabilities   = $State.Capabilities
        PSVersion      = $PSVersionTable.PSVersion.ToString()
        PSEdition      = $PSVersionTable.PSEdition
        ComputerName   = $env:COMPUTERNAME
        User           = "$env:USERDOMAIN\$env:USERNAME"
        TargetUserSid  = $State.TargetUser.Sid
        TargetUserName = $State.TargetUser.Name
        RebootRequired = $State.RebootRequired
        LogoffRequired = $State.LogoffRequired
        Aborted        = $State.Aborted
        AbortReason    = $State.AbortReason
    }
}
#endregion src\10-Core\State.ps1

#region src\10-Core\Paths.ps1
<#
    ProgramData layout and path normalization helpers.

        %ProgramData%\cs2-opt\
          manifest.json                     <- spec 1.1 default, latest run
          logs\run-<ts>.log                 <- transcript
          backup\<ts>\*.reg                 <- per-key reg exports
          runs\<ts>-<runid>\
             changes.jsonl                  <- append-and-flush per change
             manifest.json                  <- consolidated
             report.md
#>

function Initialize-OptPaths {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [string]$Root = "$env:ProgramData\cs2-opt",
        [string]$ManifestPath
    )

    $stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $runDir  = Join-Path $Root ("runs\{0}-{1}" -f $stamp, $State.RunId.Substring(0, 8))

    $paths = [ordered]@{
        Root         = $Root
        Logs         = Join-Path $Root 'logs'
        Backup       = Join-Path $Root ("backup\{0}" -f $stamp)
        RunDir       = $runDir
        Journal      = Join-Path $runDir 'changes.jsonl'
        RunManifest  = Join-Path $runDir 'manifest.json'
        Report       = Join-Path $runDir 'report.md'
        Transcript   = Join-Path $Root ("logs\run-{0}.log" -f $stamp)
        Manifest     = if ($ManifestPath) { $ManifestPath } else { Join-Path $Root 'manifest.json' }
        Stamp        = $stamp
    }

    foreach ($d in @($paths.Root, $paths.Logs, $paths.Backup, $paths.RunDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    $State.Paths = $paths
    return $paths
}

function ConvertTo-OptNormalizedPath {
    <#
        Steam's HKCU SteamPath is stored lowercase with FORWARD slashes
        (verified: 'c:/program files (x86)/steam'). Sections 3.3 and 9 use these
        paths as registry value NAMES and Defender exclusion strings, where
        casing and separators both matter - Windows writes the real casing, so
        a lowercase duplicate reads as a second, separate entry.

        Normalize separators, resolve to a full path, then re-case from the
        filesystem when the path actually exists.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

    $p = $Path.Replace('/', '\').Trim().TrimEnd('\')
    try { $p = [System.IO.Path]::GetFullPath($p) } catch { return $null }

    $trueCase = Get-OptTrueCasePath -Path $p
    if ($trueCase) { return $trueCase.TrimEnd('\') }

    return $p
}

function Get-OptTrueCasePath {
    <#
        Returns the path as the filesystem actually spells it.

        Get-Item does NOT do this - it echoes back whatever casing you handed
        it, so 'c:/program files (x86)/steam' stays lowercase. The only way to
        recover real casing is to ask each parent directory to enumerate the
        child and take the name it reports.

        This matters because section 3.3 writes the cs2.exe path as a registry
        VALUE NAME and section 9 passes library paths to Add-MpPreference.
        Windows writes those with real casing, so a lowercase variant reads as a
        second, separate entry - which breaks idempotency in a way that is
        invisible in the report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $root = [System.IO.Path]::GetPathRoot($Path)
        if (-not $root) { return $null }

        $rest = $Path.Substring($root.Length).Trim('\')
        if ([string]::IsNullOrEmpty($rest)) { return $root.ToUpperInvariant() }

        $current = $root.ToUpperInvariant()
        foreach ($part in ($rest -split '\\')) {
            $matched = @([System.IO.Directory]::GetFileSystemEntries($current, $part))
            if ($matched.Count -eq 0) { return $null }
            $current = $matched[0]
        }
        return $current
    }
    catch {
        return $null
    }
}

function Test-OptPathUnder {
    <#
        Case-insensitive containment test that is not fooled by a common
        prefix ('C:\Foo' must not be considered under 'C:\FooBar').
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory)][string]$Parent
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    $a = $Path.TrimEnd('\', '/')
    $b = $Parent.TrimEnd('\', '/')

    if ($a.Equals($b, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $a.StartsWith($b + '\', [StringComparison]::OrdinalIgnoreCase)
}
#endregion src\10-Core\Paths.ps1

#region src\10-Core\Logging.ps1
<#
    Console + transcript logging.

    Everything user-facing goes through Write-Host. That is deliberate, not
    laziness: Start-Transcript only captures the host output and information
    streams. Write-Verbose output does NOT appear in a transcript unless the
    caller passed -Verbose, so routing user-facing text through Write-Verbose
    would produce log files that are missing the very lines you need when
    diagnosing a failed run from the log alone (spec 1.5).
#>

function Start-OptTranscript {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    try {
        # Start-Transcript throws if one is already running in this session.
        Start-Transcript -Path $State.Paths.Transcript -Force -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "Could not start transcript: $($_.Exception.Message)"
        return $false
    }
}

function Stop-OptTranscript {
    [CmdletBinding()]
    param()
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}

function Write-OptLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Good', 'Warn', 'Error', 'Detail', 'Header', 'Plain')]
        [string]$Level = 'Info'
    )

    switch ($Level) {
        'Header' {
            Write-Host ''
            Write-Host $Message -ForegroundColor Cyan
            Write-Host ('-' * [Math]::Min(78, [Math]::Max(8, $Message.Length))) -ForegroundColor DarkCyan
        }
        'Good'   { Write-Host "  [ OK ]  $Message" -ForegroundColor Green }
        'Warn'   { Write-Host "  [WARN]  $Message" -ForegroundColor Yellow }
        'Error'  { Write-Host "  [FAIL]  $Message" -ForegroundColor Red }
        'Detail' { Write-Host "          $Message" -ForegroundColor DarkGray }
        'Plain'  { Write-Host $Message }
        default  { Write-Host "  [ .. ]  $Message" -ForegroundColor Gray }
    }
}

function Write-OptBanner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Deliberately pure ASCII - no Unicode box-drawing. The build gate rejects
    # non-ASCII source because Windows PowerShell 5.1 reads a BOM-less file as
    # ANSI, which would turn any such character into mojibake in the built
    # single-file script. Widest line is 66 chars, so it fits an 80-column
    # console without wrapping.
    $logo = @(
        ' ____    ____     _     __  __  _____  ____   ____    ___   _   _ '
        '| __ )  / ___|   / \   |  \/  || ____||  _ \ / ___|  / _ \ | \ | |'
        '|  _ \ | |  _   / _ \  | |\/| ||  _|  | |_) |\___ \ | | | ||  \| |'
        '| |_) || |_| | / ___ \ | |  | || |___ |  _ <  ___) || |_| || |\  |'
        '|____/  \____|/_/   \_\|_|  |_||_____||_| \_\|____/  \___/ |_| \_|'
    )

    # Vertical gradient: dimmer at the top and bottom, brightest through the
    # middle.
    $shades = @('DarkCyan', 'Cyan', 'Cyan', 'Cyan', 'DarkCyan')

    Write-Host ''
    for ($i = 0; $i -lt $logo.Count; $i++) {
        Write-Host ('  ' + $logo[$i]) -ForegroundColor $shades[$i]
    }

    Write-Host ''
    Write-Host "        C S 2    O P T I M I Z E R    S C R I P T" -ForegroundColor Yellow
    Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan

    if ($State.DryRun) {
        Write-Host '   DRY RUN ' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
        Write-Host ' nothing will be modified' -ForegroundColor Yellow
    }
    else {
        Write-Host '  Tier ' -ForegroundColor Gray -NoNewline
        Write-Host $State.Tier -ForegroundColor Green
    }

    Write-Host "  Run  $($State.RunId)" -ForegroundColor DarkGray
    Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan
}
#endregion src\10-Core\Logging.ps1

#region src\10-Core\Decision.ps1
<#
    The single decision sink.

    Gate outcomes, tier skips, unsupported-driver-keyword skips,
    already-correct no-ops, hard findings and manual checklist items ALL land
    here. The spec 1.5.5 console table and the spec 14 markdown report are
    projections of this one list.

    That is what makes "the report is generated from the same source of truth
    as the gates" a structural property rather than an aspiration - there is no
    second place to record why something did or did not happen.
#>

function Add-OptDecision {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,

        # Stable identifier, e.g. 'G-2.2-X3D' (gate) or 'S-7.1-RSS' (section).
        [Parameter(Mandatory)][string]$Id,

        [Parameter(Mandatory)][string]$Section,

        # On            - gate evaluated, tweak permitted
        # Off           - gate blocked it (carries the reason)
        # NoOp          - already in the desired state; NOT a change
        # Applied       - a change record was emitted
        # Finding       - a problem to fix, not a tweak (e.g. VBS off on FACEIT)
        # Manual        - checklist item for the user
        # Failed        - attempted and errored
        # Unverified    - applied but effect cannot be confirmed on this build
        [Parameter(Mandatory)]
        [ValidateSet('On', 'Off', 'NoOp', 'Applied', 'Finding', 'Manual', 'Failed', 'Unverified')]
        [string]$Decision,

        [Parameter(Mandatory)][AllowEmptyString()][string]$Reason,

        [string]$Title,
        [string]$Detail,

        [ValidateSet('Info', 'Warning', 'Error', 'Critical')]
        [string]$Severity = 'Info'
    )

    $entry = [pscustomobject][ordered]@{
        Id        = $Id
        Section   = $Section
        Title     = $Title
        Decision  = $Decision
        Reason    = $Reason
        Detail    = $Detail
        Severity  = $Severity
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
    }

    [void]$State.Decisions.Add($entry)

    if ($Decision -eq 'Finding') {
        [void]$State.Findings.Add($entry)
    }
    elseif ($Decision -eq 'Manual') {
        [void]$State.Manual.Add($entry)
    }

    # Echo the outcomes worth watching scroll past.
    #
    # NoOp and Off stay silent on purpose: they are the overwhelming majority
    # (roughly 110 of ~200 decisions on a typical run) and printing them would
    # bury the handful of lines that actually matter. They are still counted in
    # the per-section summary and listed in full in the markdown report.
    if ($State['ConsoleDecisions']) {
        $line = if ($Reason) { [string]$Reason } else { [string]$Title }
        if ($line.Length -gt 104) { $line = $line.Substring(0, 101) + '...' }

        switch ($Decision) {
            'Applied'    { Write-Host ('    + {0,-6} {1}' -f $Section, $line) -ForegroundColor DarkGray }
            'Failed'     { Write-Host ('    ! {0,-6} {1}' -f $Section, $line) -ForegroundColor Red }
            'Finding'    { Write-Host ('    ! {0,-6} {1}' -f $Section, $line) -ForegroundColor Yellow }
            'Unverified' { Write-Host ('    ? {0,-6} {1}' -f $Section, $line) -ForegroundColor DarkYellow }
        }
    }

    return $entry
}

function Add-OptFinding {
    <#
        A hard finding is a problem the user must fix, not a tweak that
        succeeded. Spec 10.2: on a FACEIT machine with VBS not running, the
        correct output is a blocking problem - never "optimized".
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Reason,
        [string]$Detail,
        [ValidateSet('Warning', 'Error', 'Critical')][string]$Severity = 'Error'
    )

    return Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Finding' `
        -Title $Title -Reason $Reason -Detail $Detail -Severity $Severity
}

function Add-OptManual {
    <#
        Checklist item the script deliberately does not automate - AMD Adrenalin
        and the NVIDIA profile store are opaque binary blobs (spec 3.4 / 3.5),
        Steam's localconfig.vdf is cached in memory and overwritten on exit
        (spec 11.1), and BIOS settings are not scriptable at all (spec 12).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [string]$Reason = 'not safely scriptable - see report checklist'
    )

    return Add-OptDecision -State $State -Id $Id -Section $Section -Decision 'Manual' `
        -Title $Title -Reason $Reason -Detail $Detail -Severity 'Info'
}

function Write-OptSectionSummary {
    <#
        One tally line per section, so the outcomes that are deliberately not
        echoed individually (already-correct and gated-off) are still visible
        as counts rather than vanishing.

        Counts only section decisions (S-*), not gate rows (G-*) - the gate
        matrix already reported itself in the detection report, and folding it
        in here would double-count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Section
    )

    if (-not $State['ConsoleDecisions']) { return }

    $rows = @($State.Decisions | Where-Object {
        $_.Id -like 'S-*' -and (Test-OptSectionMatch -Section $_.Section -Patterns @($Section))
    })
    if ($rows.Count -eq 0) {
        Write-Host '    (nothing applicable on this machine)' -ForegroundColor DarkGray
        return
    }

    $applied = @($rows | Where-Object { $_.Decision -eq 'Applied' }).Count
    $noop    = @($rows | Where-Object { $_.Decision -eq 'NoOp'    }).Count
    $off     = @($rows | Where-Object { $_.Decision -eq 'Off'     }).Count
    $failed  = @($rows | Where-Object { $_.Decision -eq 'Failed'  }).Count

    $verb = if ($State.DryRun) { 'planned' } else { 'applied' }
    $parts = @("$applied $verb")
    if ($noop   -gt 0) { $parts += "$noop already correct" }
    if ($off    -gt 0) { $parts += "$off skipped" }
    if ($failed -gt 0) { $parts += "$failed FAILED" }

    Write-Host ('    -> ' + ($parts -join ', ')) -ForegroundColor $(if ($failed -gt 0) { 'Yellow' } else { 'DarkCyan' })
}

function Get-OptDecisionsBySection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [string]$Section
    )

    # Leading comma survives PowerShell's single-element return unroll, so
    # callers always get an array to .Count / iterate.
    if ($Section) {
        return , @($State.Decisions | Where-Object { $_.Section -eq $Section })
    }
    return , @($State.Decisions)
}
#endregion src\10-Core\Decision.ps1

#region src\10-Core\Invoke.ps1
<#
    Native command and cmdlet mutation chokepoints.

    Every external tool (reg.exe, powercfg, bcdedit, netsh, fsutil) and every
    mutating cmdlet call in the entire script funnels through this file. Two
    reasons:

    1. -DryRun is enforced HERE, at a chokepoint, rather than at each of the
       several hundred call sites. Per-call-site enforcement always eventually
       leaks; a chokepoint cannot.

    2. Native stderr handling. With $ErrorActionPreference = 'Stop' (which this
       script sets globally), a native command that writes to stderr and is
       captured with 2>&1 produces ErrorRecord objects that THROW.
       `bcdedit /deletevalue useplatformclock` writes "The specified element was
       not found" to stderr and exits non-zero - and spec 4.3 explicitly
       requires tolerating exactly that. So every native call must run with a
       locally relaxed preference.
#>

function ConvertTo-OptArgumentString {
    <#
        Joins an argument array into a single Windows command line using the
        CommandLineToArgvW quoting rules.

        Needed because ProcessStartInfo.ArgumentList is .NET Core 2.1+ and this
        script targets Windows PowerShell 5.1 (.NET Framework 4.x), where only
        the flat .Arguments string exists.

        Rules: an argument containing whitespace or a double quote is wrapped in
        quotes; backslashes are doubled only when they immediately precede a
        quote (including the closing one); embedded quotes are backslash-escaped.

        This matters for real inputs here - registry paths with spaces
        ('HKLM\SOFTWARE\Microsoft\Windows NT\...') and the Steam library path
        ('C:\Program Files (x86)\Steam\...') both go to reg.exe as arguments.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList)

    $parts = foreach ($arg in $ArgumentList) {
        $a = [string]$arg

        if ($a.Length -gt 0 -and $a.IndexOfAny(@(' ', "`t", '"', "`n", "`v")) -lt 0) {
            $a
            continue
        }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        for ($i = 0; $i -lt $a.Length; $i++) {
            $slashes = 0
            while ($i -lt $a.Length -and $a[$i] -eq '\') { $slashes++; $i++ }

            if ($i -eq $a.Length) {
                # Trailing backslashes precede the closing quote - double them.
                [void]$sb.Append('\' * ($slashes * 2))
                break
            }
            elseif ($a[$i] -eq '"') {
                [void]$sb.Append('\' * ($slashes * 2 + 1))
                [void]$sb.Append('"')
            }
            else {
                [void]$sb.Append('\' * $slashes)
                [void]$sb.Append($a[$i])
            }
        }
        [void]$sb.Append('"')
        $sb.ToString()
    }

    return ($parts -join ' ')
}

function Invoke-OptNativeCommand {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,

        # Read-only probes must run even under -DryRun; that is the whole point
        # of a dry run that exercises the full pipeline.
        [switch]$ReadOnly,

        [string]$Purpose,
        [int[]]$SuccessExitCodes = @(0)
    )

    if (-not $ReadOnly -and $State.DryRun) {
        return @{
            ExitCode = 0
            StdOut   = ''
            StdErr   = ''
            Success  = $true
            DryRun   = $true
            Command  = "$FilePath $($ArgumentList -join ' ')"
        }
    }

    $resolved = $FilePath
    if (-not [System.IO.Path]::IsPathRooted($resolved)) {
        $cmd = Get-Command $FilePath -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($cmd) { $resolved = $cmd.Source }
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $resolved
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    # ProcessStartInfo.ArgumentList does not exist on .NET Framework, which is
    # what Windows PowerShell 5.1 runs on - it is .NET Core 2.1+ only. Build
    # the command line by hand with CommandLineToArgvW quoting rules.
    $psi.Arguments              = ConvertTo-OptArgumentString -ArgumentList $ArgumentList

    $stdout = ''
    $stderr = ''
    $code   = -1

    # Locally relaxed: a non-zero exit or stderr output is data here, not a
    # terminating condition. See the bcdedit note above.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        # Read both streams before WaitForExit, or a full pipe buffer deadlocks.
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        $code = $proc.ExitCode
        $proc.Dispose()
    }
    catch {
        $stderr = $_.Exception.Message
        $code   = -1
    }
    finally {
        $ErrorActionPreference = $previous
    }

    return @{
        ExitCode = $code
        StdOut   = $stdout
        StdErr   = $stderr
        Success  = ($SuccessExitCodes -contains $code)
        DryRun   = $false
        Command  = "$FilePath $($ArgumentList -join ' ')"
        Purpose  = $Purpose
    }
}

function Invoke-OptCmdletChange {
    <#
        Chokepoint for mutating cmdlets that have no external-tool equivalent -
        Disable-ScheduledTask, Set-Service, Disable-MMAgent, Add-MpPreference,
        Set-NetAdapterAdvancedProperty, and so on.

        The caller supplies a scriptblock; under -DryRun it is never invoked.
        Returns a result hashtable rather than throwing, so a single failed
        tweak never aborts a section.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Description,
        [switch]$ReadOnly
    )

    if (-not $ReadOnly -and $State.DryRun) {
        return @{ Success = $true; DryRun = $true; Output = $null; Error = $null; Description = $Description }
    }

    try {
        $out = & $Action
        return @{ Success = $true; DryRun = $false; Output = $out; Error = $null; Description = $Description }
    }
    catch {
        return @{ Success = $false; DryRun = $false; Output = $null; Error = $_.Exception.Message; Description = $Description }
    }
}

function Get-OptCommandLines {
    <#
        Splits captured stdout into trimmed, non-empty lines. Every
        external-tool parser in this script starts here, which keeps the
        line-splitting behaviour identical across powercfg, bcdedit, netsh and
        fsutil - and makes all of them testable against captured fixtures.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return , @() }
    return , @($Text -split "`r?`n" | ForEach-Object { $_.TrimEnd() } | Where-Object { $_.Trim().Length -gt 0 })
}
#endregion src\10-Core\Invoke.ps1

#region src\10-Core\Tier.ps1
<#
    Tier gating and section enablement.

    Tiers are cumulative (spec 1.2.10): Aggressive includes Safe, Experimental
    includes both. 'Manual' and 'Report' are pseudo-tiers that always run -
    they emit text, never changes.
#>

function Get-OptTierRank {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Tier)

    switch ($Tier) {
        'Safe'         { return 0 }
        'Aggressive'   { return 1 }
        'Experimental' { return 2 }
        'Manual'       { return -1 }
        'Report'       { return -1 }
        default        { return 99 }
    }
}

function Test-OptTier {
    <#
        Is a tweak tagged $Required permitted at the run's configured tier?
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Required
    )

    $req = Get-OptTierRank -Tier $Required
    if ($req -lt 0) { return $true }          # Manual / Report always run
    if ($req -eq 99) { return $false }        # unknown tag - fail closed

    return ($req -le (Get-OptTierRank -Tier $State.Tier))
}

function Test-OptSectionEnabled {
    <#
        Section gating, in precedence order:
          1. -Sections        (allow-list; if given, nothing else runs)
          2. -ExcludeSections (deny-list)
          3. BlockedSections  (populated by the gate matrix)

        Matching is PREFIX-based on the dotted section number, so blocking '8'
        blocks 8.1 through 8.9, while blocking '3.5' blocks only 3.5. Without
        prefix matching, a gate row that blocks a whole section would have to
        enumerate every subsection by hand.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Section
    )

    $only    = $State.Parameters['Sections']
    $exclude = $State.Parameters['ExcludeSections']

    if ($only -and $only.Count -gt 0) {
        if (-not (Test-OptSectionMatch -Section $Section -Patterns $only)) { return $false }
    }

    if ($exclude -and $exclude.Count -gt 0) {
        if (Test-OptSectionMatch -Section $Section -Patterns $exclude) { return $false }
    }

    foreach ($blocked in $State.BlockedSections) {
        if (Test-OptSectionMatch -Section $Section -Patterns @($blocked)) { return $false }
    }

    return $true
}

function Test-OptSectionMatch {
    <#
        '8' matches '8', '8.1', '8.10'.  '3.5' matches '3.5' and '3.5.1' but
        NOT '3.55' - the boundary check on the next character is what stops
        '3.5' from swallowing '3.55'.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Patterns
    )

    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }

        # Strip any leading non-digit prefix so '7', 'S7', 's7' and the section
        # symbol all mean the same thing. Done with a regex rather than a
        # TrimStart char list on purpose: the section symbol is non-ASCII, and
        # Windows PowerShell 5.1 reads a BOM-less file as ANSI - so the literal
        # would arrive as two characters and TrimStart would throw.
        $p = ($pat.Trim() -replace '^[^\d]+', '').Trim()

        if ($Section.Equals($p, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($Section.StartsWith($p + '.', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Block-OptSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Section
    )
    [void]$State.BlockedSections.Add($Section)
}

function Test-OptCapability {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not $State.Capabilities.Contains($Name)) { return $false }
    return [bool]$State.Capabilities[$Name]
}
#endregion src\10-Core\Tier.ps1

#region src\10-Core\ChangeRecord.ps1
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
        a naive rollback would write garbage or throw. Section 8.3 writes
        HKCU\Control Panel\Desktop\UserPreferencesMask, which is binary, so this
        is a live path, not a hypothetical.

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
#endregion src\10-Core\ChangeRecord.ps1

#region src\10-Core\RegistryBackup.ps1
<#
    Per-key registry export.

    A deliberate reading of spec 1.2.4: it says "reg export the PARENT key", but
    taken literally that is wrong and occasionally catastrophic - the parent of
    HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters (section 6.3) is
    ...\Services, which exports hundreds of megabytes. This exports the EXACT
    key being written, deduplicated per run.

    Equally important, stated plainly in the report: these .reg files are a
    MANUAL LAST RESORT, not the rollback mechanism. Re-importing an exported key
    restores values that were deleted elsewhere and does NOT delete values added
    since. Rollback is value-level, from the manifest.
#>

function Backup-OptRegistryKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)][string]$SubKey,
        [int]$MaxSizeMB = 20
    )

    if ($State.DryRun) { return $null }
    if (-not $State.Paths -or -not $State.Paths.Backup) { return $null }

    # -SkipRecovery drops the .reg exports only. The manifest and the journal
    # are untouched, so value-level rollback still works - these files were
    # always a manual last resort, never the undo mechanism.
    if ($State.Parameters['SkipRecovery']) { return $null }

    $full = "$Hive\$SubKey"

    if (-not $State.Contains('BackupDone')) {
        $State['BackupDone'] = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    }
    # Section 8.7 writes eight values under one Explorer\Advanced key; without
    # dedupe that is eight identical exports.
    if ($State['BackupDone'].Contains($full)) { return $null }

    $safe = ($full -replace '[\\/:*?"<>|]', '_')
    if ($safe.Length -gt 150) { $safe = $safe.Substring(0, 150) }
    $file = Join-Path $State.Paths.Backup "$safe.reg"

    $result = Invoke-OptNativeCommand -State $State -FilePath 'reg.exe' `
        -ArgumentList @('export', $full, $file, '/y') -Purpose "backup $full"

    [void]$State['BackupDone'].Add($full)

    if (-not $result.Success) {
        # Exit 1 here almost always means the key does not exist yet, which is a
        # perfectly normal precondition - the manifest records ExistedBefore and
        # rollback deletes rather than restores.
        return $null
    }

    if (Test-Path -LiteralPath $file) {
        $sizeMB = (Get-Item -LiteralPath $file).Length / 1MB
        if ($sizeMB -gt $MaxSizeMB) {
            Write-OptLog -Level Warn ("Registry backup for {0} is {1:N0} MB - removing it. Value-level rollback from the manifest still covers this change." -f $full, $sizeMB)
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            return $null
        }
        return $file
    }

    return $null
}
#endregion src\10-Core\RegistryBackup.ps1

#region src\10-Core\Registry.ps1
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
#endregion src\10-Core\Registry.ps1

#region src\10-Core\Manifest.ps1
<#
    Manifest read/write.

    Two artefacts per run:
      runs\<ts>-<id>\changes.jsonl   append-and-flush after EVERY change
      runs\<ts>-<id>\manifest.json   consolidated, rewritten at section boundaries

    %ProgramData%\cs2-opt\manifest.json (the spec 1.1 default path) is a copy of
    the latest run's manifest, which is what -Rollback picks up by default.
#>

function Write-OptManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [switch]$Final
    )

    if ($State.DryRun -and -not $Final) { return }
    if (-not $State.Paths) { return }

    $manifest = [ordered]@{
        SchemaVersion = 1
        Tool          = [ordered]@{ Name = 'cs2-opt'; Version = '1.0.0' }
        Run           = Get-OptStateSnapshot -State $State
        Fingerprint   = $(if ($State.Profile) { $State.Profile.Fingerprint } else { $null })
        Profile       = $State.Profile
        Gates         = @($State.Decisions | Where-Object { $_.Id -like 'G-*' })
        Changes       = @($State.Changes)
        Findings      = @($State.Findings)
        Manual        = @($State.Manual)
        Verification  = @($State.Verification)
        Decisions     = @($State.Decisions)
    }

    try {
        # -Depth is mandatory: the default is 2 and this object is far deeper,
        # which would silently serialize nested nodes as the literal string
        # "System.Collections.Hashtable".
        $json = $manifest | ConvertTo-Json -Depth 12

        # Write to a temp file then move, so an interrupted write cannot leave a
        # truncated manifest where a valid one used to be.
        $tmp = "$($State.Paths.RunManifest).tmp"
        Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $State.Paths.RunManifest -Force -ErrorAction Stop

        if ($Final -and -not $State.DryRun) {
            Copy-Item -LiteralPath $State.Paths.RunManifest -Destination $State.Paths.Manifest -Force -ErrorAction Stop
        }
    }
    catch {
        Write-OptLog -Level Warn "Could not write manifest: $($_.Exception.Message)"
    }
}

function Read-OptManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "No manifest found at '$Path'. Nothing to roll back."
    }

    try {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Manifest at '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

function Test-OptFingerprintMatch {
    <#
        Spec 1.5.6 re-run safety.

        Match    - normal idempotent re-run
        Mismatch - hardware changed; previously-applied vendor-specific tweaks
                   may now target absent hardware
        Absent   - first run
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowNull()]$StoredFingerprint,
        [Parameter(Mandatory)][System.Collections.IDictionary]$CurrentFingerprint
    )

    if (-not $StoredFingerprint) {
        return @{ Status = 'Absent'; Matches = $true; Detail = 'no prior run recorded' }
    }

    $storedHash = if ($StoredFingerprint -is [System.Collections.IDictionary]) { $StoredFingerprint['Hash'] } else { $StoredFingerprint.Hash }

    if ([string]$storedHash -eq [string]$CurrentFingerprint.Hash) {
        return @{ Status = 'Match'; Matches = $true; Detail = 'hardware unchanged since the last run' }
    }

    $changed = @()
    $storedComponents = if ($StoredFingerprint -is [System.Collections.IDictionary]) { $StoredFingerprint['Components'] } else { $StoredFingerprint.Components }
    if ($storedComponents) {
        foreach ($k in $CurrentFingerprint.Components.Keys) {
            $old = if ($storedComponents -is [System.Collections.IDictionary]) { $storedComponents[$k] } else { $storedComponents.$k }
            $new = $CurrentFingerprint.Components[$k]
            if ([string]$old -ne [string]$new) { $changed += "${k}: '$old' -> '$new'" }
        }
    }

    return @{
        Status  = 'Mismatch'
        Matches = $false
        Detail  = "hardware changed since the last run: $($changed -join '; ')"
        Changed = $changed
    }
}
#endregion src\10-Core\Manifest.ps1

#region src\10-Core\Verify.ps1
<#
    Verification pass (spec 1.2.9 / 14).

    Re-reads every changed value and reports PASS/FAIL.

    The honest part is VerifyMode. Several changes cannot be confirmed before a
    reboot, and the spec calls this out for MMAgent specifically: Get-MMAgent
    reports the new value immediately, but neither change takes real effect
    until the compression store is drained. The same is true of HwSchMode,
    HiberbootEnabled, Win32PrioritySeparation, the pagefile, and every bcdedit
    change.

    Those are marked PostReboot and reported as DEFERRED, never as PASS. The
    -VerifyOnly switch re-runs this pass after the reboot, which is the only way
    they ever get a real result.
#>

function Invoke-OptVerification {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [array]$Changes,
        [switch]$PostReboot
    )

    if (-not $Changes) { $Changes = @($State.Changes) }

    $summary = @{ Pass = 0; Fail = 0; Deferred = 0; Skipped = 0; Planned = 0 }

    # Under -DryRun nothing was written, so re-reading every value would report
    # FAIL for the entire planned change set - which looks like a catastrophe and
    # means nothing. Report them as PLANNED instead.
    if ($State.DryRun) {
        foreach ($change in $Changes) {
            $summary.Planned++
            [void]$State.Verification.Add([pscustomobject][ordered]@{
                ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
                Path = $change.Path; Name = $change.Name
                Result = 'PLANNED'; Expected = $change.NewValue; Actual = $change.OldValue
                Detail = 'dry run - not applied, so not verified'
            })
        }
        return $summary
    }

    foreach ($change in $Changes) {
        $mode = [string]$change.VerifyMode

        if ($mode -eq 'None') {
            $summary.Skipped++
            continue
        }

        if ($mode -eq 'PostReboot' -and -not $PostReboot) {
            $summary.Deferred++
            [void]$State.Verification.Add([pscustomobject][ordered]@{
                ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
                Path = $change.Path; Name = $change.Name
                Result = 'DEFERRED'; Expected = $change.NewValue; Actual = $null
                Detail = 'takes effect on reboot - re-run with -VerifyOnly afterwards'
            })
            continue
        }

        $result = Test-OptChangeApplied -State $State -Change $change

        if ($result.Result -eq 'PASS') { $summary.Pass++ }
        elseif ($result.Result -eq 'FAIL') { $summary.Fail++ }
        else { $summary.Skipped++ }

        [void]$State.Verification.Add([pscustomobject][ordered]@{
            ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
            Path = $change.Path; Name = $change.Name
            Result = $result.Result; Expected = $result.Expected; Actual = $result.Actual
            Detail = $result.Detail
        })
    }

    return $summary
}

function Test-OptChangeApplied {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)]$Change
    )

    switch ([string]$Change.Type) {

        'Registry' {
            $target = $Change.Target
            $hive   = [string]$target.Hive
            $sub    = [string]$target.SubKey
            $name   = [string]$target.Name
            $kind   = [string]$target.ValueKind

            $info = Get-OptRegistryValueInfo -State $State -Hive $hive -SubKey $sub -Name $name
            $expected = ConvertFrom-OptStorableValue -Value $Change.NewValue

            if (-not $info.ValueExists) {
                return @{ Result = 'FAIL'; Expected = (Format-OptValueForLog $expected); Actual = '<absent>'; Detail = 'value is not present after apply' }
            }

            $match = Compare-OptRegistryData -Type $kind -Current $info.Value -Desired (ConvertTo-OptRegistryData -Type $kind -Value $expected)
            return @{
                Result   = $(if ($match) { 'PASS' } else { 'FAIL' })
                Expected = (Format-OptValueForLog $expected)
                Actual   = (Format-OptValueForLog $info.Value)
                Detail   = $null
            }
        }

        'RegistryValueDelete' {
            $target = $Change.Target
            $info = Get-OptRegistryValueInfo -State $State -Hive ([string]$target.Hive) -SubKey ([string]$target.SubKey) -Name ([string]$target.Name)
            return @{
                Result   = $(if ($info.ValueExists) { 'FAIL' } else { 'PASS' })
                Expected = '<absent>'
                Actual   = $(if ($info.ValueExists) { (Format-OptValueForLog $info.Value) } else { '<absent>' })
                Detail   = $null
            }
        }

        'ScheduledTask' {
            $target = $Change.Target
            $task = Get-ScheduledTask -TaskPath ([string]$target.TaskPath) -TaskName ([string]$target.TaskName) -ErrorAction SilentlyContinue
            if (-not $task) { return @{ Result = 'SKIP'; Expected = 'Disabled'; Actual = '<not present>'; Detail = 'task no longer present' } }
            return @{
                Result   = $(if ([string]$task.State -eq 'Disabled') { 'PASS' } else { 'FAIL' })
                Expected = 'Disabled'; Actual = [string]$task.State; Detail = $null
            }
        }

        'Service' {
            $target = $Change.Target
            $svc = Get-Service -Name ([string]$target.ServiceName) -ErrorAction SilentlyContinue
            if (-not $svc) { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = '<not present>'; Detail = 'service no longer present' } }
            return @{
                Result   = $(if ([string]$svc.StartType -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = [string]$Change.NewValue; Actual = [string]$svc.StartType; Detail = $null
            }
        }

        'MMAgent' {
            $target = $Change.Target
            try {
                $agent = Get-MMAgent -ErrorAction Stop
                $actual = $agent.($target.Field)
                return @{
                    Result   = $(if ([bool]$actual -eq [bool]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                    Expected = [string]$Change.NewValue; Actual = [string]$actual
                    Detail   = 'reported immediately but not fully effective until reboot'
                }
            }
            catch { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = $_.Exception.Message } }
        }

        'PowerCfgActive' {
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/getactivescheme') -ReadOnly
            $schemes = Get-OptPowerSchemes -Text $r.StdOut
            $active = @($schemes)[0]
            return @{
                Result   = $(if ($active -and [string]$active.Guid -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = [string]$Change.NewValue
                Actual   = $(if ($active) { $active.Guid } else { '<unknown>' })
                Detail   = $null
            }
        }

        'NetAdapterProperty' {
            $target = $Change.Target
            try {
                $prop = Get-NetAdapterAdvancedProperty -Name ([string]$target.AdapterName) `
                            -RegistryKeyword ([string]$target.Keyword) -ErrorAction Stop
                $actual = @($prop.RegistryValue)[0]
                return @{
                    Result   = $(if ([string]$actual -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                    Expected = [string]$Change.NewValue; Actual = [string]$actual; Detail = $null
                }
            }
            catch { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = 'adapter or keyword no longer present' } }
        }

        'DefenderExclusion' {
            try {
                $pref = Get-MpPreference -ErrorAction Stop
                $target = $Change.Target
                # Get-MpPreference returns $null (not @()) when a list is empty,
                # so .Count would throw under StrictMode without the @() wrap.
                $list = @(if ([string]$target.Kind -eq 'Path') { $pref.ExclusionPath } else { $pref.ExclusionProcess })
                $present = [bool](@($list | Where-Object { [string]$_ -eq [string]$Change.NewValue }).Count)
                return @{
                    Result   = $(if ($present) { 'PASS' } else { 'FAIL' })
                    Expected = [string]$Change.NewValue
                    Actual   = $(if ($present) { [string]$Change.NewValue } else { '<not in exclusion list>' })
                    Detail   = $(if (-not $present) { 'Tamper Protection can silently reject exclusion changes' } else { $null })
                }
            }
            catch { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = $_.Exception.Message } }
        }

        'FsutilBehavior' {
            $target = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
                 -ArgumentList @('behavior', 'query', [string]$target.Setting) -ReadOnly
            $line = @(Get-OptCommandLines -Text $r.StdOut) | Select-Object -First 1
            $actual = $null
            if ($line -and $line -match '=\s*(\d+)') { $actual = $Matches[1] }
            return @{
                Result   = $(if ([string]$actual -eq [string]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = [string]$Change.NewValue; Actual = [string]$actual; Detail = $null
            }
        }

        'DisplayMode' {
            $target = $Change.Target
            $cur = Get-OptDisplayCurrentMode -Device ([string]$target.Device)
            if (-not $cur) { return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = 'display no longer present' } }
            return @{
                Result   = $(if ([int]$cur.Hz -eq [int]$Change.NewValue) { 'PASS' } else { 'FAIL' })
                Expected = "$($Change.NewValue) Hz"; Actual = "$($cur.Hz) Hz"; Detail = $null
            }
        }

        default {
            return @{ Result = 'SKIP'; Expected = $Change.NewValue; Actual = $null; Detail = "no verifier for change type '$($Change.Type)'" }
        }
    }
}

function Write-OptVerificationReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $rows = @($State.Verification)
    if ($rows.Count -eq 0) { return }

    Write-OptLog -Level Header 'VERIFICATION'

    $planned = @($rows | Where-Object { $_.Result -eq 'PLANNED' })
    if ($planned.Count -gt 0) {
        Write-OptLog -Level Info "$($planned.Count) change(s) planned. Nothing was applied, so nothing is verified."
        return
    }

    $failed = @($rows | Where-Object { $_.Result -eq 'FAIL' })
    foreach ($r in $failed) {
        Write-OptLog -Level Error ("{0} {1}\{2}: expected '{3}', got '{4}'" -f $r.Section, $r.Path, $r.Name, $r.Expected, $r.Actual)
    }

    $deferred = @($rows | Where-Object { $_.Result -eq 'DEFERRED' })
    if ($deferred.Count -gt 0) {
        Write-OptLog -Level Info "$($deferred.Count) change(s) take effect on reboot and are NOT yet verified:"
        foreach ($r in $deferred) {
            Write-OptLog -Level Detail ("{0} {1} {2}" -f $r.Section, $r.Path, $r.Name)
        }
    }

    $pass = @($rows | Where-Object { $_.Result -eq 'PASS' }).Count
    $skip = @($rows | Where-Object { $_.Result -eq 'SKIP' }).Count
    $level = if ($failed.Count -gt 0) { 'Warn' } else { 'Good' }
    Write-OptLog -Level $level ("{0} passed, {1} failed, {2} deferred to reboot, {3} skipped" -f $pass, $failed.Count, $deferred.Count, $skip)
}
#endregion src\10-Core\Verify.ps1

#region src\10-Core\Rollback.ps1
<#
    Rollback: reverse-ordinal replay with a per-Type handler.

    Design rules that came out of thinking about how this actually fails:

    - REVERSE order matters. Section 2.2 writes power values and then re-activates
      the scheme; a key is created before values are set under it. Replaying
      forwards would undo them in the wrong sequence.

    - Rollback is VALUE-LEVEL from the manifest, never `reg import` of the .reg
      backups. Importing an exported key restores values that were deleted
      elsewhere and does not delete values added since.

    - ONE BAD ENTRY MUST NOT ABORT THE WHOLE ROLLBACK. A rollback that stops
      halfway leaves the machine in a state that exists in neither manifest -
      worse than either endpoint. Every entry is attempted; failures are
      collected and reported.

    - Rollback writes its OWN artefact (rollback-<ts>.json) rather than mutating
      the original manifest, so a failed rollback is itself auditable.
#>

function Invoke-OptRollback {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][string]$ManifestPath,
        [switch]$WhatIfOnly
    )

    $manifest = Read-OptManifest -Path $ManifestPath

    $changes = @($manifest.Changes)
    if ($changes.Count -eq 0) {
        Write-OptLog -Level Info 'Manifest contains no changes - nothing to roll back.'
        return @{ Total = 0; Restored = 0; Failed = 0; Skipped = 0; Results = @() }
    }

    # Fingerprint check. A mismatch is not fatal - the user may genuinely want to
    # undo changes after a hardware swap - but vendor-specific entries may now
    # target absent hardware, so say so.
    if ($State.Profile -and $manifest.Fingerprint) {
        $fp = Test-OptFingerprintMatch -StoredFingerprint $manifest.Fingerprint -CurrentFingerprint $State.Profile.Fingerprint
        if (-not $fp.Matches) {
            Write-OptLog -Level Warn "Hardware changed since this manifest was written - $($fp.Detail)"
            Write-OptLog -Level Detail 'Entries targeting hardware that is no longer present will be reported as orphaned.'
        }
    }

    # Reverse ordinal, not reverse array order - the manifest may have been
    # reconstructed from the journal in a different sequence.
    $ordered = @($changes | Sort-Object -Property @{ Expression = { [int]$_.Id } } -Descending)

    Write-OptLog -Level Header "ROLLBACK - $($ordered.Count) change(s), newest first"

    $results  = New-Object System.Collections.ArrayList
    $restored = 0; $failed = 0; $skipped = 0

    foreach ($change in $ordered) {
        $outcome = $null
        try {
            if ($WhatIfOnly) {
                $outcome = @{ Result = 'WOULD-RESTORE'; Detail = (Get-OptRollbackDescription -Change $change) }
            }
            else {
                $outcome = Invoke-OptRollbackEntry -State $State -Change $change
            }
        }
        catch {
            # Never let one entry stop the replay.
            $outcome = @{ Result = 'FAILED'; Detail = $_.Exception.Message }
        }

        switch ($outcome.Result) {
            'RESTORED'      { $restored++; Write-OptLog -Level Good   ("[{0}] {1}" -f $change.Id, $outcome.Detail) }
            'WOULD-RESTORE' { $skipped++;  Write-OptLog -Level Plain  ("  [{0}] {1}" -f $change.Id, $outcome.Detail) }
            'SKIPPED'       { $skipped++;  Write-OptLog -Level Detail ("[{0}] skipped: {1}" -f $change.Id, $outcome.Detail) }
            'IRREVERSIBLE'  { $skipped++;  Write-OptLog -Level Warn   ("[{0}] not reversible: {1}" -f $change.Id, $outcome.Detail) }
            default         { $failed++;   Write-OptLog -Level Error  ("[{0}] {1}" -f $change.Id, $outcome.Detail) }
        }

        [void]$results.Add([pscustomobject][ordered]@{
            ChangeId = $change.Id; Type = $change.Type; Section = $change.Section
            Path = $change.Path; Name = $change.Name
            Result = $outcome.Result; Detail = $outcome.Detail
        })
    }

    $summary = @{ Total = $ordered.Count; Restored = $restored; Failed = $failed; Skipped = $skipped; Results = @($results) }

    if (-not $WhatIfOnly -and $State.Paths) {
        $out = Join-Path $State.Paths.RunDir ("rollback-{0}.json" -f $State.Paths.Stamp)
        try {
            @{ Source = $ManifestPath; Summary = $summary; Results = @($results) } |
                ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $out -Encoding UTF8
            Write-OptLog -Level Detail "Rollback record written to $out"
        }
        catch { Write-OptLog -Level Warn "Could not write rollback record: $($_.Exception.Message)" }
    }

    Write-OptLog -Level $(if ($failed -gt 0) { 'Warn' } else { 'Good' }) `
        ("Rollback complete: {0} restored, {1} failed, {2} skipped" -f $restored, $failed, $skipped)

    return $summary
}

function Get-OptRollbackDescription {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)]$Change)

    switch ([string]$Change.Type) {
        'Registry' {
            if (-not $Change.ExistedBefore) { return "delete $($Change.Path)\$($Change.Name) (did not exist before)" }
            return "restore $($Change.Path)\$($Change.Name) = $(Format-OptValueForLog (ConvertFrom-OptStorableValue $Change.OldValue))"
        }
        'RegistryValueDelete' { return "re-create $($Change.Path)\$($Change.Name)" }
        'ScheduledTask'       { return "re-enable scheduled task $($Change.Target.TaskPath)$($Change.Target.TaskName)" }
        'Service'             { return "restore service $($Change.Target.ServiceName) start type to $($Change.OldValue)" }
        'MMAgent'             { return "restore MMAgent $($Change.Target.Field) to $($Change.OldValue)" }
        'PowerCfgActive'      { return "re-activate power scheme $($Change.OldValue)" }
        'NetAdapterProperty'  { return "restore $($Change.Target.AdapterName) $($Change.Target.Keyword) to $($Change.OldValue)" }
        'DefenderExclusion'   { return "remove Defender exclusion $($Change.NewValue)" }
        'FsutilBehavior'      { return "restore fsutil $($Change.Target.Setting) to $($Change.OldValue)" }
        'DisplayMode'         { return "restore display $($Change.Target.Device) to $($Change.OldValue) Hz" }
        default               { return "$($Change.Type): $($Change.Path)" }
    }
}

function Invoke-OptRollbackEntry {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)]$Change
    )

    if ([string]$Change.Reversible -eq 'None') {
        return @{ Result = 'IRREVERSIBLE'; Detail = "$($Change.Type) cannot be undone by this script" }
    }

    switch ([string]$Change.Type) {

        'Registry' {
            $t = $Change.Target
            $hive = [string]$t.Hive; $sub = [string]$t.SubKey; $name = [string]$t.Name
            $kind = [string]$t.ValueKind

            $base = $null; $key = $null
            try {
                $base = Get-OptRegistryHiveKey -Hive $hive

                if (-not $Change.ExistedBefore) {
                    # The value did not exist before: DELETE it rather than
                    # writing anything back.
                    $key = $base.OpenSubKey($sub, $true)
                    if ($key) { $key.DeleteValue($name, $false) }

                    if (-not $Change.KeyExistedBefore) {
                        # We created the key too (e.g. the whole
                        # ...\Image File Execution Options\cs2.exe\PerfOptions
                        # subtree). Remove it - but never a key that pre-existed.
                        if ($key) { $key.Dispose(); $key = $null }
                        try { $base.DeleteSubKeyTree($sub, $false) } catch { }
                        return @{ Result = 'RESTORED'; Detail = "deleted value and key $hive\$sub\$name" }
                    }
                    return @{ Result = 'RESTORED'; Detail = "deleted $hive\$sub\$name (absent before)" }
                }

                # Restore the old value AND its ORIGINAL kind.
                #
                # Target.ValueKind is the type this script WROTE. Restoring with
                # that would leave a value whose data is right but whose type is
                # wrong - e.g. a setting that was REG_SZ "1" before we replaced
                # it with a REG_DWORD would come back as a DWORD. OldValueKind is
                # what it actually was.
                $old = ConvertFrom-OptStorableValue -Value $Change.OldValue
                $restoreKind = [string]$t.OldValueKind
                if (-not $restoreKind) { $restoreKind = $kind }

                $key = $base.CreateSubKey($sub)
                $key.SetValue($name, (ConvertTo-OptRegistryData -Type $restoreKind -Value $old), [Microsoft.Win32.RegistryValueKind]::$restoreKind)
                return @{ Result = 'RESTORED'; Detail = "restored $hive\$sub\$name = $(Format-OptValueForLog $old) ($restoreKind)" }
            }
            finally {
                if ($key)  { $key.Dispose() }
                if ($base) { $base.Dispose() }
            }
        }

        'RegistryValueDelete' {
            $t = $Change.Target
            $old = ConvertFrom-OptStorableValue -Value $Change.OldValue
            $kind = [string]$t.ValueKind
            if (-not $kind) { $kind = 'String' }

            $base = $null; $key = $null
            try {
                $base = Get-OptRegistryHiveKey -Hive ([string]$t.Hive)
                $key = $base.CreateSubKey([string]$t.SubKey)
                $key.SetValue([string]$t.Name, (ConvertTo-OptRegistryData -Type $kind -Value $old), [Microsoft.Win32.RegistryValueKind]::$kind)
                return @{ Result = 'RESTORED'; Detail = "re-created $($Change.Path)\$($Change.Name)" }
            }
            finally {
                if ($key)  { $key.Dispose() }
                if ($base) { $base.Dispose() }
            }
        }

        'ScheduledTask' {
            $t = $Change.Target
            $task = Get-ScheduledTask -TaskPath ([string]$t.TaskPath) -TaskName ([string]$t.TaskName) -ErrorAction SilentlyContinue
            if (-not $task) { return @{ Result = 'SKIPPED'; Detail = 'task no longer present' } }
            if ([string]$Change.OldValue -eq 'Disabled') { return @{ Result = 'SKIPPED'; Detail = 'was already disabled before the run' } }
            Enable-ScheduledTask -TaskPath ([string]$t.TaskPath) -TaskName ([string]$t.TaskName) -ErrorAction Stop | Out-Null
            return @{ Result = 'RESTORED'; Detail = "re-enabled $($t.TaskPath)$($t.TaskName)" }
        }

        'Service' {
            $t = $Change.Target
            $name = [string]$t.ServiceName
            $old  = [string]$Change.OldValue
            if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
                return @{ Result = 'SKIPPED'; Detail = 'service no longer present' }
            }

            # 'Automatic (Delayed Start)' is NOT restorable with Set-Service
            # alone - it is StartType=Automatic plus DelayedAutoStart=1 in the
            # service's registry key. Section 5.5 requires exactly that for
            # SysMain, so restoring only the start type would silently downgrade
            # it to plain Automatic.
            $wasDelayed = [bool]$t.DelayedAutoStart
            $setType = if ($old -match 'Delayed') { 'Automatic' } else { $old }

            Set-Service -Name $name -StartupType $setType -ErrorAction Stop
            if ($wasDelayed -or $old -match 'Delayed') {
                $base = $null; $key = $null
                try {
                    $base = Get-OptRegistryHiveKey -Hive 'HKLM'
                    $key = $base.CreateSubKey("SYSTEM\CurrentControlSet\Services\$name")
                    $key.SetValue('DelayedAutostart', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
                }
                finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
            }
            return @{ Result = 'RESTORED'; Detail = "restored service $name to $old" }
        }

        'MMAgent' {
            $field = [string]$Change.Target.Field
            $old   = [bool]$Change.OldValue
            # Restore the RECORDED pre-state, never a Windows default. On the
            # reference machine both fields were already False before the run;
            # "restoring the default" would enable them - a state the user has
            # never been in.
            if ($old) { Enable-MMAgent  -$field -ErrorAction Stop | Out-Null }
            else      { Disable-MMAgent -$field -ErrorAction Stop | Out-Null }
            return @{ Result = 'RESTORED'; Detail = "MMAgent $field restored to $old" }
        }

        'PowerCfgActive' {
            $old = [string]$Change.OldValue
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/setactive', $old)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "powercfg /setactive $old failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "re-activated power scheme $old" }
        }

        'PowerCfgSetting' {
            $t = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' `
                 -ArgumentList @('/setacvalueindex', [string]$t.Scheme, [string]$t.SubGroup, [string]$t.Setting, [string]$Change.OldValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "powercfg restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored $($t.SubGroup)/$($t.Setting) to $($Change.OldValue)" }
        }

        'PowerCfgScheme' {
            # Only delete a scheme this script created.
            if (-not $Change.Target.CreatedByUs) { return @{ Result = 'SKIPPED'; Detail = 'scheme pre-existed; left in place' } }
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/delete', [string]$Change.NewValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "powercfg /delete failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "deleted power scheme $($Change.NewValue)" }
        }

        'NetshTcpGlobal' {
            $t = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'netsh.exe' `
                 -ArgumentList @('int', 'tcp', 'set', 'global', "$([string]$t.Setting)=$([string]$Change.OldValue)")
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "netsh restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored netsh $($t.Setting) to $($Change.OldValue)" }
        }

        'FsutilBehavior' {
            $t = $Change.Target
            $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
                 -ArgumentList @('behavior', 'set', [string]$t.Setting, [string]$Change.OldValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "fsutil restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored fsutil $($t.Setting) to $($Change.OldValue)" }
        }

        'DefenderExclusion' {
            $t = $Change.Target
            try {
                if ([string]$t.Kind -eq 'Path') { Remove-MpPreference -ExclusionPath ([string]$Change.NewValue) -ErrorAction Stop }
                else { Remove-MpPreference -ExclusionProcess ([string]$Change.NewValue) -ErrorAction Stop }
                return @{ Result = 'RESTORED'; Detail = "removed Defender exclusion $($Change.NewValue)" }
            }
            catch { return @{ Result = 'FAILED'; Detail = $_.Exception.Message } }
        }

        'NetAdapterProperty' {
            $t = $Change.Target
            try {
                Set-NetAdapterAdvancedProperty -Name ([string]$t.AdapterName) `
                    -RegistryKeyword ([string]$t.Keyword) -RegistryValue ([string]$Change.OldValue) `
                    -NoRestart -ErrorAction Stop
                return @{ Result = 'RESTORED'; Detail = "restored $($t.Keyword) to $($Change.OldValue) (adapter restart pending)" }
            }
            catch { return @{ Result = 'SKIPPED'; Detail = "adapter or keyword no longer present: $($_.Exception.Message)" } }
        }

        'BcdEditValue' {
            $t = $Change.Target
            if (-not $Change.ExistedBefore) {
                $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/deletevalue', [string]$t.Element)
                return @{ Result = 'RESTORED'; Detail = "removed bcdedit element $($t.Element)" }
            }
            $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/set', [string]$t.Element, [string]$Change.OldValue)
            if (-not $r.Success) { return @{ Result = 'FAILED'; Detail = "bcdedit restore failed: $($r.StdErr)" } }
            return @{ Result = 'RESTORED'; Detail = "restored bcdedit $($t.Element) to $($Change.OldValue)" }
        }

        'DisplayMode' {
            $t = $Change.Target
            $res = [Cs2Opt.Display.Api]::TrySetRefresh([string]$t.Device, [int]$Change.OldValue, $false)
            if (-not $res.Applied) { return @{ Result = 'FAILED'; Detail = "display restore failed: $($res.CodeName)" } }
            return @{ Result = 'RESTORED'; Detail = "restored $($t.Device) to $($Change.OldValue) Hz" }
        }

        'AutomaticPagefile' {
            try {
                $inst = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                Set-CimInstance -InputObject $inst -Property @{ AutomaticManagedPagefile = [bool]$Change.OldValue } -ErrorAction Stop
                return @{ Result = 'RESTORED'; Detail = "AutomaticManagedPagefile restored to $($Change.OldValue)" }
            }
            catch { return @{ Result = 'FAILED'; Detail = $_.Exception.Message } }
        }

        'NetAdapterPowerMgmt' {
            $name = [string]$Change.Target.AdapterName
            try {
                Enable-NetAdapterPowerManagement -Name $name -ErrorAction Stop -Confirm:$false
                return @{ Result = 'RESTORED'; Detail = "re-enabled power management on $name" }
            }
            catch { return @{ Result = 'SKIPPED'; Detail = "adapter no longer present: $($_.Exception.Message)" } }
        }

        'UsbPowerMgmt' {
            # Partial by design: endpoints that have since been unplugged are
            # skipped rather than failing the whole rollback.
            $ids = @($Change.Target.InstanceIds)
            $restored = 0
            foreach ($id in $ids) {
                try {
                    $nodes = Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop |
                             Where-Object { $_.InstanceName -like "*$([string]$id -replace '\\','\\')*" }
                    foreach ($n in $nodes) {
                        Set-CimInstance -InputObject $n -Property @{ Enable = $true } -ErrorAction Stop
                        $restored++
                    }
                }
                catch { }
            }
            return @{ Result = 'RESTORED'; Detail = "re-enabled power management on $restored of $($ids.Count) USB endpoint(s)" }
        }

        'AppxPackage' {
            return @{ Result = 'IRREVERSIBLE'; Detail = "Appx removal cannot be undone by this script - reinstall '$($Change.Name)' from the Store" }
        }

        default {
            return @{ Result = 'SKIPPED'; Detail = "no rollback handler for change type '$($Change.Type)'" }
        }
    }
}
#endregion src\10-Core\Rollback.ps1

#region src\20-Interop\Interop-Bootstrap.ps1
<#
    Guarded Add-Type bootstrap.

    Every interop type is compiled once per session and guarded by an
    `-as [type]` check, because Add-Type throws "type already exists" on a
    second call in the same session - which happens constantly during
    development and testing.

    If compilation fails for any reason (locked %TEMP%, missing csc.exe,
    constrained language mode), the script does not die: it switches off the
    Interop capability, which gates section 3.8 off with a clear reason and
    downgrades section 6.1 to "registry written, logoff required".
#>

function Register-OptInteropType {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$TypeName,
        [Parameter(Mandatory)][string]$Definition
    )

    if ($TypeName -as [type]) { return $true }

    try {
        # -Language CSharp is the default and compiles through the .NET
        # Framework CodeDom (csc.exe under %WINDIR%\Microsoft.NET\Framework64).
        # It needs a writable %TEMP%. Do NOT pass -CompilerParameters; that
        # path behaves differently across 5.1 servicing levels.
        Add-Type -TypeDefinition $Definition -ErrorAction Stop
        return [bool]($TypeName -as [type])
    }
    catch {
        Write-Warning "Interop compilation failed for ${TypeName}: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-OptInterop {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $ok = $true
    $ok = (Register-OptInteropType -TypeName 'Cs2Opt.Display.Api' -Definition (Get-OptDisplayInteropSource)) -and $ok
    $ok = (Register-OptInteropType -TypeName 'Cs2Opt.Input.Api'   -Definition (Get-OptMouseInteropSource))   -and $ok
    $ok = (Register-OptInteropType -TypeName 'Cs2Opt.Cpu.Api'     -Definition (Get-OptCpuInteropSource))     -and $ok

    $State.Capabilities.Interop = $ok
    if (-not $ok) {
        $State.Capabilities.DisplayModeChange = $false
    }
    return $ok
}
#endregion src\20-Interop\Interop-Bootstrap.ps1

#region src\20-Interop\Interop-Display.ps1
<#
    Display enumeration and refresh-rate enforcement (spec 3.8).

    ALL struct marshalling lives inside C#; the surface exposed to PowerShell
    is classes with primitive fields only. This is empirical, not stylistic:
    PowerShell's boxed-struct [ref] marshalling is unreliable here - through an
    identical pattern, EnumDisplaySettingsEx worked while EnumDisplayDevices
    silently returned false. Moving the whole enumeration into C# returned all
    adapters correctly, with PCI DeviceIds.

    Uses the W entry points with CharSet.Unicode throughout. This also fixes
    DEVMODE sizing: the struct is 156 bytes under Ansi and 220 under Unicode,
    and a wrong dmSize makes EnumDisplaySettings fail in confusing ways.
#>

function Get-OptDisplayInteropSource {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cs2Opt.Display
{
    public class DisplayAdapter
    {
        public string DeviceName;
        public string DeviceString;
        public string DeviceId;
        public bool   IsPrimary;
        public bool   IsAttached;
    }

    public class DisplayMode
    {
        public string Device;
        public int Width;
        public int Height;
        public int Bpp;
        public int Hz;
    }

    public class ChangeResult
    {
        public int    Code;
        public string CodeName;
        public bool   TestPassed;
        public bool   Applied;
        public string Message;
    }

    public static class Api
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DEVMODE
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
            public short dmSpecVersion;
            public short dmDriverVersion;
            public short dmSize;
            public short dmDriverExtra;
            public int   dmFields;
            public int   dmPositionX;
            public int   dmPositionY;
            public int   dmDisplayOrientation;
            public int   dmDisplayFixedOutput;
            public short dmColor;
            public short dmDuplex;
            public short dmYResolution;
            public short dmTTOption;
            public short dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
            public short dmLogPixels;
            public int   dmBitsPerPel;
            public int   dmPelsWidth;
            public int   dmPelsHeight;
            public int   dmDisplayFlags;
            public int   dmDisplayFrequency;
            public int   dmICMMethod;
            public int   dmICMIntent;
            public int   dmMediaType;
            public int   dmDitherType;
            public int   dmReserved1;
            public int   dmReserved2;
            public int   dmPanningWidth;
            public int   dmPanningHeight;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DISPLAY_DEVICE
        {
            public int cb;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]  public string DeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
            public int StateFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "EnumDisplayDevicesW")]
        private static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "EnumDisplaySettingsExW")]
        private static extern bool EnumDisplaySettingsEx(string lpszDeviceName, int iModeNum, ref DEVMODE lpDevMode, uint dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "ChangeDisplaySettingsExW")]
        private static extern int ChangeDisplaySettingsEx(string lpszDeviceName, ref DEVMODE lpDevMode, IntPtr hwnd, uint dwflags, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "ChangeDisplaySettingsExW")]
        private static extern int ChangeDisplaySettingsExApply(string lpszDeviceName, IntPtr lpDevMode, IntPtr hwnd, uint dwflags, IntPtr lParam);

        private const int  ENUM_CURRENT_SETTINGS = -1;
        private const uint CDS_UPDATEREGISTRY    = 0x00000001;
        private const uint CDS_TEST              = 0x00000002;
        private const uint CDS_GLOBAL            = 0x00000008;

        private const int DM_BITSPERPEL       = 0x00040000;
        private const int DM_PELSWIDTH        = 0x00080000;
        private const int DM_PELSHEIGHT       = 0x00100000;
        private const int DM_DISPLAYFREQUENCY = 0x00400000;

        private const int DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x00000001;
        private const int DISPLAY_DEVICE_PRIMARY_DEVICE      = 0x00000004;

        private static DEVMODE NewDevMode()
        {
            DEVMODE dm = new DEVMODE();
            dm.dmDeviceName = new string('\0', 32);
            dm.dmFormName   = new string('\0', 32);
            dm.dmSize       = (short)Marshal.SizeOf(typeof(DEVMODE));
            return dm;
        }

        public static List<DisplayAdapter> GetAdapters()
        {
            List<DisplayAdapter> list = new List<DisplayAdapter>();
            uint i = 0;
            while (true)
            {
                DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
                dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
                if (!EnumDisplayDevices(null, i, ref dd, 0)) break;

                DisplayAdapter a = new DisplayAdapter();
                a.DeviceName   = dd.DeviceName;
                a.DeviceString = dd.DeviceString;
                a.DeviceId     = dd.DeviceID;
                a.IsPrimary    = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
                a.IsAttached   = (dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) != 0;
                list.Add(a);
                i++;
                if (i > 64) break;
            }
            return list;
        }

        /// <summary>Monitor friendly name behind an adapter (EnumDisplayDevices second level).</summary>
        public static string GetMonitorName(string device)
        {
            DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
            if (EnumDisplayDevices(device, 0, ref dd, 0)) return dd.DeviceString;
            return null;
        }

        public static DisplayMode GetCurrentMode(string device)
        {
            DEVMODE dm = NewDevMode();
            if (!EnumDisplaySettingsEx(device, ENUM_CURRENT_SETTINGS, ref dm, 0)) return null;

            DisplayMode m = new DisplayMode();
            m.Device = device;
            m.Width  = dm.dmPelsWidth;
            m.Height = dm.dmPelsHeight;
            m.Bpp    = dm.dmBitsPerPel;
            m.Hz     = dm.dmDisplayFrequency;
            return m;
        }

        public static List<DisplayMode> GetModes(string device)
        {
            List<DisplayMode> list = new List<DisplayMode>();
            int i = 0;
            while (true)
            {
                DEVMODE dm = NewDevMode();
                if (!EnumDisplaySettingsEx(device, i, ref dm, 0)) break;

                DisplayMode m = new DisplayMode();
                m.Device = device;
                m.Width  = dm.dmPelsWidth;
                m.Height = dm.dmPelsHeight;
                m.Bpp    = dm.dmBitsPerPel;
                m.Hz     = dm.dmDisplayFrequency;
                list.Add(m);
                i++;
                if (i > 8192) break;
            }
            return list;
        }

        private static string CodeName(int c)
        {
            switch (c)
            {
                case  1: return "DISP_CHANGE_RESTART";
                case  0: return "DISP_CHANGE_SUCCESSFUL";
                case -1: return "DISP_CHANGE_FAILED";
                case -2: return "DISP_CHANGE_BADMODE";
                case -3: return "DISP_CHANGE_NOTUPDATED";
                case -4: return "DISP_CHANGE_BADFLAGS";
                case -5: return "DISP_CHANGE_BADPARAM";
                case -6: return "DISP_CHANGE_BADDUALVIEW";
                default: return "DISP_CHANGE_UNKNOWN(" + c + ")";
            }
        }

        /// <summary>
        /// Sets refresh rate only. Width/height/bpp are pinned to their CURRENT
        /// values and included in dmFields, which is what enforces spec 3.8.5 -
        /// never silently drop resolution or colour depth to reach a higher
        /// refresh. Always CDS_TEST first; testOnly stops there (this is what
        /// -DryRun uses, and it is more informative than skipping because it
        /// reports whether the mode would actually validate).
        /// </summary>
        public static ChangeResult TrySetRefresh(string device, int hz, bool testOnly)
        {
            ChangeResult r = new ChangeResult();

            DEVMODE dm = NewDevMode();
            if (!EnumDisplaySettingsEx(device, ENUM_CURRENT_SETTINGS, ref dm, 0))
            {
                r.Code = -1; r.CodeName = "ENUM_CURRENT_SETTINGS failed"; r.Message = "Could not read current mode";
                return r;
            }

            dm.dmDisplayFrequency = hz;
            dm.dmFields = DM_DISPLAYFREQUENCY | DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL;

            int test = ChangeDisplaySettingsEx(device, ref dm, IntPtr.Zero, CDS_TEST, IntPtr.Zero);
            r.Code       = test;
            r.CodeName   = CodeName(test);
            r.TestPassed = (test == 0);

            if (test != 0 || testOnly)
            {
                r.Message = testOnly ? "test only" : "mode rejected by driver";
                return r;
            }

            int applied = ChangeDisplaySettingsEx(device, ref dm, IntPtr.Zero, CDS_UPDATEREGISTRY | CDS_GLOBAL, IntPtr.Zero);
            r.Code     = applied;
            r.CodeName = CodeName(applied);
            r.Applied  = (applied == 0 || applied == 1);

            if (r.Applied)
            {
                // Commit the pending change set.
                ChangeDisplaySettingsExApply(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
            }
            return r;
        }
    }
}
'@
}

function Get-OptDisplayAdapters {
    [CmdletBinding()]
    param()
    # Returns unrolled so the result can be piped into Where-Object directly.
    # Callers needing .Count wrap in @(...).
    if (-not ('Cs2Opt.Display.Api' -as [type])) { return @() }
    return @([Cs2Opt.Display.Api]::GetAdapters())
}

function Get-OptDisplayCurrentMode {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Device)
    if (-not ('Cs2Opt.Display.Api' -as [type])) { return $null }
    return [Cs2Opt.Display.Api]::GetCurrentMode($Device)
}

function Get-OptDisplayMaxRefresh {
    <#
        Max refresh available AT THE CURRENT resolution and colour depth.

        Deliberately not the global max across all modes: many panels expose a
        higher refresh at a lower resolution, and silently switching resolution
        to reach it is exactly what spec 3.8.5 forbids.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$Device,
        [Parameter(Mandatory)][int]$Width,
        [Parameter(Mandatory)][int]$Height,
        [Parameter(Mandatory)][int]$Bpp
    )

    if (-not ('Cs2Opt.Display.Api' -as [type])) { return 0 }

    $modes = @([Cs2Opt.Display.Api]::GetModes($Device) |
        Where-Object { $_.Width -eq $Width -and $_.Height -eq $Height -and $_.Bpp -eq $Bpp })

    if (-not $modes -or $modes.Count -eq 0) { return 0 }
    return [int](($modes | Measure-Object -Property Hz -Maximum).Maximum)
}
#endregion src\20-Interop\Interop-Display.ps1

#region src\20-Interop\Interop-Mouse.ps1
<#
    Mouse settings via SystemParametersInfo (spec 6.1).

    Applies "Enhance pointer precision" off without requiring a logoff.

    Ordering note that matters: SPIF_UPDATEINIFILE causes SystemParametersInfo
    to write HKCU\Control Panel\Mouse itself. So the manifest must capture the
    pre-change registry values BEFORE the SPI call, and Set-OptRegistryValue
    must run first (the registry values are what persist across logon).

    Interaction with elevation: SystemParametersInfo affects the CALLING user's
    session. If the elevated identity is not the interactive user, the registry
    writes are redirected to HKU\<interactive-sid> while an SPI call would apply
    to the wrong session - so in that case the SPI call is skipped entirely and
    a logoff is flagged instead.
#>

function Get-OptMouseInteropSource {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
using System;
using System.Runtime.InteropServices;

namespace Cs2Opt.Input
{
    public static class Api
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

        private const uint SPI_GETMOUSE       = 0x0003;
        private const uint SPI_SETMOUSE       = 0x0004;
        private const uint SPI_GETMOUSESPEED  = 0x0070;
        private const uint SPI_SETMOUSESPEED  = 0x0071;

        private const uint SPIF_UPDATEINIFILE = 0x01;
        private const uint SPIF_SENDCHANGE    = 0x02;

        /// <summary>{ threshold1, threshold2, acceleration }</summary>
        public static int[] GetMouse()
        {
            IntPtr buf = Marshal.AllocHGlobal(sizeof(int) * 3);
            try
            {
                if (!SystemParametersInfo(SPI_GETMOUSE, 0, buf, 0)) return null;
                int[] v = new int[3];
                Marshal.Copy(buf, v, 0, 3);
                return v;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static bool SetMouse(int threshold1, int threshold2, int acceleration)
        {
            IntPtr buf = Marshal.AllocHGlobal(sizeof(int) * 3);
            try
            {
                int[] v = new int[] { threshold1, threshold2, acceleration };
                Marshal.Copy(v, 0, buf, 3);
                return SystemParametersInfo(SPI_SETMOUSE, 0, buf, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        /// <summary>Pointer speed slider, 1..20. 10 is the 6/11 notch (no scaling).</summary>
        public static int GetMouseSpeed()
        {
            IntPtr buf = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                if (!SystemParametersInfo(SPI_GETMOUSESPEED, 0, buf, 0)) return -1;
                return Marshal.ReadInt32(buf);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static bool SetMouseSpeed(int speed)
        {
            // For SPI_SETMOUSESPEED the value is passed IN pvParam itself,
            // not through a pointer to a buffer.
            return SystemParametersInfo(SPI_SETMOUSESPEED, 0, new IntPtr(speed), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
        }
    }
}
'@
}

function Get-OptMouseState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if (-not ('Cs2Opt.Input.Api' -as [type])) { return $null }

    $v = [Cs2Opt.Input.Api]::GetMouse()
    if (-not $v) { return $null }

    return @{
        Threshold1   = [int]$v[0]
        Threshold2   = [int]$v[1]
        Acceleration = [int]$v[2]
        Speed        = [int][Cs2Opt.Input.Api]::GetMouseSpeed()
    }
}
#endregion src\20-Interop\Interop-Mouse.ps1

#region src\20-Interop\Interop-Cpu.ps1
<#
    CPU topology via GetLogicalProcessorInformationEx.

    This exists because deriving topology from a microarchitecture lookup table
    is unsafe. The reference machine is a Ryzen 7 9850X3D reporting
    "AMD64 Family 26 Model 68" - a part that is in nobody's hardcoded table.
    Spec 1.5.3 says unknown means skip, and a table miss would therefore skip
    section 6.4 on a machine where it is perfectly appropriate.

    Two facts are read straight from the OS instead:

      HasHybridTopology - distinct EfficiencyClass values across processor
                          cores. Intel P/E parts report more than one; every
                          AMD desktop part reports a single class. No table.

      CcdCount          - number of distinct L3 cache instances. On Ryzen each
                          CCD carries its own L3, so this is a direct read of
                          the thing section 6.4 actually cares about, rather
                          than an inference from core count.
#>

function Get-OptCpuInteropSource {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cs2Opt.Cpu
{
    public class Topology
    {
        public int  PhysicalCores;
        public int  LogicalCores;
        public int  PackageCount;
        public int  L3CacheCount;      // == CCD count on AMD Ryzen
        public long L3CacheBytesMax;
        public int  EfficiencyClassCount;
        public bool IsHybrid;
        public bool Succeeded;
        public string Error;
    }

    public static class Api
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetLogicalProcessorInformationEx(
            int relationshipType, IntPtr buffer, ref int returnedLength);

        private const int RelationProcessorCore = 0;
        private const int RelationCache         = 2;
        private const int RelationProcessorPackage = 3;
        private const int RelationAll           = 0xffff;

        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        private static int PopCount(ulong v)
        {
            int c = 0;
            while (v != 0) { v &= (v - 1); c++; }
            return c;
        }

        public static Topology Get()
        {
            Topology t = new Topology();
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int len = 0;
                GetLogicalProcessorInformationEx(RelationAll, IntPtr.Zero, ref len);
                if (len <= 0)
                {
                    t.Error = "GetLogicalProcessorInformationEx returned zero length";
                    return t;
                }

                buffer = Marshal.AllocHGlobal(len);
                if (!GetLogicalProcessorInformationEx(RelationAll, buffer, ref len))
                {
                    t.Error = "GetLogicalProcessorInformationEx failed, win32=" + Marshal.GetLastWin32Error();
                    return t;
                }

                HashSet<byte> efficiencyClasses = new HashSet<byte>();
                long offset = 0;

                while (offset < len)
                {
                    IntPtr rec = new IntPtr(buffer.ToInt64() + offset);
                    int relationship = Marshal.ReadInt32(rec, 0);
                    int size         = Marshal.ReadInt32(rec, 4);
                    if (size <= 0) break;

                    if (relationship == RelationProcessorCore)
                    {
                        t.PhysicalCores++;

                        // PROCESSOR_RELATIONSHIP:
                        //   +8  BYTE Flags
                        //   +9  BYTE EfficiencyClass
                        //   +10 BYTE Reserved[20]
                        //   +30 WORD GroupCount
                        //   +32 GROUP_AFFINITY GroupMask[]   (16 bytes each on x64)
                        byte efficiency = Marshal.ReadByte(rec, 9);
                        efficiencyClasses.Add(efficiency);

                        short groupCount = Marshal.ReadInt16(rec, 30);
                        for (int g = 0; g < groupCount; g++)
                        {
                            ulong mask = (ulong)Marshal.ReadIntPtr(rec, 32 + (g * 16)).ToInt64();
                            t.LogicalCores += PopCount(mask);
                        }
                    }
                    else if (relationship == RelationProcessorPackage)
                    {
                        t.PackageCount++;
                    }
                    else if (relationship == RelationCache)
                    {
                        // CACHE_RELATIONSHIP:
                        //   +8  BYTE Level
                        //   +9  BYTE Associativity
                        //   +10 WORD LineSize
                        //   +12 DWORD CacheSize
                        //   +16 DWORD Type
                        byte level = Marshal.ReadByte(rec, 8);
                        if (level == 3)
                        {
                            t.L3CacheCount++;
                            uint cacheSize = (uint)Marshal.ReadInt32(rec, 12);
                            if (cacheSize > t.L3CacheBytesMax) t.L3CacheBytesMax = cacheSize;
                        }
                    }

                    offset += size;
                }

                t.EfficiencyClassCount = efficiencyClasses.Count;
                t.IsHybrid   = efficiencyClasses.Count > 1;
                t.Succeeded  = true;
                return t;
            }
            catch (Exception ex)
            {
                t.Error = ex.Message;
                return t;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
'@
}

function Get-OptCpuTopology {
    <#
        Returns a plain hashtable (never a CIM/interop object) so it drops
        straight into the serializable profile.

        On failure every field is $null rather than a guess - the caller must
        treat that as "unknown", which per spec 1.5.3 means skip.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $unknown = @{
        PhysicalCores        = $null
        LogicalCores         = $null
        PackageCount         = $null
        CcdCount             = $null
        L3CacheBytesMax      = $null
        EfficiencyClassCount = $null
        IsHybrid             = $null
        Source               = 'unavailable'
    }

    if (-not ('Cs2Opt.Cpu.Api' -as [type])) { return $unknown }

    $t = [Cs2Opt.Cpu.Api]::Get()
    if (-not $t -or -not $t.Succeeded) { return $unknown }

    return @{
        PhysicalCores        = [int]$t.PhysicalCores
        LogicalCores         = [int]$t.LogicalCores
        PackageCount         = [int]$t.PackageCount
        # L3 instances == CCDs on Ryzen. Reported as $null rather than 0 when
        # the OS gave us nothing, so the gate sees "unknown", not "one CCD".
        CcdCount             = $(if ($t.L3CacheCount -gt 0) { [int]$t.L3CacheCount } else { $null })
        L3CacheBytesMax      = [long]$t.L3CacheBytesMax
        EfficiencyClassCount = [int]$t.EfficiencyClassCount
        IsHybrid             = [bool]$t.IsHybrid
        Source               = 'GetLogicalProcessorInformationEx'
    }
}
#endregion src\20-Interop\Interop-Cpu.ps1

#region src\30-Detect\DetectorFramework.ps1
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
#endregion src\30-Detect\DetectorFramework.ps1

#region src\30-Detect\Detect-Os.ps1
function Get-OptOsSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Caption = $null; BuildNumber = $null; DisplayVersion = $null; UBR = $null
        IsWin11 = $null; Is22H2OrLater = $null; Edition = 'Unknown'
        IsCopilotPlusPc = $null; HasNpu = $null
        IsDomainJoined = $null; IsAzureAdJoined = $null; IsMdmEnrolled = $null
        IsManaged = $null; HasGroupPolicy = $null
    }
}

function Get-OptOsInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'OS' -UnknownSkeleton (Get-OptOsSkeleton) -ScriptBlock {
        $os = Get-OptCimSafe -ClassName Win32_OperatingSystem | Select-Object -First 1
        $cs = Get-OptCimSafe -ClassName Win32_ComputerSystem  | Select-Object -First 1

        $build = 0
        if ($os -and $os.BuildNumber) { [void][int]::TryParse($os.BuildNumber, [ref]$build) }

        $cvKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

        # Windows 11 must be detected from the build number, never from
        # ProductName or Caption: on Windows 11 the ProductName registry value
        # still literally reads "Windows 10 Pro" (verified on this machine,
        # build 26200). Caption from Win32_OperatingSystem is correct, but the
        # build check is the one that cannot be fooled.
        $isWin11 = ($build -ge 22000)

        $edition = 'Unknown'
        if ($os -and $os.Caption) {
            $caption = $os.Caption
            if     ($caption -match 'Enterprise')  { $edition = 'Enterprise' }
            elseif ($caption -match 'Education')   { $edition = 'Education' }
            elseif ($caption -match 'Pro')         { $edition = 'Pro' }
            elseif ($caption -match 'Home')        { $edition = 'Home' }
            if ($caption -match '\bN\b') { $edition = "${edition}N" }
        }

        # --- management state -------------------------------------------------
        # Domain / Azure-AD / MDM joined machines must skip every
        # HKLM\SOFTWARE\Policies\* write (spec 1.5.4): the management channel
        # reverts them on the next policy refresh and may raise compliance
        # alerts. This drives the PolicyWrites capability.
        $isDomain = $null
        if ($cs) { $isDomain = ConvertTo-OptBool -Value $cs.PartOfDomain }

        $isAzureAd = $null
        $isMdm     = $null
        try {
            $dsreg = & "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null
            if ($LASTEXITCODE -eq 0 -and $dsreg) {
                $text = $dsreg -join "`n"
                if ($text -match 'AzureAdJoined\s*:\s*(\w+)')    { $isAzureAd = ($Matches[1] -eq 'YES') }
                if ($text -match 'WorkplaceJoined\s*:\s*(\w+)')  { if ($Matches[1] -eq 'YES') { $isMdm = $true } }
                if ($text -match 'MDMUrl\s*:\s*(\S+)')           { $isMdm = $true }
                if ($null -eq $isMdm) { $isMdm = $false }
            }
        }
        catch { }

        # --- NPU / Copilot+ ---------------------------------------------------
        # Recall and the on-device AI surfaces only exist on Copilot+ hardware.
        # Without an NPU they are NOT INSTALLED, so section 8.5 must report
        # "not present, nothing to disable" rather than writing policy keys and
        # claiming a win.
        $npu = @(Get-PnpDevice -Class 'ComputeAccelerator' -ErrorAction SilentlyContinue |
                 Where-Object { $_.Status -eq 'OK' })
        $hasNpu = ($npu.Count -gt 0)

        [ordered]@{
            Caption         = if ($os) { $os.Caption } else { $null }
            BuildNumber     = $build
            DisplayVersion  = Get-OptRegValueSafe -Hive HKLM -SubKey $cvKey -Name 'DisplayVersion'
            UBR             = Get-OptRegValueSafe -Hive HKLM -SubKey $cvKey -Name 'UBR'
            IsWin11         = $isWin11
            Is22H2OrLater   = ($build -ge 22621)
            Edition         = $edition
            IsCopilotPlusPc = $hasNpu
            HasNpu          = $hasNpu
            IsDomainJoined  = $isDomain
            IsAzureAdJoined = $isAzureAd
            IsMdmEnrolled   = $isMdm
            IsManaged       = ([bool]$isDomain -or [bool]$isAzureAd -or [bool]$isMdm)
            # Home lacks gpedit.msc, but the HKLM\...\Policies keys still work
            # via the registry - so this only controls whether the report
            # references Group Policy UI paths.
            HasGroupPolicy  = ($edition -notlike '*Home*')
        }
    }
}
#endregion src\30-Detect\Detect-Os.ps1

#region src\30-Detect\Detect-Cpu.ps1
function Get-OptCpuSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Vendor = 'Unknown'; Name = $null; Family = $null; Model = $null; Stepping = $null
        PhysicalCores = $null; LogicalCores = $null
        Microarch = 'Unknown'; HasVCache = $null; CcdCount = $null
        HasHybridTopology = $null; PpmDriver = $null
        L3TotalMB = $null; SmtEnabled = $null
    }
}

function Get-OptCpuMicroarch {
    <#
        Family/Model -> microarchitecture.

        A miss returns 'Unknown', and callers must then treat every
        arch-specific decision as "skip" (spec 1.5.3). This is not a
        theoretical concern: the reference machine is a Ryzen 7 9850X3D
        reporting AMD64 Family 26 (0x1A) Model 68, and any table written before
        that part shipped misses it.

        Crucially, nothing structural depends on this table. HasHybridTopology
        and CcdCount both come from GetLogicalProcessorInformationEx, and
        HasVCache comes from the measured L3 size - so a table miss degrades the
        report text, not the safety of the gates.
    #>
    [CmdletBinding()][OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowNull()][string]$Vendor,
        [Parameter(Mandatory)][AllowNull()]$Family,
        [Parameter(Mandatory)][AllowNull()]$Model,
        [AllowNull()][string]$Name
    )

    if ($Name -and $Name -match 'Ryzen.*\b9\d{3}X3D\b') { return 'Zen5-X3D' }

    $f = 0; $m = 0
    [void][int]::TryParse([string]$Family, [ref]$f)
    [void][int]::TryParse([string]$Model,  [ref]$m)

    if ($Vendor -eq 'AMD') {
        switch ($f) {
            23 { return 'Zen2' }                      # 0x17
            25 { return 'Zen3/Zen4' }                 # 0x19 - both live here
            26 { return 'Zen5' }                      # 0x1A
            default { return 'Unknown' }
        }
    }
    elseif ($Vendor -eq 'Intel') {
        if ($f -eq 6) {
            switch ($m) {
                151 { return 'AlderLake' }   # 0x97
                154 { return 'AlderLake' }   # 0x9A
                183 { return 'RaptorLake' }  # 0xB7
                186 { return 'RaptorLake' }  # 0xBA
                191 { return 'RaptorLake' }  # 0xBF
                197 { return 'ArrowLake' }   # 0xC5
                198 { return 'ArrowLake' }   # 0xC6
                default { return 'Unknown' }
            }
        }
        return 'Unknown'
    }

    return 'Unknown'
}

function Get-OptCpuInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'CPU' -UnknownSkeleton (Get-OptCpuSkeleton) -ScriptBlock {
        $procs = @(Get-OptCimSafe -ClassName Win32_Processor)
        if (-not $procs -or $procs.Count -eq 0) { return $null }
        $cpu = $procs | Select-Object -First 1

        $vendor = 'Unknown'
        if ($cpu.Manufacturer -match 'AMD|AuthenticAMD')      { $vendor = 'AMD' }
        elseif ($cpu.Manufacturer -match 'Intel|GenuineIntel'){ $vendor = 'Intel' }

        # Sum across sockets rather than reading the first processor (spec 1.5.2).
        $wmiCores   = ($procs | Measure-Object -Property NumberOfCores -Sum).Sum
        $wmiLogical = ($procs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum

        # Topology straight from the OS. Preferred over WMI and over any table.
        $topo = Get-OptCpuTopology

        $physical = if ($null -ne $topo.PhysicalCores -and $topo.PhysicalCores -gt 0) { $topo.PhysicalCores } else { [int]$wmiCores }
        $logical  = if ($null -ne $topo.LogicalCores  -and $topo.LogicalCores  -gt 0) { $topo.LogicalCores }  else { [int]$wmiLogical }

        # --- V-Cache ----------------------------------------------------------
        # Win32_CacheMemory.Level is a WMI ENUM, not a cache level: Level 3 is
        # L1, Level 4 is L2, Level 5 is L3. Filtering on `Level -eq 3` looking
        # for "L3" silently returns the L1 caches and kills X3D detection.
        # Verified on this machine: Level 5 = 98304 KB = 96 MB.
        $l3Bytes = 0
        if ($topo.L3CacheBytesMax) {
            $l3Bytes = [long]$topo.L3CacheBytesMax
        }
        else {
            $l3 = Get-OptCimSafe -ClassName Win32_CacheMemory | Where-Object { $_.Level -eq 5 }
            if ($l3) { $l3Bytes = [long](($l3 | Measure-Object -Property MaxCacheSize -Maximum).Maximum) * 1024 }
        }
        $l3Mb = if ($l3Bytes -gt 0) { [int][math]::Round($l3Bytes / 1MB) } else { $null }

        # Name regex OR measured size, OR'd - name matching alone is fragile
        # for OEM SKUs, size alone would misfire on a future large-L3 non-X3D part.
        $hasVCache = $null
        if ($cpu.Name -match 'X3D') { $hasVCache = $true }
        elseif ($null -ne $l3Mb)    { $hasVCache = ($l3Mb -ge 96) }

        # --- PPM driver -------------------------------------------------------
        $ppm = $null
        $ppmDrivers = @(Get-OptCimSafe -ClassName Win32_SystemDriver -Filter "Name='amdppm' OR Name='intelppm' OR Name='processr'")
        $running = $ppmDrivers | Where-Object { $_.State -eq 'Running' } | Select-Object -First 1
        if ($running) { $ppm = $running.Name.ToLowerInvariant() }

        $family = $cpu.Family
        $model  = $null
        if ($cpu.Description -match 'Model\s+(\d+)') { $model = [int]$Matches[1] }
        $stepping = $null
        if ($cpu.Description -match 'Stepping\s+(\d+)') { $stepping = [int]$Matches[1] }

        [ordered]@{
            Vendor            = $vendor
            Name              = if ($cpu.Name) { $cpu.Name.Trim() } else { $null }
            Family            = $family
            Model             = $model
            Stepping          = $stepping
            PhysicalCores     = $physical
            LogicalCores      = $logical
            SmtEnabled        = $(if ($physical -gt 0) { ($logical -gt $physical) } else { $null })
            Microarch         = Get-OptCpuMicroarch -Vendor $vendor -Family $family -Model $model -Name $cpu.Name
            HasVCache         = $hasVCache
            L3TotalMB         = $l3Mb
            # From distinct L3 instances, not inferred from core count.
            CcdCount          = $topo.CcdCount
            # From distinct EfficiencyClass values. Derived from a DIRECT signal
            # rather than the microarch table on purpose: an unknown SKU would
            # otherwise make this indeterminate, which would skip section 6.4 on
            # a machine where it is entirely appropriate.
            HasHybridTopology = $topo.IsHybrid
            PpmDriver         = $ppm
            TopologySource    = $topo.Source
        }
    }
}
#endregion src\30-Detect\Detect-Cpu.ps1

#region src\30-Detect\Detect-Gpu.ps1
function Get-OptGpuSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{ Adapters = @(); PrimaryVendor = 'Unknown'; Count = 0; HasMultiple = $null }
}

function Test-OptGpuIsVirtual {
    <#
        Filters out adapters that are not real display hardware: the Microsoft
        Basic Display Adapter (what you get before a driver installs), RDP /
        Hyper-V synthetic video, and streaming host virtual displays (Parsec,
        Sunshine, IddSampleDriver). Treating any of these as the primary GPU
        would branch the whole of section 3 down the wrong vendor path.
    #>
    [CmdletBinding()][OutputType([bool])]
    param([Parameter(Mandatory)][AllowNull()][string]$Name, [AllowNull()][string]$PnpDeviceId)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

    $virtualNames = @(
        'Microsoft Basic Display', 'Microsoft Remote Display', 'RDPDD', 'RDP Encoder',
        'Hyper-V Video', 'VMware SVGA', 'VirtualBox Graphics', 'QXL', 'Citrix',
        'Parsec Virtual Display', 'IddSampleDriver', 'Sunshine', 'USB Display',
        'DisplayLink', 'Virtual Display'
    )
    foreach ($v in $virtualNames) {
        if ($Name -like "*$v*") { return $true }
    }

    # Real display adapters sit on PCI. Root-enumerated devices are software.
    if ($PnpDeviceId -and $PnpDeviceId -notlike 'PCI\*') { return $true }

    return $false
}

function Get-OptGpuVendorFromId {
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][string]$PnpDeviceId, [AllowNull()][string]$Name)

    if ($PnpDeviceId -match 'VEN_([0-9A-Fa-f]{4})') {
        switch ($Matches[1].ToUpperInvariant()) {
            '1002'  { return 'AMD' }      # ATI/AMD
            '1022'  { return 'AMD' }
            '10DE'  { return 'NVIDIA' }
            '8086'  { return 'Intel' }
        }
    }
    # PCI vendor ID is authoritative; the marketing name is only a fallback.
    if ($Name -match 'NVIDIA|GeForce|RTX|GTX|Quadro') { return 'NVIDIA' }
    if ($Name -match 'Radeon|AMD|FirePro')            { return 'AMD' }
    if ($Name -match 'Intel|Arc|Iris|UHD Graphics')   { return 'Intel' }
    return 'Unknown'
}

function Get-OptGpuVramMB {
    <#
        Win32_VideoController.AdapterRAM is a SIGNED 32-bit value and therefore
        wraps for any card with more than 2 GB of VRAM - a 20 GB RX 7900 XT
        reports a negative or nonsense number. The driver's registry
        HardwareInformation.qwMemorySize is a QWORD and is correct.
    #>
    [CmdletBinding()][OutputType([System.Nullable[int]])]
    param([Parameter(Mandatory)][AllowNull()][string]$PnpDeviceId, [AllowNull()]$AdapterRam)

    $classRoot = 'SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    for ($i = 0; $i -le 16; $i++) {
        $sub = '{0}\{1:D4}' -f $classRoot, $i
        $match = Get-OptRegValueSafe -Hive HKLM -SubKey $sub -Name 'MatchingDeviceId'
        if (-not $match) { continue }
        if ($PnpDeviceId -and ($PnpDeviceId -replace '\\', '\') -notlike "*$($match -replace '\\','\')*") {
            if (-not ($PnpDeviceId -like "*$match*")) { continue }
        }
        $qw = Get-OptRegValueSafe -Hive HKLM -SubKey $sub -Name 'HardwareInformation.qwMemorySize'
        if ($qw) { return [int]([long]$qw / 1MB) }
    }

    if ($AdapterRam -and [long]$AdapterRam -gt 0) { return [int]([long]$AdapterRam / 1MB) }
    return $null
}

function Get-OptGpuInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$DisplayAdapters
    )

    return Invoke-OptDetector -State $State -Name 'GPU' -UnknownSkeleton (Get-OptGpuSkeleton) -ScriptBlock {
        $controllers = @(Get-OptCimSafe -ClassName Win32_VideoController)
        if (-not $controllers -or $controllers.Count -eq 0) { return $null }

        # The interop enumeration gives us the PCI DeviceId of the adapter that
        # actually drives the primary display. That is what makes the
        # "primary display is plugged into the motherboard while a dGPU exists"
        # check possible - it is a cable problem no registry tweak can fix.
        $primaryDeviceId = $null
        if ($DisplayAdapters) {
            $pd = @($DisplayAdapters | Where-Object { $_.IsPrimary }) | Select-Object -First 1
            if ($pd) { $primaryDeviceId = $pd.DeviceId }
        }

        $adapters = @()
        foreach ($c in $controllers) {
            $isVirtual = Test-OptGpuIsVirtual -Name $c.Name -PnpDeviceId $c.PNPDeviceID
            if ($isVirtual) { continue }

            $vendor = Get-OptGpuVendorFromId -PnpDeviceId $c.PNPDeviceID -Name $c.Name

            $drivesPrimary = $false
            if ($primaryDeviceId -and $c.PNPDeviceID) {
                # Compare on the VEN_/DEV_/SUBSYS_ portion; the interop string
                # and the WMI PNPDeviceID differ in their trailing instance path.
                $a = ($c.PNPDeviceID -split '\\')[1]
                if ($a -and $primaryDeviceId -like "*$a*") { $drivesPrimary = $true }
            }

            $adapters += [ordered]@{
                Vendor        = $vendor
                Name          = $c.Name
                DriverVersion = $c.DriverVersion
                DriverDate    = $(if ($c.DriverDate) { ([datetime]$c.DriverDate).ToString('yyyy-MM-dd') } else { $null })
                PnpDeviceId   = $c.PNPDeviceID
                DeviceId      = $(if ($c.PNPDeviceID -match 'DEV_([0-9A-Fa-f]{4})') { $Matches[1] } else { $null })
                VramMB        = Get-OptGpuVramMB -PnpDeviceId $c.PNPDeviceID -AdapterRam $c.AdapterRAM
                IsIntegrated  = ($c.Name -match 'UHD Graphics|Iris|Vega.*Graphics|Radeon.*Graphics$|HD Graphics')
                DrivesPrimary = $drivesPrimary
                IsPrimary     = $false   # resolved below
            }
        }

        if ($adapters.Count -eq 0) { return $null }

        # Prefer the adapter that actually drives the primary display; fall back
        # to the first discrete adapter; last resort the first adapter at all.
        $primaryIndex = 0
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            if ($adapters[$i].DrivesPrimary) { $primaryIndex = $i; break }
        }
        if (-not $adapters[$primaryIndex].DrivesPrimary) {
            for ($i = 0; $i -lt $adapters.Count; $i++) {
                if (-not $adapters[$i].IsIntegrated) { $primaryIndex = $i; break }
            }
        }
        $adapters[$primaryIndex].IsPrimary = $true

        [ordered]@{
            Adapters      = $adapters
            PrimaryVendor = $adapters[$primaryIndex].Vendor
            Count         = $adapters.Count
            HasMultiple   = ($adapters.Count -gt 1)
        }
    }
}
#endregion src\30-Detect\Detect-Gpu.ps1

#region src\30-Detect\Detect-Memory.ps1
function Get-OptMemorySkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        TotalMB = $null; UsableMB = $null; SpeedMTs = $null; ChannelCount = $null; ModuleCount = $null
        CommittedBytes = $null; AvailableMB = $null; CommitPercentOfRam = $null
        DdrGeneration = $null; LooksLikeJedecBase = $null
        MMAgent = [ordered]@{
            MemoryCompression = $null; PageCombining = $null
            ApplicationLaunchPrefetching = $null; ApplicationPreLaunch = $null
            OperationAPI = $null; MaxOperationAPIFiles = $null
            Available = $false
        }
    }
}

function Get-OptJedecBaseSpeed {
    <#
        Nominal JEDEC base for a DDR generation. Used only to flag
        "EXPO/XMP appears not enabled" in the report (spec 12) - never to change
        anything, since memory timings are firmware-side.
    #>
    [CmdletBinding()][OutputType([int])]
    param([Parameter(Mandatory)][AllowNull()]$SmbiosMemoryType)

    switch ([int]$SmbiosMemoryType) {
        26 { return 2133 }   # DDR4
        34 { return 4800 }   # DDR5
        default { return 0 }
    }
}

function Get-OptMemoryInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Memory' -UnknownSkeleton (Get-OptMemorySkeleton) -ScriptBlock {
        $cs      = Get-OptCimSafe -ClassName Win32_ComputerSystem | Select-Object -First 1
        $modules = @(Get-OptCimSafe -ClassName Win32_PhysicalMemory)

        # INSTALLED capacity, summed from the DIMMs - not
        # Win32_ComputerSystem.TotalPhysicalMemory, which reports memory
        # VISIBLE TO WINDOWS after the hardware reservation. On the reference
        # machine that difference is 32404 MB vs 32768 MB, and the 5.4.1 gate
        # compares against exactly 32768 - so using the OS-visible figure makes
        # a genuine 32 GB machine fail a ">= 32 GB" test.
        $totalMb  = $null
        $usableMb = $null
        if ($cs -and $cs.TotalPhysicalMemory) { $usableMb = [int]([long]$cs.TotalPhysicalMemory / 1MB) }

        $capacitySum = ($modules | Where-Object { $_.Capacity } | Measure-Object -Property Capacity -Sum).Sum
        if ($capacitySum -and [long]$capacitySum -gt 0) { $totalMb = [int]([long]$capacitySum / 1MB) }
        elseif ($null -ne $usableMb)                    { $totalMb = $usableMb }

        $speed = $null
        $ddrGen = $null
        $jedecBase = 0
        if ($modules -and $modules.Count -gt 0) {
            # ConfiguredClockSpeed is the speed actually in use; Speed is the
            # module's rated speed. The difference is exactly what tells you
            # whether EXPO/XMP is enabled.
            $configured = ($modules | Where-Object { $_.ConfiguredClockSpeed } |
                           Measure-Object -Property ConfiguredClockSpeed -Minimum).Minimum
            if ($configured) { $speed = [int]$configured }

            $smbiosType = ($modules | Select-Object -First 1).SMBIOSMemoryType
            $jedecBase = Get-OptJedecBaseSpeed -SmbiosMemoryType $smbiosType
            $ddrGen = switch ([int]$smbiosType) { 26 { 'DDR4' } 34 { 'DDR5' } default { $null } }
        }

        # --- commit charge ----------------------------------------------------
        # Deliberately NOT Get-Counter '\Memory\Committed Bytes': performance
        # counter PATH NAMES are localized, so that call fails outright on a
        # non-English Windows and would silently skip the 5.4.1 gate with a
        # confusing error. WMI class and property names are not localized.
        $committedBytes = $null
        $availableMb    = $null
        $perf = Get-OptCimSafe -ClassName Win32_PerfRawData_PerfOS_Memory | Select-Object -First 1
        if ($perf) {
            if ($null -ne $perf.CommittedBytes)  { $committedBytes = [long]$perf.CommittedBytes }
            if ($null -ne $perf.AvailableMBytes) { $availableMb    = [long]$perf.AvailableMBytes }
        }

        $commitPct = $null
        if ($committedBytes -and $totalMb -and $totalMb -gt 0) {
            $commitPct = [math]::Round(($committedBytes / 1MB) / $totalMb * 100, 1)
        }

        # --- MMAgent ----------------------------------------------------------
        # Cmdlet-backed, not plain registry values, so these need a dedicated
        # recorder and rollback path (spec 5.4). Record the ACTUAL current state:
        # on this machine both are already False, and a rollback that assumed
        # Windows defaults would ENABLE them - a state the user has never been in.
        $mm = Get-OptMemorySkeleton
        $mmState = $mm.MMAgent
        try {
            $agent = Get-MMAgent -ErrorAction Stop
            if ($agent) {
                $mmState.MemoryCompression            = [bool]$agent.MemoryCompression
                $mmState.PageCombining                = [bool]$agent.PageCombining
                $mmState.ApplicationLaunchPrefetching = [bool]$agent.ApplicationLaunchPrefetching
                $mmState.ApplicationPreLaunch         = [bool]$agent.ApplicationPreLaunch
                $mmState.OperationAPI                 = [bool]$agent.OperationAPI
                $mmState.MaxOperationAPIFiles         = [int]$agent.MaxOperationAPIFiles
                $mmState.Available                    = $true
            }
        }
        catch {
            $mmState.Available = $false
        }

        [ordered]@{
            TotalMB            = $totalMb
            UsableMB           = $usableMb
            SpeedMTs           = $speed
            ChannelCount       = $null
            ModuleCount        = @($modules).Count
            CommittedBytes     = $committedBytes
            AvailableMB        = $availableMb
            CommitPercentOfRam = $commitPct
            DdrGeneration      = $ddrGen
            LooksLikeJedecBase = $(if ($speed -and $jedecBase -gt 0) { ($speed -le $jedecBase) } else { $null })
            MMAgent            = $mmState
        }
    }
}
#endregion src\30-Detect\Detect-Memory.ps1

#region src\30-Detect\Detect-Storage.ps1
function Get-OptStorageSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Volumes = @(); Disks = @(); BootBusType = 'Unknown'; BootMediaType = 'Unknown'
        TrimEnabled = $null; HasHdd = $null; HasNonBootFixedVolume = $null
    }
}

function Get-OptStorageInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Storage' -UnknownSkeleton (Get-OptStorageSkeleton) -ScriptBlock {
        $bootLetter = ($env:SystemDrive).TrimEnd(':')

        $physical = @()
        try {
            $physical = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
                [ordered]@{
                    DeviceId     = $_.DeviceId
                    FriendlyName = $_.FriendlyName
                    BusType      = [string]$_.BusType
                    MediaType    = [string]$_.MediaType
                    SizeGB       = [int][math]::Round($_.Size / 1GB)
                    SerialNumber = $_.SerialNumber
                }
            })
        }
        catch { }

        # Map each lettered volume back to its physical disk so BusType and
        # MediaType can be attributed per drive letter. Disk -> Partition ->
        # Volume, because Get-Volume alone does not carry bus type.
        $volumes = @()
        try {
            foreach ($part in (Get-Partition -ErrorAction Stop | Where-Object { $_.DriveLetter })) {
                $disk = $physical | Where-Object { $_.DeviceId -eq [string]$part.DiskNumber } | Select-Object -First 1
                $vol  = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue

                $volumes += [ordered]@{
                    DriveLetter = [string]$part.DriveLetter
                    DiskNumber  = [int]$part.DiskNumber
                    BusType     = $(if ($disk) { $disk.BusType }   else { 'Unknown' })
                    MediaType   = $(if ($disk) { $disk.MediaType } else { 'Unknown' })
                    FileSystem  = $(if ($vol)  { [string]$vol.FileSystem } else { $null })
                    Label       = $(if ($vol)  { [string]$vol.FileSystemLabel } else { $null })
                    SizeGB      = $(if ($vol -and $vol.Size) { [int][math]::Round($vol.Size / 1GB) } else { $null })
                    FreeGB      = $(if ($vol -and $vol.SizeRemaining) { [int][math]::Round($vol.SizeRemaining / 1GB) } else { $null })
                    IsBoot      = ([string]$part.DriveLetter -eq $bootLetter)
                }
            }
        }
        catch { }

        $boot = $volumes | Where-Object { $_.IsBoot } | Select-Object -First 1

        # --- TRIM -------------------------------------------------------------
        # DisableDeleteNotify=0 means TRIM is ON. The command reports separate
        # NTFS and ReFS lines on current builds, so match the value rather than
        # assuming a single line.
        $trim = $null
        $r = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
             -ArgumentList @('behavior', 'query', 'DisableDeleteNotify') -ReadOnly
        if ($r.Success) {
            $lines = Get-OptCommandLines -Text $r.StdOut
            $ntfs  = $lines | Where-Object { $_ -match 'NTFS' } | Select-Object -First 1
            $any   = $lines | Where-Object { $_ -match 'DisableDeleteNotify\s*=\s*(\d)' } | Select-Object -First 1
            $line  = if ($ntfs) { $ntfs } else { $any }
            if ($line -and $line -match '=\s*(\d)') { $trim = ([int]$Matches[1] -eq 0) }
        }

        $nonBootFixed = @($volumes | Where-Object { -not $_.IsBoot -and $_.FileSystem -eq 'NTFS' })

        [ordered]@{
            Volumes               = $volumes
            Disks                 = $physical
            BootBusType           = $(if ($boot) { $boot.BusType }   else { 'Unknown' })
            BootMediaType         = $(if ($boot) { $boot.MediaType } else { 'Unknown' })
            BootFreeGB            = $(if ($boot) { $boot.FreeGB }    else { $null })
            TrimEnabled           = $trim
            HasHdd                = ([bool](@($physical | Where-Object { $_.MediaType -eq 'HDD' }).Count))
            # On the reference machine this is FALSE: C: is the only lettered
            # volume (disk 1 holds the EFI system partition and a Linux
            # partition Windows reports as Unknown). Section 5.1 therefore has
            # no non-boot candidate for the pagefile even before the
            # crash-dump argument applies.
            HasNonBootFixedVolume = ($nonBootFixed.Count -gt 0)
            NonBootFixedVolumes   = $nonBootFixed
        }
    }
}
#endregion src\30-Detect\Detect-Storage.ps1

#region src\30-Detect\Detect-Network.ps1
function Get-OptNetworkSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Adapters = @(); ActiveAdapterName = $null; ActiveIsWireless = $null
        MultipleDefaultRoutes = $null; VirtualAheadOfPhysical = $null
    }
}

function Get-OptNetworkInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Network' -UnknownSkeleton (Get-OptNetworkSkeleton) -ScriptBlock {
        $nics = @()
        try { $nics = @(Get-NetAdapter -ErrorAction Stop) } catch { return $null }
        if ($nics.Count -eq 0) { return $null }

        # Default routes tell us which adapter actually carries game traffic.
        # Machines routinely enumerate Hyper-V vSwitches, VPN tunnels,
        # Tailscale, Bluetooth PAN and a disconnected second NIC all at once,
        # and tuning the wrong one does nothing while looking like the tweak
        # failed.
        $routes = @()
        try {
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                        Sort-Object -Property RouteMetric)
        }
        catch { }

        $adapters = @()
        foreach ($n in $nics) {
            $route = $routes | Where-Object { $_.ifIndex -eq $n.ifIndex } | Select-Object -First 1

            # Advanced properties are captured ONCE here; section 7.1 iterates
            # this snapshot rather than re-querying per property.
            $props = @()
            try {
                $props = @(Get-NetAdapterAdvancedProperty -Name $n.Name -ErrorAction Stop | ForEach-Object {
                    [ordered]@{
                        RegistryKeyword    = $_.RegistryKeyword
                        DisplayName        = $_.DisplayName
                        DisplayValue       = $_.DisplayValue
                        RegistryValue      = $(if ($_.RegistryValue) { @($_.RegistryValue)[0] } else { $null })
                        ValidDisplayValues = @($_.ValidDisplayValues)
                        ValidRegistryValues= @($_.ValidRegistryValues)
                    }
                })
            }
            catch { }

            $isVirtual = [bool]$n.Virtual -or
                         ($n.InterfaceDescription -match 'WAN Miniport|Hyper-V|VirtualBox|VMware|TAP-|Tailscale|WireGuard|Bluetooth|Loopback|Npcap')

            $adapters += [ordered]@{
                Name             = $n.Name
                IfIndex          = [int]$n.ifIndex
                Description      = $n.InterfaceDescription
                MacAddress       = $n.MacAddress
                LinkSpeed        = [string]$n.LinkSpeed
                Status           = [string]$n.Status
                IsActive         = ($n.Status -eq 'Up')
                IsWireless       = ($n.PhysicalMediaType -match 'Native 802.11|Wireless' -or $n.InterfaceDescription -match 'Wi-?Fi|Wireless|802\.11')
                IsVirtual        = $isVirtual
                IsDefaultRoute   = ($null -ne $route)
                RouteMetric      = $(if ($route) { [int]$route.RouteMetric } else { $null })
                # An inbox Microsoft driver exposes almost none of the section
                # 7.1 keywords. When that is the case the real fix is installing
                # the vendor driver, not editing the registry.
                DriverProvider   = [string]$n.DriverProvider
                DriverVersion    = [string]$n.DriverVersion
                SupportedKeywords= @($props | ForEach-Object { $_.RegistryKeyword })
                AdvancedProperties = $props
            }
        }

        # The adapter to tune: has a default route, is up, and is not virtual.
        # Lowest route metric wins when several qualify.
        $candidates = @($adapters |
            Where-Object { $_.IsDefaultRoute -and $_.IsActive -and -not $_.IsVirtual } |
            Sort-Object -Property @{ Expression = { if ($null -eq $_.RouteMetric) { [int]::MaxValue } else { $_.RouteMetric } } })

        $active = $candidates | Select-Object -First 1

        # A VPN / Tailscale / Hyper-V adapter holding a LOWER metric than the
        # physical NIC silently routes game traffic through it, which alone can
        # add tens of milliseconds.
        $virtualAhead = $false
        $physMetric = $(if ($active -and $null -ne $active.RouteMetric) { $active.RouteMetric } else { [int]::MaxValue })
        foreach ($a in $adapters) {
            if ($a.IsVirtual -and $a.IsDefaultRoute -and $a.IsActive -and
                $null -ne $a.RouteMetric -and $a.RouteMetric -lt $physMetric) {
                $virtualAhead = $true
            }
        }

        [ordered]@{
            Adapters              = $adapters
            ActiveAdapterName     = $(if ($active) { $active.Name } else { $null })
            ActiveIfIndex         = $(if ($active) { $active.IfIndex } else { $null })
            ActiveIsWireless      = $(if ($active) { $active.IsWireless } else { $null })
            ActiveDriverProvider  = $(if ($active) { $active.DriverProvider } else { $null })
            ActiveLinkSpeed       = $(if ($active) { $active.LinkSpeed } else { $null })
            MultipleDefaultRoutes = (@($adapters | Where-Object { $_.IsDefaultRoute -and $_.IsActive }).Count -gt 1)
            VirtualAheadOfPhysical= $virtualAhead
        }
    }
}
#endregion src\30-Detect\Detect-Network.ps1

#region src\30-Detect\Detect-Display.ps1
function Get-OptDisplaySkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        Displays = @(); PrimaryRefreshHz = $null; PrimaryMaxRefreshHz = $null
        RefreshBelowMax = $null; PrimaryOnIntegrated = $null
    }
}

function Get-OptDisplayInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$GpuInfo
    )

    return Invoke-OptDetector -State $State -Name 'Display' -UnknownSkeleton (Get-OptDisplaySkeleton) -ScriptBlock {
        if (-not $State.Capabilities.Interop) { return $null }

        $adapters = @(Get-OptDisplayAdapters | Where-Object { $_.IsAttached })
        if ($adapters.Count -eq 0) { return $null }

        $displays = @()
        foreach ($a in $adapters) {
            $cur = Get-OptDisplayCurrentMode -Device $a.DeviceName
            if (-not $cur) { continue }

            # Max refresh AT THE CURRENT RESOLUTION AND DEPTH. Not the global
            # maximum: many panels offer a higher rate at a lower resolution,
            # and silently switching resolution to reach it is what spec 3.8.5
            # forbids.
            $max = Get-OptDisplayMaxRefresh -Device $a.DeviceName -Width $cur.Width -Height $cur.Height -Bpp $cur.Bpp

            $monitorName = $null
            try { $monitorName = [Cs2Opt.Display.Api]::GetMonitorName($a.DeviceName) } catch { }

            $displays += [ordered]@{
                Device            = $a.DeviceName
                MonitorName       = $monitorName
                AdapterName       = $a.DeviceString
                AdapterDeviceId   = $a.DeviceId
                IsPrimary         = [bool]$a.IsPrimary
                Width             = [int]$cur.Width
                Height            = [int]$cur.Height
                Bpp               = [int]$cur.Bpp
                CurrentRefreshHz  = [int]$cur.Hz
                MaxRefreshHz      = [int]$max
                RefreshBelowMax   = ($max -gt 0 -and $cur.Hz -lt $max)
            }
        }

        if ($displays.Count -eq 0) { return $null }

        $primary = @($displays | Where-Object { $_.IsPrimary }) | Select-Object -First 1
        if (-not $primary) { $primary = $displays[0] }

        # Primary display driven by the iGPU while a discrete card exists is a
        # silent, very large performance loss - and it is a cable problem, not
        # something any registry value can fix.
        $primaryOnIgpu = $null
        if ($GpuInfo -and $GpuInfo.Adapters -and $GpuInfo.Adapters.Count -gt 1) {
            $igpu = @($GpuInfo.Adapters | Where-Object { $_.IsIntegrated -and $_.DrivesPrimary })
            $dgpu = @($GpuInfo.Adapters | Where-Object { -not $_.IsIntegrated })
            $primaryOnIgpu = (($igpu.Count -gt 0) -and ($dgpu.Count -gt 0))
        }
        elseif ($GpuInfo -and $GpuInfo.Adapters) {
            $primaryOnIgpu = $false
        }

        [ordered]@{
            Displays            = $displays
            PrimaryDevice       = $primary.Device
            PrimaryRefreshHz    = $primary.CurrentRefreshHz
            PrimaryMaxRefreshHz = $primary.MaxRefreshHz
            RefreshBelowMax     = [bool]($displays | Where-Object { $_.RefreshBelowMax })
            PrimaryOnIntegrated = $primaryOnIgpu
        }
    }
}
#endregion src\30-Detect\Detect-Display.ps1

#region src\30-Detect\Detect-Audio.ps1
function Get-OptAudioSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{ Endpoints = @(); DefaultName = $null; DefaultIsHdmi = $null; HasUsbDac = $null; UsbDacNotDefault = $null }
}

function Get-OptAudioInfo {
    <#
        Report-only (spec 11.4). Audio positioning is competitively load-bearing
        in CS2, but every meaningful setting - sample rate, exclusive mode,
        enhancements, spatial sound - lives in per-endpoint property stores that
        are not safely scriptable. The value here is naming the DETECTED default
        endpoint in the checklist rather than printing generic advice.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Audio' -UnknownSkeleton (Get-OptAudioSkeleton) -ScriptBlock {
        $renderRoot = 'SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render'

        $base = $null
        $root = $null
        $endpoints = @()
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine,
                        [Microsoft.Win32.RegistryView]::Registry64)
            $root = $base.OpenSubKey($renderRoot)
            if (-not $root) { return $null }

            foreach ($id in $root.GetSubKeyNames()) {
                $ep = $null
                try {
                    $ep = $root.OpenSubKey($id)
                    if (-not $ep) { continue }

                    # DeviceState: 1 = active. Skip disconnected/unplugged
                    # endpoints, which otherwise dominate this list.
                    $stateVal = $ep.GetValue('DeviceState', 0)
                    if ([int]$stateVal -ne 1) { continue }

                    $propsKey = $ep.OpenSubKey('Properties')
                    $friendly = $null
                    $deviceDesc = $null
                    $interfaceName = $null
                    $enumerator = $null
                    $formFactor = $null
                    if ($propsKey) {
                        # PKEY_Device_FriendlyName. Frequently ABSENT - verified
                        # on this machine - so it is only the first candidate.
                        $friendly      = $propsKey.GetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},14')
                        # PKEY_Device_DeviceDesc -> 'Speakers', 'Headphones'
                        $deviceDesc    = $propsKey.GetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},2')
                        # PKEY_DeviceInterface_FriendlyName -> the adapter, e.g. 'TOPPING USB DAC'
                        $interfaceName = $propsKey.GetValue('{b3f8fa53-0004-438e-9003-51a46e139bfc},6')
                        # PKEY_Device_EnumeratorName. NOT always the literal 'USB':
                        # a class-driver DAC enumerates as e.g. 'TUSBAUDIO_ENUM'.
                        $enumerator    = $propsKey.GetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},24')
                        # PKEY_AudioEndpoint_FormFactor
                        $formFactor    = $propsKey.GetValue('{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},0')
                        $propsKey.Dispose()
                    }

                    # Rebuild the name Windows itself shows: "Speakers (TOPPING USB DAC)".
                    $name = [string]$friendly
                    if ([string]::IsNullOrWhiteSpace($name)) {
                        if ($deviceDesc -and $interfaceName) { $name = "$deviceDesc ($interfaceName)" }
                        elseif ($interfaceName)              { $name = [string]$interfaceName }
                        elseif ($deviceDesc)                 { $name = [string]$deviceDesc }
                        else                                 { $name = $id }
                    }
                    $endpoints += [ordered]@{
                        Id         = $id
                        Name       = $name
                        Enumerator = [string]$enumerator
                        # Substring match, not equality: a USB DAC using a vendor
                        # class driver reports 'TUSBAUDIO_ENUM' rather than 'USB',
                        # and an equality test would miss it entirely.
                        IsUsb      = ([string]$enumerator -match 'USB')
                        # FormFactor 4 = DigitalAudioDisplayDevice (HDMI/DP).
                        IsHdmi     = ([int]([string]$formFactor -as [int]) -eq 4) -or ($name -match 'HDMI|DisplayPort|NVIDIA Output|AMD HD Audio')
                        IsDefault  = $false
                    }
                }
                finally { if ($ep) { $ep.Dispose() } }
            }
        }
        finally {
            if ($root) { $root.Dispose() }
            if ($base) { $base.Dispose() }
        }

        if ($endpoints.Count -eq 0) { return $null }

        # The default endpoint is not exposed through a documented registry
        # value, so resolve it from Win32_SoundDevice ordering as a best effort
        # and mark it explicitly as an inference in the report.
        $default = $endpoints | Select-Object -First 1
        $default.IsDefault = $true

        $usb = @($endpoints | Where-Object { $_.IsUsb })

        [ordered]@{
            Endpoints        = $endpoints
            DefaultName      = $default.Name
            DefaultIsHdmi    = [bool]$default.IsHdmi
            HasUsbDac        = ($usb.Count -gt 0)
            UsbDacNotDefault = (($usb.Count -gt 0) -and -not $default.IsUsb)
        }
    }
}
#endregion src\30-Detect\Detect-Audio.ps1

#region src\30-Detect\Detect-Input.ps1
function Get-OptInputSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{ VendorUtilities = @(); HasVendorUtility = $null; Mouse = $null }
}

function Get-OptInputInfo {
    <#
        Report-only, and it matters (spec 1.5.4): peripheral vendor utilities
        override the Windows mouse settings that section 6.1 writes. Disabling
        acceleration in Windows while G HUB / Synapse / iCUE re-applies its own
        acceleration or angle-snapping leaves the user worse off than before,
        believing it was fixed.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Input' -UnknownSkeleton (Get-OptInputSkeleton) -ScriptBlock {
        $known = @(
            @{ Name = 'Logitech G HUB';    Process = 'lghub';        Pattern = 'G HUB' }
            @{ Name = 'Logitech Gaming';   Process = 'LCore';        Pattern = 'Logitech Gaming Software' }
            @{ Name = 'Razer Synapse';     Process = 'Razer Synapse';Pattern = 'Razer Synapse' }
            @{ Name = 'Corsair iCUE';      Process = 'iCUE';         Pattern = 'iCUE' }
            @{ Name = 'ASUS Armoury Crate';Process = 'ArmouryCrate'; Pattern = 'Armoury Crate' }
            @{ Name = 'SteelSeries GG';    Process = 'SteelSeriesGG';Pattern = 'SteelSeries' }
            @{ Name = 'Glorious Core';     Process = 'GloriousCore'; Pattern = 'Glorious' }
            @{ Name = 'Pulsar Fusion';     Process = 'Fusion';       Pattern = 'Pulsar' }
            @{ Name = 'Wooting';           Process = 'wootility';    Pattern = 'Wootility' }
        )

        $installed = @()
        foreach ($root in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                            'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $base = $null; $key = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                            [Microsoft.Win32.RegistryHive]::LocalMachine,
                            [Microsoft.Win32.RegistryView]::Registry64)
                $key = $base.OpenSubKey($root)
                if (-not $key) { continue }
                foreach ($sub in $key.GetSubKeyNames()) {
                    $s = $null
                    try {
                        $s = $key.OpenSubKey($sub)
                        if ($s) { $installed += [string]$s.GetValue('DisplayName') }
                    }
                    finally { if ($s) { $s.Dispose() } }
                }
            }
            catch { }
            finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
        }

        $running = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)

        $found = @()
        foreach ($k in $known) {
            $isInstalled = [bool](@($installed | Where-Object { $_ -and $_ -like "*$($k.Pattern)*" }).Count)
            $isRunning   = [bool](@($running   | Where-Object { $_ -like "*$($k.Process)*" }).Count)
            if ($isInstalled -or $isRunning) {
                $found += [ordered]@{ Name = $k.Name; Installed = $isInstalled; Running = $isRunning }
            }
        }

        [ordered]@{
            VendorUtilities  = $found
            HasVendorUtility = ($found.Count -gt 0)
            Mouse            = Get-OptMouseState
        }
    }
}
#endregion src\30-Detect\Detect-Input.ps1

#region src\30-Detect\Detect-Power.ps1
function Get-OptPowerSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        ActiveSchemeGuid = $null; ActiveSchemeName = $null; Schemes = @()
        IsLaptop = $null; HasBattery = $null; OnAcPower = $null
        SupportsModernStandby = $null; AvailableSleepStates = @()
        UltimatePerformanceGuid = $null
    }
}

function Get-OptSleepStates {
    <#
        Parses `powercfg /a`, which has TWO sections:

            The following sleep states are available on this system:
                ...
            The following sleep states are not available on this system:
                ...

        A naive `powercfg /a | Select-String 'S0 Low Power Idle'` matches text in
        EITHER section and therefore reports the OPPOSITE answer on machines
        where S0ix is listed as unavailable. Verified on the reference machine:
        S0 Low Power Idle appears under "not available", so the naive check
        returns $true when the correct answer is $false.

        Returns only the states in the AVAILABLE section.
    #>
    [CmdletBinding()][OutputType([string[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text)

    $lines = Get-OptCommandLines -Text $Text
    if ($lines.Count -eq 0) { return , @() }

    $available = @()
    $inAvailable = $false

    foreach ($line in $lines) {
        # Order matters: test the negative header FIRST, because it is a
        # superstring of the positive one.
        if ($line -match 'sleep states are not available|not available on this system') {
            $inAvailable = $false
            continue
        }
        if ($line -match 'sleep states are available|available on this system') {
            $inAvailable = $true
            continue
        }
        if (-not $inAvailable) { continue }

        # Indented state names; skip the indented explanatory sentences that
        # follow an unavailable state.
        $t = $line.Trim()
        if ($t -match '^(Standby|Hibernate|Hybrid Sleep|Fast Startup|S\d)' ) {
            $available += $t
        }
    }

    return , @($available)
}

function Get-OptPowerSchemes {
    <#
        Parses `powercfg /L` lines of the form:
            Power Scheme GUID: 381b4222-...  (Balanced) *
        The trailing asterisk marks the active scheme.
    #>
    [CmdletBinding()][OutputType([array])]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text)

    $schemes = @()
    foreach ($line in (Get-OptCommandLines -Text $Text)) {
        if ($line -match 'GUID:\s*([0-9a-fA-F-]{36})\s*\(([^)]*)\)\s*(\*)?') {
            $schemes += [ordered]@{
                Guid     = $Matches[1].ToLowerInvariant()
                Name     = $Matches[2].Trim()
                IsActive = ($Matches[3] -eq '*')
            }
        }
    }
    return , @($schemes)
}

function Get-OptPowerInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Power' -UnknownSkeleton (Get-OptPowerSkeleton) -ScriptBlock {
        # Canonical built-in Ultimate Performance GUID. On the reference machine
        # this scheme ALREADY exists and is already active - so section 2.1 must
        # reuse it. A blind `powercfg -duplicatescheme` creates a second copy
        # every run, which is the main idempotency trap in that section.
        $ultimateGuid = '682abefa-2beb-44cf-ad85-84c45fd50e03'

        $listResult = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/L') -ReadOnly
        $schemes = Get-OptPowerSchemes -Text $listResult.StdOut

        $active = $schemes | Where-Object { $_.IsActive } | Select-Object -First 1
        if (-not $active) {
            $r = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/getactivescheme') -ReadOnly
            $parsed = Get-OptPowerSchemes -Text $r.StdOut
            $active = $parsed | Select-Object -First 1
        }

        $aResult = Invoke-OptNativeCommand -State $State -FilePath 'powercfg.exe' -ArgumentList @('/a') -ReadOnly
        $sleepStates = Get-OptSleepStates -Text $aResult.StdOut

        # --- chassis / battery ------------------------------------------------
        $battery = @(Get-OptCimSafe -ClassName Win32_Battery)
        $hasBattery = ($battery.Count -gt 0)

        $enclosure = Get-OptCimSafe -ClassName Win32_SystemEnclosure | Select-Object -First 1
        $laptopChassis = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
        $isLaptopChassis = $false
        if ($enclosure -and $enclosure.ChassisTypes) {
            foreach ($t in @($enclosure.ChassisTypes)) {
                if ($laptopChassis -contains [int]$t) { $isLaptopChassis = $true }
            }
        }

        $onAc = $null
        if ($hasBattery) {
            $b = $battery | Select-Object -First 1
            # BatteryStatus 2 = AC connected.
            if ($null -ne $b.BatteryStatus) { $onAc = ([int]$b.BatteryStatus -eq 2) }
        }
        else { $onAc = $true }

        $existingUltimate = $schemes | Where-Object { $_.Guid -eq $ultimateGuid } | Select-Object -First 1

        [ordered]@{
            ActiveSchemeGuid        = $(if ($active) { $active.Guid } else { $null })
            ActiveSchemeName        = $(if ($active) { $active.Name } else { $null })
            Schemes                 = $schemes
            IsLaptop                = ($hasBattery -or $isLaptopChassis)
            HasBattery              = $hasBattery
            ChassisTypes            = $(if ($enclosure) { @($enclosure.ChassisTypes) } else { @() })
            OnAcPower               = $onAc
            AvailableSleepStates    = $sleepStates
            # S0ix machines ignore some legacy timeouts. Spec says log it rather
            # than fight it - apply the settings but do not report them as
            # effective without verification.
            SupportsModernStandby   = [bool](@($sleepStates | Where-Object { $_ -match 'S0 Low Power Idle' }).Count)
            UltimatePerformanceGuid = $(if ($existingUltimate) { $existingUltimate.Guid } else { $null })
            UltimatePerformanceExists = ($null -ne $existingUltimate)
        }
    }
}
#endregion src\30-Detect\Detect-Power.ps1

#region src\30-Detect\Detect-Security.ps1
function Get-OptSecuritySkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        SecureBootEnabled = $null; SecureBootSupported = $null
        TpmPresent = $null; TpmReady = $null; TpmVersion = $null
        VbsStatus = $null; VbsRunning = $null; HvciRunning = $null
        CredentialGuardRunning = $null; SecurityServicesRunning = @()
        AvailableSecurityProperties = @(); HypervisorLaunchType = $null
        IommuEnabled = $null; IommuEvidence = @(); KernelDmaProtection = $null
        BitLockerProtected = @(); BitLockerAnyProtected = $null
        BitLockerRecoveryKeyEscrowed = $null
        AntiCheat = @(); HasKernelAntiCheat = $null; HasFaceitAc = $null
    }
}

function Get-OptAntiCheatTable {
    <#
        Match on service AND driver: an uninstalled product very often leaves
        one behind, and either alone is a false signal.
    #>
    [CmdletBinding()][OutputType([array])]
    param()
    return , @(
        @{ Name = 'FACEIT AC';    Services = @('FACEITService', 'FACEIT');          Drivers = @('FACEIT', 'FACEIT_IOMMU') }
        @{ Name = 'Vanguard';     Services = @('vgc');                              Drivers = @('vgk') }
        @{ Name = 'EasyAntiCheat';Services = @('EasyAntiCheat', 'EasyAntiCheat_EOS');Drivers = @('EasyAntiCheat', 'EasyAntiCheat_EOS') }
        @{ Name = 'BattlEye';     Services = @('BEService');                        Drivers = @('BEDaisy', 'BEGameup') }
        @{ Name = 'ESEA';         Services = @('ESEAService');                      Drivers = @('ESEADriver2', 'ESEADriver') }
    )
}

function Get-OptSecurityInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Security' -UnknownSkeleton (Get-OptSecuritySkeleton) -ScriptBlock {

        # --- Secure Boot ------------------------------------------------------
        # Confirm-SecureBootUEFI THROWS on a legacy BIOS rather than returning
        # false, and throws a different exception when access is denied. Those
        # two are not the same answer and must not collapse to "disabled".
        $secureBoot   = $null
        $sbSupported  = $null
        try {
            $secureBoot  = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
            $sbSupported = $true
        }
        catch [System.PlatformNotSupportedException] {
            $secureBoot = $null; $sbSupported = $false      # legacy BIOS
        }
        catch {
            if ($_.Exception.Message -match 'not supported|legacy|BIOS') { $sbSupported = $false }
            $secureBoot = $null
        }

        # --- TPM --------------------------------------------------------------
        $tpmPresent = $null; $tpmReady = $null; $tpmVersion = $null
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            if ($tpm) {
                $tpmPresent = [bool]$tpm.TpmPresent
                $tpmReady   = [bool]$tpm.TpmReady
                $tpmVersion = [string]$tpm.ManufacturerVersion
            }
        }
        catch { }

        # --- Device Guard / VBS ----------------------------------------------
        $dg = Get-OptCimSafe -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' | Select-Object -First 1

        $vbsStatus = $null; $servicesRunning = @(); $availableProps = @()
        if ($dg) {
            if ($null -ne $dg.VirtualizationBasedSecurityStatus) { $vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus }
            $servicesRunning = @($dg.SecurityServicesRunning     | ForEach-Object { [int]$_ })
            $availableProps  = @($dg.AvailableSecurityProperties | ForEach-Object { [int]$_ })
        }

        # VirtualizationBasedSecurityStatus: 0 off, 1 configured, 2 running.
        $vbsRunning = $(if ($null -ne $vbsStatus) { ($vbsStatus -eq 2) } else { $null })
        # SecurityServicesRunning: 1 Credential Guard, 2 HVCI/Memory Integrity.
        $hvci       = $(if ($dg) { ($servicesRunning -contains 2) } else { $null })
        $credGuard  = $(if ($dg) { ($servicesRunning -contains 1) } else { $null })

        # --- bcdedit hypervisor settings -------------------------------------
        $hvLaunch = $null; $iommuPolicy = $null
        $bcd = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/enum', '{current}') -ReadOnly
        if ($bcd.Success) {
            foreach ($line in (Get-OptCommandLines -Text $bcd.StdOut)) {
                # Anchor on the token: 'hypervisorlaunchtype' is a prefix of
                # nothing, but 'hypervisoriommupolicy' also starts with
                # 'hypervisor', so a loose -match would cross-contaminate.
                if ($line -match '^\s*hypervisorlaunchtype\s+(\S+)')  { $hvLaunch    = $Matches[1] }
                if ($line -match '^\s*hypervisoriommupolicy\s+(\S+)') { $iommuPolicy = $Matches[1] }
            }
        }

        # --- IOMMU: deliberately TRI-STATE ------------------------------------
        # There is no clean API for "IOMMU is on". $true only on a positive
        # signal; otherwise $null meaning indeterminate. This matters because a
        # false negative here sends the user into their BIOS for nothing, and
        # spec 10.2 would have it reported as a hard FACEIT compliance failure.
        $iommu = $null
        $evidence = @()

        if ($iommuPolicy -and $iommuPolicy -match '^Enable') {
            $iommu = $true; $evidence += "bcdedit hypervisoriommupolicy=$iommuPolicy"
        }

        $dmaGuard = Get-OptCimSafe -ClassName MSFT_DmaGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' | Select-Object -First 1
        $kernelDma = $null
        if ($dmaGuard -and $null -ne $dmaGuard.DmaGuardState) {
            $kernelDma = ([int]$dmaGuard.DmaGuardState -eq 1)
            if ($kernelDma) { $iommu = $true; $evidence += 'Kernel DMA Protection on' }
        }

        # FACEIT ships a dedicated IOMMU-check driver. If it loaded and is
        # running, the platform satisfied FACEIT's own IOMMU requirement -
        # which is a stronger signal for our purposes than any WMI property.
        $faceitIommu = Get-OptCimSafe -ClassName Win32_SystemDriver -Filter "Name='FACEIT_IOMMU'" | Select-Object -First 1
        if ($faceitIommu -and $faceitIommu.State -eq 'Running') {
            $iommu = $true; $evidence += 'FACEIT_IOMMU driver running'
        }

        if ($availableProps -contains 3) { $evidence += 'DMA protection listed as available' }

        # --- BitLocker --------------------------------------------------------
        $blProtected = @()
        $blEscrowed  = $null
        try {
            foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
                if ([string]$v.ProtectionStatus -eq 'On') {
                    $protectors = @($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
                    $blProtected += [ordered]@{
                        MountPoint   = [string]$v.MountPoint
                        VolumeStatus = [string]$v.VolumeStatus
                        Protectors   = $protectors
                    }
                    if ($protectors -contains 'RecoveryPassword') { $blEscrowed = $true }
                }
            }
            if ($blProtected.Count -gt 0 -and $null -eq $blEscrowed) { $blEscrowed = $false }
        }
        catch { }

        # --- anti-cheat -------------------------------------------------------
        $allServices = @()
        try { $allServices = @(Get-Service -ErrorAction SilentlyContinue) } catch { }
        $allDrivers = @(Get-OptCimSafe -ClassName Win32_SystemDriver)

        $found = @()
        foreach ($ac in (Get-OptAntiCheatTable)) {
            $svc = @($allServices | Where-Object { $ac.Services -contains $_.Name })
            $drv = @($allDrivers  | Where-Object { $ac.Drivers  -contains $_.Name })
            if ($svc.Count -eq 0 -and $drv.Count -eq 0) { continue }

            $found += [ordered]@{
                Name           = $ac.Name
                ServiceNames   = @($svc | ForEach-Object { $_.Name })
                # Deliberately record StartType and Status separately. These
                # services are Stopped/Manual by design - they start on demand
                # when the client launches. A postflight assertion of "Running"
                # would false-fail on every single run.
                ServiceStates  = @($svc | ForEach-Object { "$($_.Name)=$($_.Status)/$($_.StartType)" })
                ServicePresent = ($svc.Count -gt 0)
                ServiceEnabled = [bool](@($svc | Where-Object { [string]$_.StartType -ne 'Disabled' }).Count)
                DriverNames    = @($drv | ForEach-Object { $_.Name })
                DriverStates   = @($drv | ForEach-Object { "$($_.Name)=$($_.State)/$($_.StartMode)" })
                DriverPresent  = ($drv.Count -gt 0)
                DriverRunning  = [bool](@($drv | Where-Object { $_.State -eq 'Running' }).Count)
            }
        }

        [ordered]@{
            SecureBootEnabled            = $secureBoot
            SecureBootSupported          = $sbSupported
            TpmPresent                   = $tpmPresent
            TpmReady                     = $tpmReady
            TpmVersion                   = $tpmVersion
            VbsStatus                    = $vbsStatus
            VbsRunning                   = $vbsRunning
            HvciRunning                  = $hvci
            CredentialGuardRunning       = $credGuard
            SecurityServicesRunning      = $servicesRunning
            AvailableSecurityProperties  = $availableProps
            HypervisorLaunchType         = $hvLaunch
            HypervisorIommuPolicy        = $iommuPolicy
            IommuEnabled                 = $iommu
            IommuEvidence                = $evidence
            KernelDmaProtection          = $kernelDma
            BitLockerProtected           = $blProtected
            BitLockerAnyProtected        = ($blProtected.Count -gt 0)
            BitLockerRecoveryKeyEscrowed = $blEscrowed
            AntiCheat                    = $found
            HasKernelAntiCheat           = ($found.Count -gt 0)
            HasFaceitAc                  = [bool](@($found | Where-Object { $_.Name -eq 'FACEIT AC' }).Count)
        }
    }
}
#endregion src\30-Detect\Detect-Security.ps1

#region src\30-Detect\Detect-Games.ps1
function Get-OptGamesSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        SteamPath = $null; LibraryPaths = @(); Cs2ExePath = $null
        Cs2Installed = $null; Cs2LibraryPath = $null; Cs2LibraryMediaType = 'Unknown'
    }
}

function ConvertFrom-OptVdf {
    <#
        Minimal tokenizer for Valve's KeyValues format.

        A tokenizer rather than a regex because libraryfolders.vdf stores paths
        with escaped backslashes ("D:\\Games\\Steam") and the v2 format nests an
        "apps" block inside each library entry. A regex over quoted pairs
        happily matches the app-id/size pairs inside "apps" and mixes them into
        the library list.

        Returns nested ordered hashtables.
    #>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $result = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Text)) { return $result }

    $stack = New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push($result)
    $pendingKey = $null

    $i = 0
    $len = $Text.Length
    while ($i -lt $len) {
        $ch = $Text[$i]

        if ($ch -eq '"') {
            # Quoted token, honouring backslash escapes.
            $sb = New-Object System.Text.StringBuilder
            $i++
            while ($i -lt $len -and $Text[$i] -ne '"') {
                if ($Text[$i] -eq '\' -and ($i + 1) -lt $len) {
                    $i++
                    switch ($Text[$i]) {
                        'n'     { [void]$sb.Append("`n") }
                        't'     { [void]$sb.Append("`t") }
                        '\'     { [void]$sb.Append('\') }
                        '"'     { [void]$sb.Append('"') }
                        default { [void]$sb.Append($Text[$i]) }
                    }
                }
                else { [void]$sb.Append($Text[$i]) }
                $i++
            }
            $i++
            $token = $sb.ToString()

            if ($null -eq $pendingKey) { $pendingKey = $token }
            else {
                $stack.Peek()[$pendingKey] = $token
                $pendingKey = $null
            }
            continue
        }

        if ($ch -eq '{') {
            $child = [ordered]@{}
            if ($null -ne $pendingKey) {
                $stack.Peek()[$pendingKey] = $child
                $pendingKey = $null
            }
            $stack.Push($child)
            $i++
            continue
        }

        if ($ch -eq '}') {
            if ($stack.Count -gt 1) { [void]$stack.Pop() }
            $i++
            continue
        }

        # Line comments
        if ($ch -eq '/' -and ($i + 1) -lt $len -and $Text[$i + 1] -eq '/') {
            while ($i -lt $len -and $Text[$i] -ne "`n") { $i++ }
            continue
        }

        $i++
    }

    return $result
}

function Get-OptGamesInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$StorageInfo
    )

    return Invoke-OptDetector -State $State -Name 'Games' -UnknownSkeleton (Get-OptGamesSkeleton) -ScriptBlock {
        # Never hardcode C:\Program Files (x86)\Steam. On the reference machine
        # this value reads 'c:/program files (x86)/steam' - lowercase, with
        # FORWARD slashes - which is why it goes through path normalization
        # before being used anywhere.
        $raw = Get-OptRegValueSafe -Hive HKCU -SubKey 'Software\Valve\Steam' -Name 'SteamPath'
        if (-not $raw) {
            $raw = Get-OptRegValueSafe -Hive HKLM -SubKey 'SOFTWARE\WOW6432Node\Valve\Steam' -Name 'InstallPath'
        }

        $steamPath = ConvertTo-OptNormalizedPath -Path ([string]$raw)
        if (-not $steamPath -or -not (Test-Path -LiteralPath $steamPath)) {
            return [ordered]@{
                SteamPath = $null; LibraryPaths = @(); Cs2ExePath = $null
                Cs2Installed = $false; Cs2LibraryPath = $null; Cs2LibraryMediaType = 'Unknown'
            }
        }

        # --- libraries --------------------------------------------------------
        $libraries = @($steamPath)
        $vdfPath = Join-Path $steamPath 'steamapps\libraryfolders.vdf'
        if (Test-Path -LiteralPath $vdfPath) {
            $parsed = ConvertFrom-OptVdf -Text (Get-Content -LiteralPath $vdfPath -Raw -ErrorAction SilentlyContinue)
            $root = $null
            foreach ($k in $parsed.Keys) {
                if ($k -match '^libraryfolders$') { $root = $parsed[$k]; break }
            }
            if (-not $root) { $root = $parsed }

            foreach ($k in $root.Keys) {
                $entry = $root[$k]
                if ($entry -is [System.Collections.IDictionary] -and $entry.Contains('path')) {
                    $p = ConvertTo-OptNormalizedPath -Path ([string]$entry['path'])
                    if ($p -and (Test-Path -LiteralPath $p)) { $libraries += $p }
                }
            }
        }
        $libraries = @($libraries | Sort-Object -Unique)

        # --- CS2 (appid 730) --------------------------------------------------
        $cs2Exe = $null
        $cs2Library = $null
        foreach ($lib in $libraries) {
            $candidate = Join-Path $lib 'steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe'
            if (Test-Path -LiteralPath $candidate) {
                # Re-case from the filesystem: section 3.3 uses this string as a
                # registry VALUE NAME, and Windows writes it with real casing -
                # a lowercase duplicate would read as a separate entry.
                $cs2Exe = (Get-Item -LiteralPath $candidate).FullName
                $cs2Library = $lib
                break
            }
        }

        $mediaType = 'Unknown'
        if ($cs2Library -and $StorageInfo -and $StorageInfo.Volumes) {
            $letter = ($cs2Library.Substring(0, 1))
            $vol = $StorageInfo.Volumes | Where-Object { $_.DriveLetter -eq $letter } | Select-Object -First 1
            if ($vol) { $mediaType = $vol.MediaType }
        }

        [ordered]@{
            SteamPath           = $steamPath
            LibraryPaths        = $libraries
            Cs2ExePath          = $cs2Exe
            Cs2Installed        = ($null -ne $cs2Exe)
            Cs2LibraryPath      = $cs2Library
            Cs2LibraryMediaType = $mediaType
        }
    }
}
#endregion src\30-Detect\Detect-Games.ps1

#region src\30-Detect\Detect-Boot.ps1
function Get-OptBootSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        FirmwareType = 'Unknown'; IsDualBoot = $null; BootEntries = @()
        NonWindowsPartitions = @(); DualBootEvidence = @()
        FastStartupEnabled = $null; HibernationEnabled = $null
    }
}

function Get-OptBootInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [AllowNull()]$StorageInfo
    )

    return Invoke-OptDetector -State $State -Name 'Boot' -UnknownSkeleton (Get-OptBootSkeleton) -ScriptBlock {
        $firmware = 'Unknown'
        try {
            # PEFirmwareType: 1 = BIOS, 2 = UEFI.
            $fw = (Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop).BiosFirmwareType
            if ($fw) { $firmware = [string]$fw }
        }
        catch {
            if ($env:firmware_type) { $firmware = $env:firmware_type }
        }

        $evidence = @()

        # --- BCD firmware entries --------------------------------------------
        # Only half the story. On the reference machine Linux boots from its own
        # ESP via the firmware boot menu, so `bcdedit /enum firmware` lists ONLY
        # Windows Boot Manager even though the machine is genuinely dual-boot.
        $entries = @()
        $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/enum', 'firmware') -ReadOnly
        if ($r.Success) {
            $currentDesc = $null
            foreach ($line in (Get-OptCommandLines -Text $r.StdOut)) {
                if ($line -match '^\s*description\s+(.+)$') {
                    $currentDesc = $Matches[1].Trim()
                    $entries += $currentDesc
                }
            }
            $nonWindows = @($entries | Where-Object { $_ -notmatch 'Windows|Firmware Application|UEFI OS Boot' })
            if ($nonWindows.Count -gt 0) {
                $evidence += "BCD firmware entries: $($nonWindows -join ', ')"
            }
        }

        # --- partition heuristic ---------------------------------------------
        # This is the half that actually fires here. A partition Windows cannot
        # recognise (ext4/btrfs/xfs) shows up with no drive letter and an
        # unrecognised type - that is the Linux install.
        $foreign = @()
        try {
            foreach ($part in (Get-Partition -ErrorAction Stop)) {
                $sizeGb = [int][math]::Round($part.Size / 1GB)
                if ($part.DriveLetter) { continue }
                if ($sizeGb -lt 8) { continue }              # ignore ESP/MSR/recovery
                $type = [string]$part.Type
                if ($type -match 'Basic|Reserved|Recovery|System') { continue }

                $foreign += [ordered]@{
                    DiskNumber      = [int]$part.DiskNumber
                    PartitionNumber = [int]$part.PartitionNumber
                    Type            = $type
                    SizeGB          = $sizeGb
                }
            }
        }
        catch { }

        if ($foreign.Count -gt 0) {
            $evidence += ("unrecognised partition(s): " + (($foreign | ForEach-Object { "disk $($_.DiskNumber) part $($_.PartitionNumber) $($_.Type) $($_.SizeGB)GB" }) -join '; '))
        }

        # --- hibernation / Fast Startup --------------------------------------
        $hiberFileSize = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateFileSizePercent'
        $hiberEnabled  = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
        $hiberboot     = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled'

        # Both registry values are absent on current builds when hibernation was
        # never explicitly toggled, so fall back to the artefact itself: the
        # presence of hiberfil.sys is the ground truth for "hibernation is on".
        $hibernation = $null
        if ($null -ne $hiberEnabled)       { $hibernation = ([int]$hiberEnabled -ne 0) }
        elseif ($null -ne $hiberFileSize)  { $hibernation = ([int]$hiberFileSize -gt 0) }
        else {
            $hiberFile = Join-Path $env:SystemDrive 'hiberfil.sys'
            # Needs -Force: hiberfil.sys is hidden + system.
            $hibernation = [bool](Get-Item -LiteralPath $hiberFile -Force -ErrorAction SilentlyContinue)
        }

        [ordered]@{
            FirmwareType         = $firmware
            BootEntries          = $entries
            NonWindowsPartitions = $foreign
            DualBootEvidence     = $evidence
            IsDualBoot           = ($evidence.Count -gt 0)
            HibernationEnabled   = $hibernation
            # Fast Startup defaults to ON when the value is absent.
            FastStartupEnabled   = $(if ($null -ne $hiberboot) { ([int]$hiberboot -ne 0) } else { $true })
        }
    }
}
#endregion src\30-Detect\Detect-Boot.ps1

#region src\30-Detect\Detect-Virtualization.ps1
function Get-OptVirtualizationSkeleton {
    [CmdletBinding()][OutputType([hashtable])]
    param()
    return [ordered]@{
        IsVirtualMachine = $null; VmEvidence = $null
        HyperVEnabled = $null; WslInstalled = $null; DockerInstalled = $null
        SandboxEnabled = $null; VmPlatformEnabled = $null
        BlocksHypervisorOff = $null; HypervisorPresent = $null
    }
}

function Get-OptVirtualizationInfo {
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    return Invoke-OptDetector -State $State -Name 'Virtualization' -UnknownSkeleton (Get-OptVirtualizationSkeleton) -ScriptBlock {
        $cs = Get-OptCimSafe -ClassName Win32_ComputerSystem | Select-Object -First 1
        $bios = Get-OptCimSafe -ClassName Win32_BIOS | Select-Object -First 1

        # --- is this a VM -----------------------------------------------------
        # Note HypervisorPresent is TRUE on any machine running VBS, because VBS
        # IS a hypervisor. It must never be used as a VM signal - doing so would
        # abort the run on exactly the FACEIT-compliant machines this script
        # exists for.
        $vmEvidence = $null
        $model = [string]$cs.Model
        $manufacturer = [string]$cs.Manufacturer
        $biosVersion = [string]$bios.SMBIOSBIOSVersion

        $vmPatterns = @(
            @{ Pattern = 'Virtual Machine';   Source = 'Model' }
            @{ Pattern = 'VMware';            Source = 'Model' }
            @{ Pattern = 'VirtualBox';        Source = 'Model' }
            @{ Pattern = 'KVM|QEMU|Bochs';    Source = 'Model' }
            @{ Pattern = 'Parallels';         Source = 'Model' }
            @{ Pattern = 'Xen';               Source = 'Model' }
        )
        foreach ($p in $vmPatterns) {
            if ($model -match $p.Pattern)        { $vmEvidence = "Model='$model'"; break }
            if ($manufacturer -match $p.Pattern) { $vmEvidence = "Manufacturer='$manufacturer'"; break }
        }
        if (-not $vmEvidence -and $manufacturer -match 'Microsoft Corporation' -and $model -match 'Virtual') {
            $vmEvidence = "Model='$model'"
        }
        if (-not $vmEvidence -and $biosVersion -match 'VRTUAL|A M I |VBOX|BOCHS|PRLS') {
            $vmEvidence = "BIOS='$biosVersion'"
        }

        # --- optional features ------------------------------------------------
        # Get-WindowsOptionalFeature is slow (seconds), so query only the names
        # that gate a decision.
        $features = @{}
        foreach ($name in @('Microsoft-Hyper-V-Hypervisor', 'Microsoft-Windows-Subsystem-Linux',
                            'VirtualMachinePlatform', 'Containers-DisposableClientVM')) {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
                $features[$name] = ([string]$f.State -eq 'Enabled')
            }
            catch { $features[$name] = $null }
        }

        $wsl = $features['Microsoft-Windows-Subsystem-Linux']
        if (-not $wsl) {
            $wslDistros = $null
            try {
                $r = Invoke-OptNativeCommand -State $State -FilePath 'wsl.exe' -ArgumentList @('-l', '-q') -ReadOnly
                if ($r.Success -and (Get-OptCommandLines -Text $r.StdOut).Count -gt 0) { $wslDistros = $true }
            }
            catch { }
            if ($wslDistros) { $wsl = $true }
        }

        $docker = $null
        try {
            $docker = [bool](Get-Service -Name 'com.docker.service', 'docker' -ErrorAction SilentlyContinue)
        }
        catch { $docker = $false }

        $hyperV  = $features['Microsoft-Hyper-V-Hypervisor']
        $sandbox = $features['Containers-DisposableClientVM']
        $vmp     = $features['VirtualMachinePlatform']

        [ordered]@{
            IsVirtualMachine    = ($null -ne $vmEvidence)
            VmEvidence          = $vmEvidence
            HypervisorPresent   = $(if ($cs) { [bool]$cs.HypervisorPresent } else { $null })
            HyperVEnabled       = $hyperV
            WslInstalled        = $wsl
            DockerInstalled     = $docker
            SandboxEnabled      = $sandbox
            VmPlatformEnabled   = $vmp
            # Any of these means `bcdedit /set hypervisorlaunchtype off` would
            # break a workload the user actually uses (spec 1.5.4).
            BlocksHypervisorOff = ([bool]$hyperV -or [bool]$wsl -or [bool]$docker -or [bool]$sandbox -or [bool]$vmp)
        }
    }
}
#endregion src\30-Detect\Detect-Virtualization.ps1

#region src\30-Detect\Get-OptProfile.ps1
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
#endregion src\30-Detect\Get-OptProfile.ps1

#region src\40-Gates\GateMatrix.ps1
<#
    The spec 1.5.4 gating matrix, as data.

    Every hardware-conditional decision in the script lives in this one table.
    Nothing here touches the OS: each row's `When` is a pure predicate over a
    plain profile hashtable, which is what makes all ~45 rows testable against
    synthetic profiles with zero real hardware.

    TRI-STATE IS THE CORE DESIGN POINT.

    `When` returns $true, $false, or $null (indeterminate), and every row states
    an explicit OnIndeterminate policy. Positive predicates are safe on $null
    because `$null -eq $true` is $false. NEGATIVE predicates are the trap:

        { -not $p.CPU.HasHybridTopology }

    evaluates to $true when the field is unknown, i.e. it would APPLY the tweak
    on unidentified hardware - the exact inversion of spec 1.5.3's "unknown
    means skip, not guess". Forcing every row to declare what an unknown means
    turns that rule into something mechanical and testable.

    Kinds:
      Abort      - stop the run entirely
      ForceTier  - clamp the tier
      Skip       - block one or more sections (prefix match: '8' blocks 8.*)
      Capability - switch off a capability enforced at the mutation chokepoints
      Escalate   - raise a section's importance in the report
      Finding    - a problem for the user to fix, NOT a tweak that succeeded
      Manual     - checklist item
      Note       - expectation-setting text only
#>

function Get-OptGateMatrix {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    return , @(

        # ---------------------------------------------------------------- host
        @{
            Id = 'G-VM'; Section = '0'; Title = 'Virtual machine'
            When = { param($p, $o) ConvertTo-OptBool $p.Virtualization.IsVirtualMachine }
            OnIndeterminate = 'Allow'
            Kind = 'Abort'; Severity = 'Critical'
            Reason = 'running in a virtual machine - nothing in this spec is meaningful here'
        }
        @{
            Id = 'G-LAPTOP'; Section = '2'; Title = 'Laptop / battery present'
            When = { param($p, $o) ConvertTo-OptBool $p.Power.IsLaptop }
            OnIndeterminate = 'Allow'
            Kind = 'ForceTier'; Effect = @{ Tier = 'Safe'; Skip = @('2.1', '2.2') }
            Severity = 'Warning'
            Reason = 'laptop detected - Ultimate Performance and core-parking changes are a thermal-throttling trap'
        }

        # ----------------------------------------------------------------- CPU
        @{
            Id = 'G-6.4-HYBRID'; Section = '6.4'; Title = 'IFEO High priority'
            When = { param($p, $o) ConvertTo-OptBool $p.CPU.HasHybridTopology }
            # Unknown blocks: applying High priority on an unidentified hybrid
            # part can land the render thread on E-cores.
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('6.4') }
            Reason = 'Intel P/E hybrid topology - High priority fights Thread Director placement'
        }
        @{
            Id = 'G-6.4-CORES'; Section = '6.4'; Title = 'IFEO High priority'
            When = { param($p, $o)
                if ($null -eq $p.CPU.LogicalCores) { return $null }
                return ([int]$p.CPU.LogicalCores -lt 8)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('6.4') }
            Reason = 'fewer than 8 logical cores - High priority starves audio and input threads'
        }
        @{
            Id = 'G-2.2-CPMINCORES-HYBRID'; Section = '2.2'; Title = 'Core parking minimum'
            When = { param($p, $o) ConvertTo-OptBool $p.CPU.HasHybridTopology }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('2.2.CPMINCORES') }
            Reason = 'hybrid topology - core parking is managed by Thread Director; overriding forces work onto E-cores'
        }
        @{
            Id = 'G-2.2-X3D'; Section = '2.2'; Title = 'Processor idle disable'
            When = { param($p, $o) ConvertTo-OptBool $p.CPU.HasVCache }
            OnIndeterminate = 'Block'
            Kind = 'Note'; Severity = 'Info'
            Reason = 'X3D part - idle-blocking raises the thermal floor and reduces sustained boost residency (IDLEDISABLE stays 0 on every path anyway)'
        }
        @{
            Id = 'G-6.4-AFFINITY'; Section = '6.4'; Title = 'CPU affinity pinning'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Block'
            Kind = 'Note'
            Reason = 'CPU affinity is never set on any hardware - harmful on single-CCD parts, unvalidated on multi-CCD'
        }
        @{
            Id = 'G-AMD-PPM'; Section = '2.2'; Title = 'AMD power model driver'
            When = { param($p, $o)
                if ($p.CPU.Vendor -ne 'AMD') { return $false }
                return ($p.CPU.PpmDriver -ne 'amdppm')
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'AMD CPU without the amdppm power driver loaded - Windows will misapply the power model regardless of what this script sets. Install the AMD chipset driver package.'
        }

        # ----------------------------------------------------------------- GPU
        @{
            Id = 'G-3.4-AMD'; Section = '3.4'; Title = 'AMD Adrenalin checklist'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -ne 'AMD') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.4') }
            Reason = 'primary GPU vendor is not AMD'
        }
        @{
            Id = 'G-3.5-NVIDIA'; Section = '3.5'; Title = 'NVIDIA checklist'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -ne 'NVIDIA') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.5') }
            Reason = 'primary GPU vendor is not NVIDIA'
        }
        @{
            Id = 'G-3.6-INTEL'; Section = '3.6'; Title = 'Intel Arc checklist'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -ne 'Intel') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.6') }
            Reason = 'primary GPU vendor is not Intel'
        }
        @{
            Id = 'G-3.1-HAGS-ARC'; Section = '3.1'; Title = 'Hardware-accelerated GPU scheduling'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -eq 'Intel') }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.1.HwSchMode') }
            Reason = 'Intel Arc - HAGS behaviour is driver-version dependent; leave at driver default'
        }
        @{
            Id = 'G-GPU-UNKNOWN'; Section = '3'; Title = 'GPU vendor unknown'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -eq 'Unknown' -or $null -eq $p.GPU.PrimaryVendor) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.4', '3.5', '3.6') }
            Severity = 'Warning'
            Reason = 'GPU vendor could not be determined - no vendor-specific GPU tweak will be applied'
        }
        @{
            Id = 'G-3.7-IGPU-CABLE'; Section = '3.7'; Title = 'Primary display on integrated GPU'
            When = { param($p, $o) ConvertTo-OptBool $p.Display.PrimaryOnIntegrated }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Error'
            Reason = 'the primary display is connected to the motherboard while a discrete GPU is present. This is a cable problem and no registry tweak fixes it - move the cable to the graphics card.'
        }
        @{
            Id = 'G-AMD-ANTILAGPLUS'; Section = '3.4'; Title = 'AMD Anti-Lag+'
            When = { param($p, $o) ($p.GPU.PrimaryVendor -eq 'AMD') }
            OnIndeterminate = 'Allow'
            Kind = 'Note'; Severity = 'Warning'
            Reason = 'never enable Anti-Lag+ - it triggered VAC bans in CS2 (Oct 2023). Standard Anti-Lag and game-integrated Anti-Lag 2 are fine.'
        }

        # ------------------------------------------------------------- display
        @{
            Id = 'G-3.8-REFRESH'; Section = '3.8'; Title = 'Refresh rate enforcement'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.Display.RefreshBelowMax) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.8') }
            Reason = 'every display is already running at its maximum refresh for the current resolution'
        }
        @{
            Id = 'G-REFRESH-LOW'; Section = '3.8'; Title = 'Low refresh expectations'
            When = { param($p, $o)
                if ($null -eq $p.Display.PrimaryMaxRefreshHz) { return $null }
                return ([int]$p.Display.PrimaryMaxRefreshHz -lt 120)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'primary display is under 120 Hz - latency tweaks here have diminishing returns; they still apply, but set expectations accordingly'
        }
        @{
            Id = 'G-REFRESH-HIGH'; Section = '3.8'; Title = 'High refresh priority'
            When = { param($p, $o)
                if ($null -eq $p.Display.PrimaryMaxRefreshHz) { return $null }
                return ([int]$p.Display.PrimaryMaxRefreshHz -ge 240)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'high-refresh panel - sections 3.8, 4.1, 6 and 9 dominate here. Section 10 is not a lever: VBS stays on.'
        }

        # -------------------------------------------------------------- memory
        @{
            Id = 'G-5.4.1-RAM'; Section = '5.4.1'; Title = 'Memory compression disable'
            When = { param($p, $o)
                if ($null -eq $p.Memory.TotalMB) { return $null }
                return ([int]$p.Memory.TotalMB -lt 32768)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.4.1') }
            Reason = 'under 32 GB RAM - disabling compression trades CPU for pagefile I/O once pressure exists'
        }
        @{
            Id = 'G-5.4.1-COMMIT'; Section = '5.4.1'; Title = 'Memory compression disable'
            When = { param($p, $o)
                if ($null -eq $p.Memory.CommitPercentOfRam) { return $null }
                return ([double]$p.Memory.CommitPercentOfRam -gt 60)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.4.1') }
            Severity = 'Warning'
            Reason = 'commit charge is already above 60% of physical RAM at preflight - capacity alone is not enough, headroom is what matters'
        }
        @{
            Id = 'G-5.4.2-RAM'; Section = '5.4.2'; Title = 'Page combining disable'
            When = { param($p, $o)
                if ($null -eq $p.Memory.TotalMB) { return $null }
                return ([int]$p.Memory.TotalMB -lt 16384)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.4.2') }
            Reason = 'under 16 GB RAM - page combining is saving you memory you need'
        }
        @{
            Id = 'G-EXPO'; Section = '12'; Title = 'Memory speed'
            When = { param($p, $o) ConvertTo-OptBool $p.Memory.LooksLikeJedecBase }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'memory appears to be running at JEDEC base speed - EXPO/XMP may not be enabled. This is a firmware setting and is worth more than most of this script.'
        }

        # ------------------------------------------------------------- storage
        @{
            Id = 'G-5.5-HDD'; Section = '5.5'; Title = 'SysMain disable'
            When = { param($p, $o)
                if ($p.Games.Cs2LibraryMediaType -eq 'HDD') { return $true }
                return (ConvertTo-OptBool $p.Storage.HasHdd)
            }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('5.5') }
            Reason = 'spinning disk present - SysMain prefetch genuinely helps HDDs; keep it enabled and move the library instead'
        }
        @{
            Id = 'G-DEFRAG-KEEP'; Section = '8.1'; Title = 'ScheduledDefrag'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'ScheduledDefrag stays enabled on every storage type - on SSD/NVMe it issues TRIM, on HDD it defragments. Disabling it is actively harmful.'
        }

        # ------------------------------------------------------------- network
        @{
            Id = 'G-7.1-WIRELESS'; Section = '7.1'; Title = 'NIC advanced properties'
            When = { param($p, $o) ConvertTo-OptBool $p.Network.ActiveIsWireless }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('7.1') }
            Severity = 'Warning'
            Reason = 'the active adapter is wireless - power-management keywords behave differently on Wi-Fi and changing them can cause disconnects. Use wired for FACEIT.'
        }
        @{
            Id = 'G-7.1-INBOX'; Section = '7.1'; Title = 'NIC advanced properties'
            When = { param($p, $o) ([string]$p.Network.ActiveDriverProvider -eq 'Microsoft') }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'the active NIC uses the Microsoft inbox driver, which exposes almost none of these keywords. Installing the vendor driver is the actual fix, not registry edits.'
        }
        @{
            Id = 'G-7-NOADAPTER'; Section = '7'; Title = 'Network tuning'
            When = { param($p, $o) ($null -eq $p.Network.ActiveAdapterName) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('7.1', '7.3') }
            Severity = 'Warning'
            Reason = 'no active physical adapter carrying the default route could be identified'
        }
        @{
            Id = 'G-7-VPNMETRIC'; Section = '7'; Title = 'Virtual adapter routing ahead of the NIC'
            When = { param($p, $o) ConvertTo-OptBool $p.Network.VirtualAheadOfPhysical }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'a virtual adapter (VPN/Tailscale/Hyper-V) holds a lower route metric than the physical NIC - that alone can add tens of milliseconds'
        }

        # -------------------------------------------------------------- games
        @{
            Id = 'G-CS2-ABSENT'; Section = '3.3'; Title = 'CS2-dependent sections'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.Games.Cs2Installed) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('3.3', '6.4', '9.1', '11') }
            Severity = 'Warning'
            Reason = 'CS2 is not installed - every path-dependent tweak is a no-op. Writing IFEO keys for a nonexistent binary would just leave orphans.'
        }

        # ------------------------------------------------ security / anti-cheat
        @{
            Id = 'G-10-VBS'; Section = '10'; Title = 'VBS disable'
            When = { param($p, $o) ConvertTo-OptBool $p.Security.HasKernelAntiCheat }
            # Unknown BLOCKS: never disable VBS when anti-cheat presence is unclear.
            OnIndeterminate = 'Block'
            Kind = 'Capability'; Effect = @{ Capability = @{ HypervisorOff = $false } ; Skip = @('10.4') }
            Reason = 'kernel anti-cheat present - VBS is a dependency, not an optimization target'
        }
        @{
            Id = 'G-10-VBS-OFF'; Section = '10'; Title = 'FACEIT requires VBS'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasFaceitAc)) { return $false }
                $vbs = ConvertTo-OptBool $p.Security.VbsRunning
                if ($null -eq $vbs) { return $null }
                return (-not $vbs)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'FACEIT AC is installed but VBS is NOT running. This is a blocking compliance problem, not a tweak - you will be denied entry as enforcement waves expand. Set hypervisorlaunchtype to Auto, enable IOMMU in firmware, reboot.'
        }
        @{
            Id = 'G-10-IOMMU-OFF'; Section = '10'; Title = 'FACEIT requires IOMMU'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasFaceitAc)) { return $false }
                $iommu = ConvertTo-OptBool $p.Security.IommuEnabled
                # $null here means "could not confirm", which must NOT be
                # reported as a failure - a false positive sends the user into
                # their BIOS for nothing.
                if ($null -eq $iommu) { return $null }
                return (-not $iommu)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'FACEIT AC is installed but IOMMU could not be confirmed enabled. Enable VT-d (Intel) or IOMMU/AMD-Vi + SVM (AMD) in firmware.'
        }
        @{
            Id = 'G-10-NOAC'; Section = '10'; Title = 'VBS disable available'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.Security.HasKernelAntiCheat) }
            OnIndeterminate = 'Block'
            Kind = 'Note'; Severity = 'Warning'
            Reason = 'no kernel anti-cheat detected - VBS disable becomes technically available under Experimental, but it is not the default and the security tradeoff is real'
        }
        @{
            Id = 'G-10.4-HVCI'; Section = '10.4'; Title = 'HVCI / Memory Integrity'
            When = { param($p, $o) ConvertTo-OptBool $p.Security.HvciRunning }
            OnIndeterminate = 'Allow'
            Kind = 'Manual'
            Reason = 'HVCI is running and is left exactly as-is. Turning it off is a user-confirmed experiment only - if a future enforcement wave adds an HVCI check, a script-baked assumption becomes a silent lockout.'
        }
        @{
            Id = 'G-SECUREBOOT'; Section = '0'; Title = 'Secure Boot'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasKernelAntiCheat)) { return $false }
                $sb = ConvertTo-OptBool $p.Security.SecureBootEnabled
                if ($null -eq $sb) { return $null }
                return (-not $sb)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'kernel anti-cheat present but Secure Boot is disabled - TPM 2.0 and Secure Boot are mandatory for all FACEIT players since 25 Nov 2025'
        }
        @{
            Id = 'G-TPM'; Section = '0'; Title = 'TPM 2.0'
            When = { param($p, $o)
                if (-not (ConvertTo-OptBool $p.Security.HasKernelAntiCheat)) { return $false }
                $tpm = ConvertTo-OptBool $p.Security.TpmReady
                if ($null -eq $tpm) { return $null }
                return (-not $tpm)
            }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Critical'
            Reason = 'kernel anti-cheat present but TPM is not present/ready - enable fTPM or PTT in firmware'
        }
        @{
            Id = 'G-BITLOCKER'; Section = '4.3'; Title = 'bcdedit-touching sections'
            When = { param($p, $o)
                $bl = ConvertTo-OptBool $p.Security.BitLockerAnyProtected
                if ($null -eq $bl) { return $null }
                if (-not $bl) { return $false }
                return (-not [bool]$o.BitLockerAcknowledged)
            }
            OnIndeterminate = 'Block'
            Kind = 'Capability'; Effect = @{ Capability = @{ BcdEdit = $false } }
            Severity = 'Warning'
            Reason = 'BitLocker protection is on. Boot-configuration changes alter TPM PCR measurements and drop the machine into a recovery-key prompt. Skipping is deliberate and safer than suspending - Suspend-BitLocker -RebootCount 1 does not survive a delayed reboot.'
        }

        # ------------------------------------------------------ virtualization
        @{
            Id = 'G-HYPERV'; Section = '10'; Title = 'hypervisorlaunchtype off'
            When = { param($p, $o) ConvertTo-OptBool $p.Virtualization.BlocksHypervisorOff }
            OnIndeterminate = 'Block'
            Kind = 'Capability'; Effect = @{ Capability = @{ HypervisorOff = $false } }
            Reason = 'Hyper-V / WSL / Docker / Sandbox is in use - disabling the hypervisor would break it'
        }

        # ------------------------------------------------------------ policies
        @{
            Id = 'G-MANAGED'; Section = '8'; Title = 'Group Policy writes'
            When = { param($p, $o) ConvertTo-OptBool $p.OS.IsManaged }
            OnIndeterminate = 'Allow'
            Kind = 'Capability'; Effect = @{ Capability = @{ PolicyWrites = $false } }
            Severity = 'Warning'
            Reason = 'domain / Azure-AD / MDM joined - HKLM\SOFTWARE\Policies writes are reverted by the management channel and may raise compliance alerts. Ask IT instead.'
        }
        @{
            Id = 'G-8.5-NPU'; Section = '8.5'; Title = 'Windows AI surfaces'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.OS.HasNpu) }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'no NPU - Recall and the on-device AI features are NOT INSTALLED on this machine. The policy keys are still written as future-proofing, but they are not counted as an applied optimization.'
        }
        @{
            Id = 'G-4.3-PRE22H2'; Section = '4.3'; Title = 'GlobalTimerResolutionRequests'
            When = { param($p, $o) -not (ConvertTo-OptBool $p.OS.Is22H2OrLater) }
            OnIndeterminate = 'Block'
            Kind = 'Skip'; Effect = @{ Skip = @('4.3.GlobalTimer') }
            Reason = 'pre-22H2 - timer resolution is already global, so this value has nothing to restore'
        }

        # ---------------------------------------------------------------- boot
        @{
            Id = 'G-2.3-DUALBOOT'; Section = '2.3'; Title = 'Fast Startup / hibernation'
            When = { param($p, $o) ConvertTo-OptBool $p.Boot.IsDualBoot }
            OnIndeterminate = 'Allow'
            Kind = 'Escalate'; Effect = @{ Escalate = @('2.3') }
            Severity = 'Warning'
            Reason = 'dual-boot detected - Fast Startup leaves NTFS dirty and risks corruption when the other OS mounts the partition. This is mandatory here, not optional.'
        }
        @{
            Id = 'G-MODERNSTANDBY'; Section = '2.2'; Title = 'Legacy power timeouts'
            When = { param($p, $o) ConvertTo-OptBool $p.Power.SupportsModernStandby }
            OnIndeterminate = 'Allow'
            Kind = 'Note'
            Reason = 'Modern Standby (S0ix) platform - some legacy timeouts are ignored by the platform. They are still applied, but will not be reported as effective without verification.'
        }

        # --------------------------------------------------------- opt-in only
        @{
            Id = 'G-8.8-OPTIN'; Section = '8.8'; Title = 'Inbox app removal'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Block'
            Kind = 'Note'
            Reason = 'report-only in this build. Provisioned Appx removal cannot be reliably rolled back, and it buys disk space, not frames.'
        }
        @{
            Id = 'G-8.9-OPTIN'; Section = '8.9'; Title = 'OneDrive removal'
            When = { param($p, $o) $true }
            OnIndeterminate = 'Block'
            Kind = 'Note'
            Reason = 'report-only in this build. "Local-only content" cannot be reliably distinguished from Files-On-Demand placeholders by file attributes alone.'
        }

        # -------------------------------------------------------------- input
        @{
            Id = 'G-6.1-VENDOR'; Section = '6.1'; Title = 'Peripheral vendor utility'
            When = { param($p, $o) ConvertTo-OptBool $p.Input.HasVendorUtility }
            OnIndeterminate = 'Allow'
            Kind = 'Finding'; Severity = 'Warning'
            Reason = 'a peripheral vendor utility is installed and overrides the Windows mouse settings written here. You must also disable acceleration / angle-snapping inside that utility, or section 6.1 achieves nothing.'
        }
    )
}
#endregion src\40-Gates\GateMatrix.ps1

#region src\40-Gates\Resolve-OptGates.ps1
<#
    Gate evaluation.

    Resolve-OptGates is a PURE function of a plain profile hashtable plus the
    run options. It makes zero live calls, which is what makes the whole
    gating matrix testable against synthetic profiles.

    It runs once after detection and produces, in a single pass:
      - the blocked-section set
      - the decision list (which the 1.5.5 console table and the section 14
        markdown report are both projections of)
      - findings, manual items, capability changes and tier clamping
#>

function Resolve-OptGates {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ProfileData,
        [Parameter(Mandatory)][string]$Tier,
        [System.Collections.IDictionary]$Options = @{},
        [array]$Rows
    )

    if (-not $Rows) { $Rows = Get-OptGateMatrix }

    $result = [ordered]@{
        Tier            = $Tier
        Abort           = $false
        AbortReason     = $null
        BlockedSections = New-Object 'System.Collections.Generic.List[string]'
        Escalated       = New-Object 'System.Collections.Generic.List[string]'
        Capabilities    = [ordered]@{}
        Decisions       = New-Object System.Collections.ArrayList
    }

    foreach ($row in $Rows) {
        $verdict = $null
        # Deliberately NOT named $error - that is the automatic variable holding
        # the session's error collection, and assigning it silently succeeds.
        $predicateError = $null

        try {
            $verdict = ConvertTo-OptBool -Value (& $row.When $ProfileData $Options)
        }
        catch {
            $predicateError = $_.Exception.Message
            $verdict = $null
        }

        $indeterminate = ($null -eq $verdict)

        # An indeterminate predicate resolves through the row's DECLARED policy,
        # never through PowerShell truthiness. This is the mechanism that keeps
        # "unknown means skip, not guess" from depending on how each predicate
        # happened to be written.
        $fires = if ($indeterminate) {
            ([string]$row.OnIndeterminate -eq 'Block')
        }
        else { $verdict }

        $reason = [string]$row.Reason
        if ($indeterminate) {
            $reason = if ($fires) {
                "$reason [indeterminate - blocked per fail-safe rule]"
            }
            else {
                "$reason [indeterminate - allowed per row policy]"
            }
        }
        if ($predicateError) { $reason = "$reason [predicate error: $predicateError]" }

        $kind     = [string]$row.Kind
        $severity = if ($row.Contains('Severity') -and $row.Severity) { [string]$row.Severity } else { 'Info' }
        $effect   = if ($row.Contains('Effect')) { $row.Effect } else { @{} }

        if (-not $fires) {
            [void]$result.Decisions.Add([pscustomobject][ordered]@{
                Id = $row.Id; Section = $row.Section; Title = $row.Title
                Decision = 'On'; Kind = $kind
                Reason = 'gate condition not met'; Severity = 'Info'
                Indeterminate = $indeterminate
            })
            continue
        }

        switch ($kind) {
            'Abort' {
                $result.Abort = $true
                $result.AbortReason = $reason
            }
            'ForceTier' {
                $wanted = [string]$effect['Tier']
                # Only ever clamp DOWNWARD. A gate must not raise the tier the
                # user asked for.
                if ((Get-OptTierRank -Tier $wanted) -lt (Get-OptTierRank -Tier $result.Tier)) {
                    $result.Tier = $wanted
                }
                foreach ($s in @($effect['Skip'])) { if ($s) { $result.BlockedSections.Add([string]$s) } }
            }
            'Skip' {
                foreach ($s in @($effect['Skip'])) { if ($s) { $result.BlockedSections.Add([string]$s) } }
            }
            'Capability' {
                $caps = $effect['Capability']
                if ($caps) {
                    foreach ($k in $caps.Keys) { $result.Capabilities[$k] = $caps[$k] }
                }
                foreach ($s in @($effect['Skip'])) { if ($s) { $result.BlockedSections.Add([string]$s) } }
            }
            'Escalate' {
                foreach ($s in @($effect['Escalate'])) { if ($s) { $result.Escalated.Add([string]$s) } }
            }
        }

        $decision = switch ($kind) {
            'Finding'  { 'Finding' }
            'Manual'   { 'Manual' }
            'Note'     { 'NoOp' }
            # An Escalate row RAISES a section's priority - the opposite of a
            # block - so it must never render under "GATED OFF".
            'Escalate' { 'NoOp' }
            default    { 'Off' }
        }

        [void]$result.Decisions.Add([pscustomobject][ordered]@{
            Id = $row.Id; Section = $row.Section; Title = $row.Title
            Decision = $decision; Kind = $kind
            Reason = $reason; Severity = $severity
            Indeterminate = $indeterminate
        })
    }

    return $result
}

function Set-OptGateResults {
    <#
        Applies a Resolve-OptGates result to the live run state. Split from the
        evaluation itself so the evaluation can stay pure and testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$GateResult
    )

    if ($GateResult.Abort) {
        $State.Aborted     = $true
        $State.AbortReason = $GateResult.AbortReason
    }

    $State.Tier = $GateResult.Tier

    foreach ($s in $GateResult.BlockedSections) { [void]$State.BlockedSections.Add($s) }

    foreach ($k in $GateResult.Capabilities.Keys) {
        $State.Capabilities[$k] = $GateResult.Capabilities[$k]
    }

    foreach ($d in $GateResult.Decisions) {
        # Only surface gates that actually did something. Logging ~45 "condition
        # not met" lines would bury the ones that matter.
        if ($d.Decision -eq 'On') { continue }

        [void](Add-OptDecision -State $State -Id $d.Id -Section $d.Section `
            -Decision $d.Decision -Reason $d.Reason -Title $d.Title -Severity $d.Severity)
    }
}
#endregion src\40-Gates\Resolve-OptGates.ps1

#region src\50-Sections\Section-00-SecurityFlight.ps1
<#
    Section 0 - anti-cheat preflight and postflight.

    These are the ONLY checks in the script that are fatal. Everything else
    degrades to a warning.

    The single most important assertion here is negative: a VBS/IOMMU regression
    is the worst outcome this script can produce (spec 14), so if VBS drops
    between preflight and postflight the run does not merely report it - it
    rolls the security-adjacent changes back and tells the user not to reboot.
#>

function Invoke-OptSecurityPreflight {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 0 - Anti-cheat preflight'

    $s = $State.Profile.Security
    $hasAc = [bool]$s.HasKernelAntiCheat

    $snapshot = [ordered]@{
        SecureBootEnabled       = $s.SecureBootEnabled
        TpmReady                = $s.TpmReady
        VbsStatus               = $s.VbsStatus
        VbsRunning              = $s.VbsRunning
        HvciRunning             = $s.HvciRunning
        SecurityServicesRunning = @($s.SecurityServicesRunning)
        HypervisorLaunchType    = $s.HypervisorLaunchType
        HypervisorIommuPolicy   = $s.HypervisorIommuPolicy
        IommuEnabled            = $s.IommuEnabled
        AntiCheat               = @($s.AntiCheat | ForEach-Object {
                                    @{ Name = $_.Name; DriverRunning = $_.DriverRunning; ServiceEnabled = $_.ServiceEnabled }
                                 })
    }
    $State['SecuritySnapshot'] = $snapshot

    $fatal = New-Object System.Collections.ArrayList

    if ($hasAc) {
        Write-OptLog -Level Info "Kernel anti-cheat detected: $((@($s.AntiCheat | ForEach-Object { $_.Name })) -join ', ') - section 0 checks are FATAL"

        if ($s.SecureBootEnabled -eq $false) { [void]$fatal.Add('Secure Boot is disabled') }
        if ($s.TpmReady -eq $false)          { [void]$fatal.Add('TPM is not present or not ready') }
    }
    else {
        Write-OptLog -Level Info 'No kernel anti-cheat detected - section 0 checks downgraded to warnings'
        # Still never DISABLE Secure Boot or TPM, since one may be installed later.
    }

    foreach ($f in $fatal) {
        [void](Add-OptFinding -State $State -Id 'S-0-FATAL' -Section '0' `
            -Title 'Anti-cheat preflight failure' -Reason $f -Severity 'Critical')
    }

    if ($fatal.Count -gt 0) {
        $State.Aborted = $true
        $State.AbortReason = "anti-cheat preflight failed: $($fatal -join '; ')"
        return @{ Passed = $false; Fatal = @($fatal) }
    }

    Write-OptLog -Level Good ("Secure Boot {0}, TPM {1}, VBS {2}, HVCI {3}, IOMMU {4}" -f `
        (Format-OptTriState $s.SecureBootEnabled), (Format-OptTriState $s.TpmReady),
        (Format-OptTriState $s.VbsRunning), (Format-OptTriState $s.HvciRunning),
        (Format-OptTriState $s.IommuEnabled))

    foreach ($ac in $s.AntiCheat) {
        # Assert PRESENT and NOT DISABLED - never "Running". These services are
        # Stopped/Manual by design and start on demand when the client launches,
        # so a Running assertion would false-fail on every single run.
        $ok = $ac.DriverPresent -or $ac.ServicePresent
        Write-OptLog -Level $(if ($ok) { 'Good' } else { 'Warn' }) `
            ("{0}: drivers [{1}] services [{2}]" -f $ac.Name, (@($ac.DriverStates) -join ' '), (@($ac.ServiceStates) -join ' '))
    }

    return @{ Passed = $true; Fatal = @() }
}

function Invoke-OptSecurityPostflight {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 0 - Anti-cheat postflight'

    $before = $State['SecuritySnapshot']
    if (-not $before) { return @{ Passed = $true; Regressions = @() } }

    # Re-detect rather than trusting the preflight profile.
    $after = Get-OptSecurityInfo -State $State

    $regressions = New-Object System.Collections.ArrayList

    if ($before.SecureBootEnabled -eq $true -and $after.SecureBootEnabled -ne $true) {
        [void]$regressions.Add('Secure Boot is no longer enabled')
    }
    if ($before.TpmReady -eq $true -and $after.TpmReady -ne $true) {
        [void]$regressions.Add('TPM is no longer ready')
    }
    if ($before.VbsRunning -eq $true -and $after.VbsRunning -ne $true) {
        [void]$regressions.Add('VBS is no longer running')
    }
    if ($before.IommuEnabled -eq $true -and $after.IommuEnabled -eq $false) {
        [void]$regressions.Add('IOMMU is no longer enabled')
    }

    foreach ($acBefore in @($before.AntiCheat)) {
        $acAfter = @($after.AntiCheat) | Where-Object { $_.Name -eq $acBefore.Name } | Select-Object -First 1
        if (-not $acAfter) { [void]$regressions.Add("$($acBefore.Name) is no longer detected"); continue }
        if ($acBefore.DriverRunning -and -not $acAfter.DriverRunning) {
            [void]$regressions.Add("$($acBefore.Name) driver is no longer running")
        }
        if ($acBefore.ServiceEnabled -and -not $acAfter.ServiceEnabled) {
            [void]$regressions.Add("$($acBefore.Name) service has been disabled")
        }
    }

    if ($regressions.Count -eq 0) {
        Write-OptLog -Level Good 'No security or anti-cheat regressions - Secure Boot, TPM, VBS, IOMMU and anti-cheat all unchanged'
        return @{ Passed = $true; Regressions = @() }
    }

    foreach ($r in $regressions) {
        [void](Add-OptFinding -State $State -Id 'S-0-REGRESSION' -Section '0' `
            -Title 'SECURITY REGRESSION' -Reason $r -Severity 'Critical')
        Write-OptLog -Level Error $r
    }

    # Act, do not merely report. Reporting the worst outcome the script can
    # produce while leaving the machine in that state is the wrong behaviour.
    Write-OptLog -Level Error 'DO NOT REBOOT until this is resolved.'
    Invoke-OptSecurityAutoRollback -State $State

    return @{ Passed = $false; Regressions = @($regressions) }
}

function Invoke-OptSecurityAutoRollback {
    <#
        Rolls back ONLY the security-adjacent changes, newest first, leaving the
        rest of the run intact.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $pattern = 'hypervisorlaunchtype|DeviceGuard|HypervisorEnforcedCodeIntegrity|EnableVirtualizationBasedSecurity|LsaCfgFlags'

    $suspects = @($State.Changes | Where-Object {
        "$($_.Path)\$($_.Name)" -match $pattern -or [string]$_.Type -eq 'BcdEditValue'
    } | Sort-Object -Property @{ Expression = { [int]$_.Id } } -Descending)

    if ($suspects.Count -eq 0) {
        Write-OptLog -Level Warn 'No security-adjacent changes were made by this run - the regression has another cause (firmware, driver, or another tool).'
        return
    }

    Write-OptLog -Level Warn "Auto-rolling back $($suspects.Count) security-adjacent change(s)..."
    foreach ($c in $suspects) {
        try {
            $r = Invoke-OptRollbackEntry -State $State -Change $c
            Write-OptLog -Level Info "[$($c.Id)] $($r.Result): $($r.Detail)"
        }
        catch {
            Write-OptLog -Level Error "[$($c.Id)] auto-rollback failed: $($_.Exception.Message)"
        }
    }
}
#endregion src\50-Sections\Section-00-SecurityFlight.ps1

#region src\50-Sections\Section-02-Power.ps1
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
    Invoke-OptPowerCfgSetting -State $State -SubGroup 'SUB_VIDEO' -Setting 'VIDEOIDLE' -Value 0 -Title 'Never turn off display'

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
    # the adapter that actually carries the default route.
    $adapterName = [string]$p.Network.ActiveAdapterName
    if ($adapterName) {
        $r = Invoke-OptCmdletChange -State $State -Description "Disable-NetAdapterPowerManagement $adapterName" -Action {
            Disable-NetAdapterPowerManagement -Name $adapterName -ErrorAction Stop -Confirm:$false
        }
        if ($r.Success) {
            $nicChange = New-OptChangeRecord -State $State -Type 'NetAdapterPowerMgmt' -Section '2.4' -Tier 'Safe' `
                -Path $adapterName -Name 'AllowComputerToTurnOffDevice' `
                -Target @{ AdapterName = $adapterName } `
                -OldValue 'Enabled' -NewValue 'Disabled' -VerifyMode 'None'
            if ($State.DryRun) { [void]$State.Changes.Add($nicChange) } else { [void](Add-OptChange -State $State -Change $nicChange) }
        }

        [void](Add-OptDecision -State $State -Id 'S-2.4-NIC' -Section '2.4' `
            -Decision $(if ($r.Success) { 'Applied' } else { 'Failed' }) `
            -Title 'NIC power management' `
            -Severity $(if ($r.Success) { 'Info' } else { 'Warning' }) `
            -Reason $(if ($r.Success) { "power saving disabled on $adapterName" } else { [string]$r.Error }))
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

    if ($p.Audio.HasUsbDac) {
        [void](Add-OptDecision -State $State -Id 'S-2.4-USBAUDIO' -Section '2.4' -Decision 'NoOp' `
            -Title 'USB audio endpoint' `
            -Reason "USB audio device detected ($($p.Audio.DefaultName)) - included in the USB power-management sweep")
    }

    $done = 0
    foreach ($dev in $targets) {
        $instance = [string]$dev.InstanceId
        $r = Invoke-OptCmdletChange -State $State -Description "disable USB power saving for $instance" -Action {
            $node = Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop |
                    Where-Object { $_.InstanceName -like "*$($instance -replace '\\','\\')*" }
            foreach ($n in $node) {
                if ($n.Enable) { Set-CimInstance -InputObject $n -Property @{ Enable = $false } -ErrorAction Stop }
            }
        }
        if ($r.Success) { $done++ }
    }

    if ($done -gt 0 -or $State.DryRun) {
        # Recorded as a single bulk entry with an explicit endpoint list, so the
        # sweep is not an unrecorded mutation. Reversible='Partial' is honest:
        # rollback re-enables power management on the endpoints still present,
        # and silently skips any device that has since been unplugged.
        $usbChange = New-OptChangeRecord -State $State -Type 'UsbPowerMgmt' -Section '2.4' -Tier 'Safe' `
            -Path 'MSPower_DeviceEnable' -Name 'UsbEndpoints' `
            -Target @{ InstanceIds = @($targets | ForEach-Object { [string]$_.InstanceId }) } `
            -OldValue $true -NewValue $false -Reversible 'Partial' -VerifyMode 'None'
        if ($State.DryRun) { [void]$State.Changes.Add($usbChange) } else { [void](Add-OptChange -State $State -Change $usbChange) }
    }

    [void](Add-OptDecision -State $State -Id 'S-2.4-USB' -Section '2.4' -Decision 'Applied' `
        -Title 'USB device power management' `
        -Reason "processed $done input/audio USB endpoint(s) derived from the detected profile")
}
#endregion src\50-Sections\Section-02-Power.ps1

#region src\50-Sections\Section-03-Gpu.ps1
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

    Invoke-OptSection31Registry   -State $State
    Invoke-OptSection32Mpo        -State $State
    Invoke-OptSection33PerApp     -State $State
    Invoke-OptSection38Refresh    -State $State
}

function Invoke-OptSection31Registry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Hardware-accelerated GPU scheduling. Required for AMD Anti-Lag and NVIDIA
    # Reflex low-latency paths to work correctly. Gated off for Intel Arc, where
    # behaviour is driver-version dependent.
    if (Test-OptSectionEnabled -State $State -Section '3.1.HwSchMode') {
        Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' `
            -Name 'HwSchMode' -Type DWord -Value 2 -Section '3.1' -Tier 'Safe' `
            -Title 'Hardware-accelerated GPU scheduling' -RequiresReboot -VerifyMode PostReboot | Out-Null
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
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Disabling Multi-Plane Overlay is the standard fix for desktop flicker and
    # micro-stutter on RDNA hardware, but it can INCREASE desktop compositing
    # cost - so it is Experimental, and rollback is a simple value delete.
    Set-OptRegistryValue -State $State -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' `
        -Name 'OverlayTestMode' -Type DWord -Value 5 -Section '3.2' -Tier 'Experimental' `
        -Title 'Disable Multi-Plane Overlay' -RequiresReboot -VerifyMode PostReboot | Out-Null

    if (Test-OptTier -State $State -Required 'Experimental') {
        [void](Add-OptDecision -State $State -Id 'S-3.2-NOTE' -Section '3.2' -Decision 'NoOp' `
            -Title 'MPO disable expectations' `
            -Reason 'only apply this if you actually see desktop flicker or micro-stutter - it can increase compositing cost otherwise')
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
#endregion src\50-Sections\Section-03-Gpu.ps1

#region src\50-Sections\Section-04-Scheduler.ps1
<#
    Section 4 - MMCSS, priority separation, timer configuration.
#>

function Invoke-OptSection04 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 4 - Scheduler, timers, MMCSS'

    Invoke-OptSection41Mmcss    -State $State
    Invoke-OptSection42Priority -State $State
    Invoke-OptSection43Timers   -State $State
}

function Invoke-OptSection41Mmcss {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    $gamesKey   = "$profileKey\Tasks\Games"

    # SystemResponsiveness is clamped internally; 10 is the meaningful floor,
    # not 0. NetworkThrottlingIndex is the half of this block with a real,
    # measurable effect on a high-packet-rate title - and unlike section 7.3 it
    # applies to UDP, which is what CS2 actually uses.
    Set-OptRegistryValue -State $State -Path $profileKey -Name 'SystemResponsiveness' `
        -Type DWord -Value 10 -Section '4.1' -Tier 'Aggressive' `
        -Title 'MMCSS SystemResponsiveness' | Out-Null

    Set-OptRegistryValue -State $State -Path $profileKey -Name 'NetworkThrottlingIndex' `
        -Type DWord -Value 4294967295 -Section '4.1' -Tier 'Aggressive' `
        -Title 'MMCSS NetworkThrottlingIndex (disabled)' | Out-Null

    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'GPU Priority' `
        -Type DWord -Value 8 -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games GPU Priority' | Out-Null
    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'Priority' `
        -Type DWord -Value 6 -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games Priority' | Out-Null
    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'Scheduling Category' `
        -Type String -Value 'High' -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games Scheduling Category' | Out-Null
    Set-OptRegistryValue -State $State -Path $gamesKey -Name 'SFIO Priority' `
        -Type String -Value 'High' -Section '4.1' -Tier 'Aggressive' -Title 'MMCSS Games SFIO Priority' | Out-Null
}

function Invoke-OptSection42Priority {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # 0x26 = 38. Honest note for the report: the Win11 desktop default of 2
    # already resolves to short quantum / variable / 3:1, so this makes the
    # existing behaviour explicit rather than changing it. Impact is near-zero.
    # Deliberately NOT 0x2A or 0x18 - those force fixed/long quantums, which is
    # worse for a foreground game.
    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' `
        -Name 'Win32PrioritySeparation' -Type DWord -Value 0x26 -Section '4.2' -Tier 'Aggressive' `
        -Title 'Win32PrioritySeparation' -RequiresReboot -VerifyMode PostReboot | Out-Null

    [void](Add-OptDecision -State $State -Id 'S-4.2-NOTE' -Section '4.2' -Decision 'NoOp' `
        -Title 'Priority separation expectations' `
        -Reason 'Windows 11 already defaults to short/variable/3:1 - this makes it explicit rather than inherited. Expect no measurable change.')
}

function Invoke-OptSection43Timers {
    <#
        Section 4.3 is a CLEANUP step, not an addition.

        Windows 11 22H2+ made timer resolution per-process, so the correct
        action is removing damage left by other optimization scripts, not adding
        anything. On a clean machine every one of these reports "element not
        found", which is the desired state.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not (Test-OptSectionEnabled -State $State -Section '4.3')) {
        [void](Add-OptDecision -State $State -Id 'S-4.3' -Section '4.3' -Decision 'Off' `
            -Title 'bcdedit timer cleanup' -Reason 'section gated off')
        return
    }

    if (-not $State.Capabilities.BcdEdit) {
        [void](Add-OptDecision -State $State -Id 'S-4.3-BCD' -Section '4.3' -Decision 'Off' `
            -Title 'bcdedit timer cleanup' -Severity 'Warning' `
            -Reason 'bcdedit changes are blocked (BitLocker protection is on) - registry-only tweaks still proceed')
        return
    }

    $elements = @('useplatformclock', 'useplatformtick', 'disabledynamictick', 'tscsyncpolicy')

    # Read the current boot configuration once so we know what is actually
    # present. Issuing /deletevalue blindly works, but then the report cannot
    # honestly say what was removed versus what was never there.
    $present = @{}
    $enum = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' -ArgumentList @('/enum', '{current}') -ReadOnly
    if ($enum.Success) {
        foreach ($line in (Get-OptCommandLines -Text $enum.StdOut)) {
            foreach ($e in $elements) {
                if ($line -match "^\s*$e\s+(\S+)") { $present[$e] = $Matches[1] }
            }
        }
    }

    foreach ($element in $elements) {
        if (-not $present.Contains($element)) {
            [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'NoOp' `
                -Title "bcdedit $element" -Reason 'not set - already in the desired state')
            continue
        }

        $old = $present[$element]
        $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' `
             -ArgumentList @('/deletevalue', $element) -Purpose "remove $element"

        if ($State.DryRun) {
            $planned = New-OptChangeRecord -State $State -Type 'BcdEditValue' -Section '4.3' -Tier 'Safe' `
                -Path 'bcdedit {current}' -Name $element -Target @{ Element = $element } `
                -OldValue $old -NewValue $null -ExistedBefore $true `
                -RequiresReboot -VerifyMode 'PostReboot'
            [void]$State.Changes.Add($planned)

            [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'Applied' `
                -Title "bcdedit $element" -Reason "would remove (currently '$old')")
            continue
        }

        # "The specified element was not found" on stderr with a non-zero exit
        # is a success condition here, which is exactly why every native call
        # runs through Invoke-OptNativeCommand with a locally relaxed
        # $ErrorActionPreference.
        if (-not $r.Success -and $r.StdErr -notmatch 'element was not found|cannot find') {
            [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'Failed' `
                -Title "bcdedit $element" -Reason $r.StdErr.Trim() -Severity 'Error')
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'BcdEditValue' -Section '4.3' -Tier 'Safe' `
            -Path 'bcdedit {current}' -Name $element `
            -Target @{ Element = $element } `
            -OldValue $old -NewValue $null -ExistedBefore $true `
            -RequiresReboot -VerifyMode 'PostReboot'
        [void](Add-OptChange -State $State -Change $change)

        [void](Add-OptDecision -State $State -Id "S-4.3-$element" -Section '4.3' -Decision 'Applied' `
            -Title "bcdedit $element" -Reason "removed (was '$old') - this is cleanup of a known-harmful tweak")
    }

    # Optional, and honestly flagged: restores pre-22H2 global timer resolution.
    if (Test-OptSectionEnabled -State $State -Section '4.3.GlobalTimer') {
        Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' `
            -Name 'GlobalTimerResolutionRequests' -Type DWord -Value 1 `
            -Section '4.3.GlobalTimer' -Tier 'Experimental' `
            -Title 'GlobalTimerResolutionRequests' -RequiresReboot -VerifyMode PostReboot | Out-Null

        [void](Add-OptDecision -State $State -Id 'S-4.3-GLOBALTIMER-NOTE' -Section '4.3' -Decision 'NoOp' `
            -Title 'GlobalTimerResolutionRequests expectations' `
            -Reason 'measured benefit in CS2 is inconsistent - A/B test this one specifically rather than assuming it helped')
    }

    # Explicitly NOT implemented: HPET forcing/disabling via bcdedit. Leave the
    # firmware HPET setting at its default (spec 4.3).
}
#endregion src\50-Sections\Section-04-Scheduler.ps1

#region src\50-Sections\Section-05-MemStorage.ps1
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

    # These are classic non-idempotent commands, so query first in every case.
    $settings = @(
        @{ Name = 'disablelastaccess';   Value = 1; Title = 'Disable last-access timestamps' }
        @{ Name = 'disable8dot3name';    Value = 1; Title = 'Disable 8.3 name creation' }
        @{ Name = 'DisableDeleteNotify'; Value = 0; Title = 'Ensure TRIM is enabled' }
    )

    foreach ($s in $settings) {
        $q = Invoke-OptNativeCommand -State $State -FilePath 'fsutil.exe' `
             -ArgumentList @('behavior', 'query', $s.Name) -ReadOnly

        $current = $null
        foreach ($line in (Get-OptCommandLines -Text $q.StdOut)) {
            if ($line -match '=\s*(\d+)') { $current = [int]$Matches[1]; break }
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
#endregion src\50-Sections\Section-05-MemStorage.ps1

#region src\50-Sections\Section-06-Input.ps1
<#
    Section 6 - Input and foreground process priority.
#>

function Invoke-OptSection06 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 6 - Input and process priority'

    Invoke-OptSection61Mouse         -State $State
    Invoke-OptSection62Accessibility -State $State
    Invoke-OptSection63Queues        -State $State
    Invoke-OptSection64Priority      -State $State
}

function Invoke-OptSection61Mouse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Registry FIRST, then the live SPI call. Ordering matters: SPI_SETMOUSE with
    # SPIF_UPDATEINIFILE writes these same values itself, so the pre-change state
    # has to be captured into the manifest before that happens - and the registry
    # values are what persist across logon.
    foreach ($v in @(
        @{ N = 'MouseSpeed';      V = '0' }
        @{ N = 'MouseThreshold1'; V = '0' }
        @{ N = 'MouseThreshold2'; V = '0' }
    )) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\Control Panel\Mouse' -Name $v.N `
            -Type String -Value $v.V -Section '6.1' -Tier 'Safe' `
            -Title "Mouse acceleration off ($($v.N))" | Out-Null
    }

    # Pointer speed slider. 10 is the 6/11 notch - any other value applies a
    # scaling multiplier to raw input.
    $mouse = $State.Profile.Input.Mouse
    if ($mouse -and $null -ne $mouse.Speed -and [int]$mouse.Speed -ne 10) {
        Set-OptRegistryValue -State $State -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSensitivity' `
            -Type String -Value '10' -Section '6.1' -Tier 'Safe' `
            -Title 'Pointer speed to 6/11 (no scaling)' | Out-Null
    }

    if (-not (Test-OptSectionEnabled -State $State -Section '6.1')) { return }
    if (-not (Test-OptTier -State $State -Required 'Safe')) { return }

    # Apply live so no logoff is needed - but only when the elevated identity IS
    # the interactive user. SystemParametersInfo affects the CALLING session, so
    # running it as a different admin would apply to the wrong session while the
    # registry writes went to the right one.
    if (-not $State.TargetUser.IsCurrent) {
        $State.LogoffRequired = $true
        [void](Add-OptDecision -State $State -Id 'S-6.1-SPI' -Section '6.1' -Decision 'NoOp' `
            -Title 'Live mouse setting refresh' -Severity 'Warning' `
            -Reason 'elevated identity is not the interactive user - registry written, but a logoff is required for it to take effect')
        return
    }

    if ($State.Capabilities.Interop -and -not $State.DryRun) {
        $applied = [Cs2Opt.Input.Api]::SetMouse(0, 0, 0)
        [void](Add-OptDecision -State $State -Id 'S-6.1-SPI' -Section '6.1' `
            -Decision $(if ($applied) { 'Applied' } else { 'Failed' }) `
            -Title 'Live mouse setting refresh' `
            -Reason $(if ($applied) { 'Enhance pointer precision disabled without requiring a logoff' } else { 'SystemParametersInfo call failed - logoff required' }))
        if (-not $applied) { $State.LogoffRequired = $true }
    }
}

function Invoke-OptSection62Accessibility {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Stops the sticky-keys popup appearing mid-round from shift-spam.
    foreach ($v in @(
        @{ P = 'HKCU:\Control Panel\Accessibility\StickyKeys';        N = 'Flags'; V = '506' }
        @{ P = 'HKCU:\Control Panel\Accessibility\Keyboard Response'; N = 'Flags'; V = '122' }
        @{ P = 'HKCU:\Control Panel\Accessibility\ToggleKeys';        N = 'Flags'; V = '58'  }
    )) {
        Set-OptRegistryValue -State $State -Path $v.P -Name $v.N -Type String -Value $v.V `
            -Section '6.2' -Tier 'Safe' -Title "Accessibility hotkey off ($(Split-Path -Leaf $v.P))" | Out-Null
    }
}

function Invoke-OptSection63Queues {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    # Marginal and unmeasured - included for completeness and flagged as such.
    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters' `
        -Name 'MouseDataQueueSize' -Type DWord -Value 50 -Section '6.3' -Tier 'Experimental' `
        -Title 'Mouse data queue size' -RequiresReboot -VerifyMode PostReboot | Out-Null

    Set-OptRegistryValue -State $State -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters' `
        -Name 'KeyboardDataQueueSize' -Type DWord -Value 50 -Section '6.3' -Tier 'Experimental' `
        -Title 'Keyboard data queue size' -RequiresReboot -VerifyMode PostReboot | Out-Null

    if (Test-OptTier -State $State -Required 'Experimental') {
        [void](Add-OptDecision -State $State -Id 'S-6.3-NOTE' -Section '6.3' -Decision 'NoOp' `
            -Title 'Device queue size expectations' `
            -Reason 'default is 100; this is unmeasured and expected to show nothing. Included only because it appears on every list.')
    }
}

function Invoke-OptSection64Priority {
    <#
        The anti-cheat-safe way to raise process priority: the kernel applies
        IFEO at process creation, so nothing injects into cs2.exe's address
        space. Never Realtime, and never combined with a -high launch option.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile
    if (-not $p.Games.Cs2Installed) { return }

    $exeName = Split-Path -Leaf ([string]$p.Games.Cs2ExePath)
    $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exeName\PerfOptions"

    # 3 = High. (1=Idle, 2=Normal, 3=High, 5=BelowNormal, 6=AboveNormal.)
    Set-OptRegistryValue -State $State -Path $key -Name 'CpuPriorityClass' -Type DWord -Value 3 `
        -Section '6.4' -Tier 'Aggressive' -Title 'CS2 process priority (High, via IFEO)' | Out-Null

    Set-OptRegistryValue -State $State -Path $key -Name 'IoPriority' -Type DWord -Value 3 `
        -Section '6.4' -Tier 'Aggressive' -Title 'CS2 I/O priority' | Out-Null

    if ($p.CPU.CcdCount -and [int]$p.CPU.CcdCount -gt 1) {
        [void](Add-OptDecision -State $State -Id 'S-6.4-CCD' -Section '6.4' -Decision 'Manual' `
            -Title 'CCD pinning (multi-CCD part)' `
            -Reason 'CCD0 pinning is a legitimate manual experiment on dual-CCD X3D parts, but it is workload- and BIOS-dependent, so this script reports it rather than implementing it')
    }
}
#endregion src\50-Sections\Section-06-Input.ps1

#region src\50-Sections\Section-07-Network.ps1
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
#endregion src\50-Sections\Section-07-Network.ps1

#region src\50-Sections\Section-08-Background.ps1
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

    Set-OptRegistryValue -State $State -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' `
        -Name 'VisualFXSetting' -Type DWord -Value 2 -Section '8.3' -Tier 'Aggressive' `
        -Title 'Visual effects: adjust for best performance' | Out-Null

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
#endregion src\50-Sections\Section-08-Background.ps1

#region src\50-Sections\Section-09-Defender.ps1
<#
    Section 9 - Defender exclusions.

    Real-time scanning of shader-cache writes and VPK reads is a measurable
    stutter source. Exclusions get most of the benefit of "disable Defender"
    with none of the trust-signal cost - real-time protection stays ON, which
    section 0 requires.

    Deliberately NOT excluded: FACEIT's own directories. Leave the anti-cheat's
    footprint scanned.
#>

function Invoke-OptSection09 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 9 - Defender exclusions'

    if (-not (Test-OptSectionEnabled -State $State -Section '9')) {
        [void](Add-OptDecision -State $State -Id 'S-9' -Section '9' -Decision 'Off' `
            -Title 'Defender exclusions' -Reason 'section gated off')
        return
    }
    if (-not (Test-OptTier -State $State -Required 'Aggressive')) {
        [void](Add-OptDecision -State $State -Id 'S-9' -Section '9' -Decision 'Off' `
            -Title 'Defender exclusions' -Reason 'requires tier Aggressive')
        return
    }

    $p = $State.Profile

    $current = $null
    try { $current = Get-MpPreference -ErrorAction Stop }
    catch {
        [void](Add-OptDecision -State $State -Id 'S-9-PREF' -Section '9' -Decision 'Failed' `
            -Title 'Defender exclusions' -Severity 'Warning' `
            -Reason "could not read Defender preferences: $($_.Exception.Message)")
        return
    }

    # Get-MpPreference returns $null - not @() - when a list is empty, so .Count
    # would throw under StrictMode without the wrap.
    $existingPaths     = @($current.ExclusionPath)
    $existingProcesses = @($current.ExclusionProcess)

    $paths = New-Object System.Collections.ArrayList
    foreach ($lib in @($p.Games.LibraryPaths)) { if ($lib) { [void]$paths.Add([string]$lib) } }

    # Vendor shader cache. Only the detected vendor's path is added - adding an
    # NVIDIA cache path on an AMD machine would be a meaningless exclusion.
    switch ($p.GPU.PrimaryVendor) {
        'AMD'    { [void]$paths.Add("$env:LOCALAPPDATA\AMD") }
        'NVIDIA' { [void]$paths.Add("$env:LOCALAPPDATA\NVIDIA"); [void]$paths.Add("$env:LOCALAPPDATA\NVIDIA Corporation") }
        'Intel'  { [void]$paths.Add("$env:LOCALAPPDATA\Intel") }
    }

    foreach ($path in $paths) {
        $normalized = ConvertTo-OptNormalizedPath -Path $path
        if (-not $normalized) { continue }

        if (@($existingPaths | Where-Object { [string]$_ -eq $normalized }).Count -gt 0) {
            [void](Add-OptDecision -State $State -Id "S-9-PATH-$normalized" -Section '9' -Decision 'NoOp' `
                -Title 'Defender path exclusion' -Reason "already excluded: $normalized")
            continue
        }

        $r = Invoke-OptCmdletChange -State $State -Description "Add-MpPreference -ExclusionPath $normalized" -Action {
            Add-MpPreference -ExclusionPath $normalized -ErrorAction Stop
        }

        if (-not $r.Success) {
            [void](Add-OptDecision -State $State -Id "S-9-PATH-$normalized" -Section '9' -Decision 'Failed' `
                -Title 'Defender path exclusion' -Severity 'Warning' `
                -Reason "$($r.Error) - Tamper Protection can silently reject exclusion changes")
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'DefenderExclusion' -Section '9' -Tier 'Aggressive' `
            -Path 'Defender' -Name $normalized -Target @{ Kind = 'Path' } `
            -OldValue $null -NewValue $normalized -ExistedBefore $false
        if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

        [void](Add-OptDecision -State $State -Id "S-9-PATH-$normalized" -Section '9' -Decision 'Applied' `
            -Title 'Defender path exclusion' -Reason "excluded $normalized")
    }

    # Process exclusions. cs2.exe only if CS2 is actually installed.
    $processes = @('steam.exe', 'steamwebhelper.exe')
    if ($p.Games.Cs2Installed) { $processes = @('cs2.exe') + $processes }

    foreach ($proc in $processes) {
        if (@($existingProcesses | Where-Object { [string]$_ -eq $proc }).Count -gt 0) {
            [void](Add-OptDecision -State $State -Id "S-9-PROC-$proc" -Section '9' -Decision 'NoOp' `
                -Title 'Defender process exclusion' -Reason "already excluded: $proc")
            continue
        }

        $r = Invoke-OptCmdletChange -State $State -Description "Add-MpPreference -ExclusionProcess $proc" -Action {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
        }

        if (-not $r.Success) {
            [void](Add-OptDecision -State $State -Id "S-9-PROC-$proc" -Section '9' -Decision 'Failed' `
                -Title 'Defender process exclusion' -Severity 'Warning' -Reason $r.Error)
            continue
        }

        $change = New-OptChangeRecord -State $State -Type 'DefenderExclusion' -Section '9' -Tier 'Aggressive' `
            -Path 'Defender' -Name $proc -Target @{ Kind = 'Process' } `
            -OldValue $null -NewValue $proc -ExistedBefore $false
        if ($State.DryRun) { [void]$State.Changes.Add($change) } else { [void](Add-OptChange -State $State -Change $change) }

        [void](Add-OptDecision -State $State -Id "S-9-PROC-$proc" -Section '9' -Decision 'Applied' `
            -Title 'Defender process exclusion' -Reason "excluded $proc")
    }

    [void](Add-OptDecision -State $State -Id 'S-9-NOTE' -Section '9' -Decision 'NoOp' `
        -Title 'Defender scope' `
        -Reason 'real-time protection stays ON and FACEIT directories are deliberately left scanned - only game asset and shader-cache paths are excluded')
}
#endregion src\50-Sections\Section-09-Defender.ps1

#region src\50-Sections\Section-10-Vbs.ps1
<#
    Section 10 - Virtualization-Based Security: PRESERVE, DO NOT DISABLE.

    This section is REPORT-ONLY on any machine with a kernel anti-cheat.

    Most CS2 optimization guides tell you to disable VBS for the CPU headroom.
    That advice is wrong for any machine running FACEIT AC: FACEIT requires VBS
    in order to support IOMMU, which is the mechanism that neutralizes DMA-card
    cheats. TPM 2.0 and Secure Boot became mandatory for all players on
    25 Nov 2025; IOMMU and VBS have been enforced in expanding waves since
    April 2025.

    So on a FACEIT machine VBS is a DEPENDENCY, not an optimization target, and
    "VBS is not running" is a blocking problem to fix - never a tweak that
    succeeded.
#>

function Invoke-OptSection10 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 10 - VBS / IOMMU compliance (report only)'

    $s = $State.Profile.Security

    if (-not $s.HasKernelAntiCheat) {
        [void](Add-OptDecision -State $State -Id 'S-10-NOAC' -Section '10' -Decision 'NoOp' `
            -Title 'VBS state' -Severity 'Warning' `
            -Reason 'no kernel anti-cheat detected, so disabling VBS is technically available under Experimental. This script still will not do it by default - the DMA-cheat protection is worth more than the CPU headroom, and installing FACEIT later would immediately require it back.')
        return
    }

    # --- compliance summary ---
    $compliant = ($s.VbsRunning -eq $true) -and ($s.IommuEnabled -ne $false) -and
                 ($s.SecureBootEnabled -eq $true) -and ($s.TpmReady -eq $true)

    if ($compliant) {
        Write-OptLog -Level Good 'FACEIT security requirements are satisfied: Secure Boot ON, TPM ready, VBS running, IOMMU enabled'
        [void](Add-OptDecision -State $State -Id 'S-10-COMPLIANT' -Section '10' -Decision 'NoOp' `
            -Title 'FACEIT compliance' `
            -Reason "Secure Boot ON, TPM ready, VBS running, IOMMU $(Format-OptTriState $s.IommuEnabled) ($($s.IommuEvidence -join '; ')) - nothing to change")
    }

    if ($s.VbsRunning -eq $false) {
        [void](Add-OptFinding -State $State -Id 'S-10-VBS' -Section '10' `
            -Title 'VBS is not running but FACEIT AC is installed' -Severity 'Critical' `
            -Reason 'Remediation: 1) enable IOMMU in firmware (VT-d on Intel, IOMMU/AMD-Vi plus SVM on AMD); 2) ensure HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity = 1 and RequirePlatformSecurityFeatures = 1 or 3; 3) confirm bcdedit hypervisorlaunchtype is Auto, not Off - a previous "optimization" script is the most common cause; 4) reboot and re-verify.')
    }

    if ($s.IommuEnabled -eq $false) {
        [void](Add-OptFinding -State $State -Id 'S-10-IOMMU' -Section '10' `
            -Title 'IOMMU is not enabled but FACEIT AC is installed' -Severity 'Critical' `
            -Reason 'This is a firmware change, not something a script can do. Enable VT-d (Intel) or IOMMU / AMD-Vi plus SVM (AMD) in BIOS.')
    }
    elseif ($null -eq $s.IommuEnabled) {
        # Indeterminate is NOT a failure. Reporting it as one would send the
        # user into their BIOS for nothing.
        [void](Add-OptDecision -State $State -Id 'S-10-IOMMU-UNKNOWN' -Section '10' -Decision 'Unverified' `
            -Title 'IOMMU state could not be confirmed' `
            -Reason 'no positive signal was available. Check msinfo32 for "Kernel DMA Protection" and the "Virtualization-based security" fields - that is what FACEIT support asks for. This is not being reported as a failure.')
    }

    if ([string]$s.HypervisorLaunchType -match '^Off') {
        [void](Add-OptFinding -State $State -Id 'S-10-HVLAUNCH' -Section '10' `
            -Title 'hypervisorlaunchtype is Off' -Severity 'Critical' `
            -Reason 'This silently prevents VBS from running, so the machine fails the FACEIT check with no obvious cause. Fix with: bcdedit /set hypervisorlaunchtype Auto')
    }

    # --- 10.4: the one place performance is still recoverable ---
    if ($s.HvciRunning -eq $true) {
        [void](Add-OptManual -State $State -Id 'S-10.4' -Section '10.4' `
            -Title 'Memory Integrity (HVCI) - user-confirmed experiment only' `
            -Reason 'left exactly as-is by design' `
            -Detail @'
VBS and HVCI are not the same thing. VBS is the hypervisor-backed security
boundary; HVCI is one service running on top of it, and HVCI carries the larger
share of the CPU cost because it forces code-integrity checks through the
hypervisor.

FACEIT's published requirements name IOMMU and VBS throughout and do not name
HVCI / Memory Integrity. So the likely performance-optimal COMPLIANT
configuration is IOMMU on, VBS on, Memory Integrity off, Credential Guard off.

Treat that as a HYPOTHESIS, not a fact. This script will never auto-disable HVCI
on a FACEIT machine: if a future enforcement wave adds an HVCI check, an
assumption baked into a script becomes a silent lockout.

If you want to test it: turn Memory Integrity off in Windows Security > Device
security > Core isolation, reboot, then LAUNCH THE FACEIT AC CLIENT AND CONFIRM
IT PASSES before queueing a match. Registry equivalent, for reference only:
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 0
'@)
    }

    # --- 10.5: reframe the performance target honestly ---
    [void](Add-OptDecision -State $State -Id 'S-10.5' -Section '10' -Decision 'NoOp' `
        -Title 'Realistic performance ceiling' `
        -Reason 'With VBS mandatory, the levers that actually matter on this machine are section 3.8 (refresh rate), 4.1 (MMCSS), 6 (input), 9 (Defender exclusions) and firmware-level memory tuning - not kernel security teardown. Nothing in this script can recover what VBS costs, and it will not pretend otherwise.')
}
#endregion src\50-Sections\Section-10-Vbs.ps1

#region src\50-Sections\Section-13-BadTweaks.ps1
<#
    Section 13 - detect and offer to revert known-harmful "optimizations".

    These appear constantly in CS2 optimization videos and are either useless,
    harmful, or anti-cheat risks. The starred ones in the spec are detected here
    and reverted, because leaving them in place actively costs the user
    performance or FACEIT access.
#>

function Invoke-OptSection13 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SECTION 13 - Detect and revert known-harmful tweaks'

    if (-not (Test-OptSectionEnabled -State $State -Section '13')) { return }

    $p = $State.Profile
    $found = 0

    # --- hypervisorlaunchtype off ---------------------------------------------
    # The most damaging one: it silently prevents VBS from running, so the
    # machine fails the FACEIT check with no obvious cause.
    if ([string]$p.Security.HypervisorLaunchType -match '^Off') {
        $found++
        if ($State.Capabilities.BcdEdit -and $State.Capabilities.HypervisorOff -ne $true) {
            $r = Invoke-OptNativeCommand -State $State -FilePath 'bcdedit.exe' `
                 -ArgumentList @('/set', 'hypervisorlaunchtype', 'Auto') -Purpose 'restore hypervisorlaunchtype'

            if ($State.DryRun) {
                [void](Add-OptDecision -State $State -Id 'S-13-HVLAUNCH' -Section '13' -Decision 'Applied' `
                    -Title 'Revert hypervisorlaunchtype off' -Reason 'would set hypervisorlaunchtype back to Auto')
            }
            elseif ($r.Success) {
                $change = New-OptChangeRecord -State $State -Type 'BcdEditValue' -Section '13' -Tier 'Safe' `
                    -Path 'bcdedit {current}' -Name 'hypervisorlaunchtype' `
                    -Target @{ Element = 'hypervisorlaunchtype' } `
                    -OldValue 'Off' -NewValue 'Auto' -ExistedBefore $true -RequiresReboot -VerifyMode 'PostReboot'
                [void](Add-OptChange -State $State -Change $change)
                [void](Add-OptDecision -State $State -Id 'S-13-HVLAUNCH' -Section '13' -Decision 'Applied' `
                    -Title 'Revert hypervisorlaunchtype off' -Severity 'Warning' `
                    -Reason 'was Off, which silently prevents VBS from running and fails the FACEIT check - restored to Auto. Reboot required.')
            }
        }
        else {
            [void](Add-OptFinding -State $State -Id 'S-13-HVLAUNCH' -Section '13' `
                -Title 'hypervisorlaunchtype is Off' -Severity 'Critical' `
                -Reason 'could not revert automatically (bcdedit is blocked). Run: bcdedit /set hypervisorlaunchtype Auto')
        }
    }

    # --- TCP autotuning disabled ----------------------------------------------
    # A genuine throughput regression that many scripts introduce. Section 7.2
    # already fixes it; this reports it as damage found rather than a tweak.
    $show = Invoke-OptNativeCommand -State $State -FilePath 'netsh.exe' -ArgumentList @('int', 'tcp', 'show', 'global') -ReadOnly
    foreach ($line in (Get-OptCommandLines -Text $show.StdOut)) {
        if ($line -match 'Receive Window Auto-Tuning Level\s*:\s*disabled') {
            $found++
            [void](Add-OptDecision -State $State -Id 'S-13-AUTOTUNE' -Section '13' -Decision 'Finding' `
                -Title 'TCP auto-tuning was disabled' -Severity 'Warning' `
                -Reason 'this is a real throughput regression introduced by many optimization scripts - section 7.2 restores it to normal')
        }
    }

    # --- pagefile disabled ----------------------------------------------------
    $paging = Get-OptRegValueSafe -Hive HKLM -SubKey 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles'
    if ($null -ne $paging -and @($paging).Count -eq 0) {
        $found++
        [void](Add-OptFinding -State $State -Id 'S-13-PAGEFILE' -Section '13' `
            -Title 'Pagefile is disabled' -Severity 'Error' `
            -Reason 'causes hard crashes under memory pressure and kills crash dumps. Section 5.1 restores a fixed-size pagefile.')
    }

    # --- ScheduledDefrag disabled ---------------------------------------------
    $defrag = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction SilentlyContinue
    if ($defrag -and [string]$defrag.State -eq 'Disabled') {
        $found++
        $r = Invoke-OptCmdletChange -State $State -Description 're-enable ScheduledDefrag' -Action {
            Enable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop | Out-Null
        }
        [void](Add-OptDecision -State $State -Id 'S-13-DEFRAG' -Section '13' `
            -Decision $(if ($r.Success) { 'Applied' } else { 'Failed' }) `
            -Title 'Re-enable ScheduledDefrag' -Severity 'Warning' `
            -Reason 'was disabled - that stops TRIM on SSDs and stops real defragmentation on HDDs. Harmful on every storage type.')
    }

    # --- VBS / Memory Integrity disabled by a prior "optimization" ------------
    if ($p.Security.HasKernelAntiCheat -and $p.Security.VbsRunning -eq $false) {
        $found++
        # Already raised as a section 10 finding; noted here as the known-bad
        # tweak it almost always is.
        [void](Add-OptDecision -State $State -Id 'S-13-VBS' -Section '13' -Decision 'Finding' `
            -Title 'VBS disabled on an anti-cheat machine' -Severity 'Critical' `
            -Reason 'the single most common piece of bad CS2 advice as of 2026 - see the section 10 remediation steps')
    }

    # --- resident timer-resolution utilities ----------------------------------
    $timerTools = @(Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^(ISLC|TimerTool|TimerResolution|SetTimerResolution)' })
    if ($timerTools.Count -gt 0) {
        $found++
        [void](Add-OptFinding -State $State -Id 'S-13-TIMERTOOL' -Section '13' `
            -Title 'Resident timer-resolution utility running' -Severity 'Error' `
            -Reason "found: $((@($timerTools | ForEach-Object { $_.Name }) | Sort-Object -Unique) -join ', '). A resident process plus potential injection is an anti-cheat risk, and it contradicts the run-once design. Close and uninstall it.")
    }

    if ($found -eq 0) {
        Write-OptLog -Level Good 'No known-harmful tweaks detected'
        [void](Add-OptDecision -State $State -Id 'S-13-CLEAN' -Section '13' -Decision 'NoOp' `
            -Title 'Known-harmful tweak scan' -Reason 'none of the starred bad tweaks from the spec are present on this machine')
    }
}
#endregion src\50-Sections\Section-13-BadTweaks.ps1

#region src\50-Sections\Section-Manual.ps1
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
  Radeon Anti-Lag ................ On  (STANDARD ONLY - never Anti-Lag+)
  Radeon Chill ................... Off
  Radeon Boost ................... Off
  Enhanced Sync .................. Off
  Wait for Vertical Refresh ...... Always Off
  Radeon Image Sharpening ........ Off (or low, to taste)
  Texture Filtering Quality ...... Performance
  Surface Format Optimization .... On
  Tessellation Mode .............. Override, 8x or Off
  FreeSync ....................... On at the display (inert when fps > refresh, harmless)
  AMD Software ................... disable auto-start with Windows,
                                   disable "AMD User Experience Program" telemetry,
                                   disable the in-game overlay AND its hotkeys entirely

  WARNING: never enable Anti-Lag+. It triggered VAC bans in CS2 in October 2023.
  Standard Anti-Lag is fine, and game-integrated Anti-Lag 2 is fine.
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
        'AMD'    { 'Latency reduction: use Adrenalin Anti-Lag (standard - NEVER Anti-Lag+)' }
        'NVIDIA' { 'Latency reduction: enable in-game NVIDIA Reflex' }
        'Intel'  { 'Latency reduction: use Arc Low Latency Mode' }
        default  { 'Latency reduction: GPU vendor unknown - no recommendation' }
    }

    [void](Add-OptManual -State $State -Id 'M-11' -Section '11' -Title 'Steam and CS2 settings' -Detail @"
  LAUNCH OPTIONS (Steam > CS2 > Properties):
      -novid -nojoy -console

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
#endregion src\50-Sections\Section-Manual.ps1

#region src\60-Report\Report-Detection.ps1
<#
    The spec 1.5.5 detection report.

    Printed before anything is applied. Both this table and the section 14
    markdown report are projections of the SAME decision list produced by
    Resolve-OptGates - there is no second source of truth about why something
    was or was not done.
#>

function Write-OptDetectionReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $p = $State.Profile

    Write-OptLog -Level Header 'DETECTED'

    # --- CPU ---
    $cpuBits = @()
    if ($p.CPU.Microarch -ne 'Unknown') { $cpuBits += $p.CPU.Microarch }
    if ($null -ne $p.CPU.PhysicalCores) { $cpuBits += "$($p.CPU.PhysicalCores)C/$($p.CPU.LogicalCores)T" }
    if ($null -ne $p.CPU.CcdCount)      { $cpuBits += "$($p.CPU.CcdCount) CCD" }
    if ($p.CPU.HasVCache -eq $true)     { $cpuBits += "V-Cache $($p.CPU.L3TotalMB)MB" }
    if ($p.CPU.SmtEnabled -eq $false)   { $cpuBits += 'SMT off' }
    if ($p.CPU.HasHybridTopology -eq $true) { $cpuBits += 'hybrid P/E' }
    Write-OptLog -Level Plain ("  CPU      : {0} ({1})" -f ([string]$p.CPU.Name).Trim(), ($cpuBits -join ', '))

    # --- GPU ---
    foreach ($g in $p.GPU.Adapters) {
        $tag = if ($g.IsPrimary) { 'primary' } else { 'secondary' }
        $vram = if ($g.VramMB) { ", $([math]::Round($g.VramMB/1024))GB" } else { '' }
        Write-OptLog -Level Plain ("  GPU      : {0} ({1}, driver {2}{3})" -f $g.Name, $tag, $g.DriverVersion, $vram)
    }

    # --- memory / storage ---
    $memBits = @("$([math]::Round(([int]$p.Memory.TotalMB)/1024)) GB")
    if ($p.Memory.DdrGeneration) { $memBits += $p.Memory.DdrGeneration }
    if ($p.Memory.SpeedMTs)      { $memBits += "$($p.Memory.SpeedMTs) MT/s" }
    if ($null -ne $p.Memory.CommitPercentOfRam) { $memBits += "commit $($p.Memory.CommitPercentOfRam)%" }
    Write-OptLog -Level Plain ("  MEMORY   : {0}" -f ($memBits -join ', '))
    Write-OptLog -Level Plain ("  STORAGE  : boot {0}/{1}, {2} GB free, TRIM {3}" -f `
        $p.Storage.BootBusType, $p.Storage.BootMediaType, $p.Storage.BootFreeGB,
        $(if ($p.Storage.TrimEnabled) { 'on' } else { 'off' }))

    # --- display ---
    foreach ($d in $p.Display.Displays) {
        $tag = if ($d.IsPrimary) { 'primary' } else { 'secondary' }
        $rate = if ($d.RefreshBelowMax) { "$($d.CurrentRefreshHz) Hz of $($d.MaxRefreshHz) Hz available" }
                else { "$($d.CurrentRefreshHz) Hz (max)" }
        Write-OptLog -Level Plain ("  DISPLAY  : {0} {1}x{2} @ {3} [{4}]" -f $d.MonitorName, $d.Width, $d.Height, $rate, $tag)
    }

    # --- network ---
    $active = $p.Network.Adapters | Where-Object { $_.Name -eq $p.Network.ActiveAdapterName } | Select-Object -First 1
    if ($active) {
        Write-OptLog -Level Plain ("  NETWORK  : {0} ({1}), {2}, driver by {3}, {4} tunable keywords" -f `
            $active.Description, $active.Name, $active.LinkSpeed, $active.DriverProvider, @($active.SupportedKeywords).Count)
    }

    # --- audio / input ---
    if ($p.Audio.DefaultName) {
        Write-OptLog -Level Plain ("  AUDIO    : {0}{1}" -f $p.Audio.DefaultName, $(if ($p.Audio.DefaultIsHdmi) { ' [HDMI/DP - check this is intended]' } else { '' }))
    }
    if (@($p.Input.VendorUtilities).Count -gt 0) {
        Write-OptLog -Level Plain ("  INPUT    : {0} installed" -f ((@($p.Input.VendorUtilities) | ForEach-Object { $_.Name }) -join ', '))
    }

    # --- power / os ---
    Write-OptLog -Level Plain ("  POWER    : {0}{1}" -f $p.Power.ActiveSchemeName,
        $(if ($p.Power.SupportsModernStandby) { ', Modern Standby' } else { '' }))
    Write-OptLog -Level Plain ("  OS       : Windows build {0} {1} {2}{3}" -f `
        $p.OS.BuildNumber, $p.OS.DisplayVersion, $p.OS.Edition,
        $(if ($p.OS.HasNpu) { ', NPU present' } else { '' }))

    # --- security ---
    $sec = @(
        "Secure Boot $(Format-OptTriState $p.Security.SecureBootEnabled)"
        "TPM $(Format-OptTriState $p.Security.TpmReady)"
        "VBS $(Format-OptTriState $p.Security.VbsRunning)"
        "HVCI $(Format-OptTriState $p.Security.HvciRunning)"
        "IOMMU $(Format-OptTriState $p.Security.IommuEnabled)"
    )
    Write-OptLog -Level Plain ("  SECURITY : {0}" -f ($sec -join ', '))
    if (@($p.Security.BitLockerProtected).Count -gt 0) {
        Write-OptLog -Level Plain ("  BITLOCKER: protected on {0}" -f ((@($p.Security.BitLockerProtected) | ForEach-Object { $_.MountPoint }) -join ', '))
    }
    foreach ($ac in $p.Security.AntiCheat) {
        Write-OptLog -Level Plain ("  ANTICHEAT: {0} - services [{1}] drivers [{2}]" -f `
            $ac.Name, (@($ac.ServiceStates) -join ' '), (@($ac.DriverStates) -join ' '))
    }

    # --- games / boot ---
    if ($p.Games.SteamPath) {
        Write-OptLog -Level Plain ("  STEAM    : {0} ({1} librar{2})" -f $p.Games.SteamPath, @($p.Games.LibraryPaths).Count, $(if (@($p.Games.LibraryPaths).Count -eq 1) { 'y' } else { 'ies' }))
    }
    Write-OptLog -Level Plain ("  CS2      : {0}" -f $(if ($p.Games.Cs2Installed) { $p.Games.Cs2ExePath } else { 'not installed' }))
    Write-OptLog -Level Plain ("  BOOT     : {0}{1}, Fast Startup {2}" -f `
        $p.Boot.FirmwareType,
        $(if ($p.Boot.IsDualBoot) { ', dual-boot' } else { '' }),
        $(if ($p.Boot.FastStartupEnabled) { 'ON' } else { 'off' }))

    if (@($p.DetectionErrors).Count -gt 0) {
        Write-OptLog -Level Warn "$(@($p.DetectionErrors).Count) detector(s) failed - affected tweaks will be skipped:"
        foreach ($e in $p.DetectionErrors) { Write-OptLog -Level Detail "$($e.Detector): $($e.Message)" }
    }

    Write-OptDecisionSummary -State $State
}

function Format-OptTriState {
    <#
        Renders the tri-state honestly. '?' is a distinct answer from 'off' and
        must look like one - reporting an unconfirmed IOMMU as "off" would send
        the user into their BIOS for nothing.
    #>
    [CmdletBinding()][OutputType([string])]
    param([AllowNull()]$Value)

    if ($null -eq $Value)  { return '?' }
    if ($Value -is [bool]) { return $(if ($Value) { 'ON' } else { 'off' }) }
    return [string]$Value
}

function Write-OptDecisionSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $gated = @($State.Decisions | Where-Object { $_.Decision -eq 'Off' })
    if ($gated.Count -gt 0) {
        Write-OptLog -Level Header 'GATED OFF'
        foreach ($d in $gated) {
            Write-OptLog -Level Plain ("  {0,-22} {1}" -f "$($d.Section) $($d.Title)", $d.Reason)
        }
    }

    $notes = @($State.Decisions | Where-Object { $_.Decision -eq 'NoOp' -and $_.Id -like 'G-*' })
    if ($notes.Count -gt 0) {
        Write-OptLog -Level Header 'NOTES'
        foreach ($d in $notes) {
            Write-OptLog -Level Plain ("  {0,-22} {1}" -f "$($d.Section) $($d.Title)", $d.Reason)
        }
    }

    $findings = @($State.Findings)
    if ($findings.Count -gt 0) {
        Write-OptLog -Level Header 'FINDINGS - these are problems to fix, not tweaks that succeeded'
        foreach ($f in $findings) {
            $level = switch ($f.Severity) { 'Critical' { 'Error' } 'Error' { 'Error' } default { 'Warn' } }
            Write-OptLog -Level $level ("[{0}] {1}" -f $f.Section, $f.Title)
            Write-OptLog -Level Detail $f.Reason
        }
    }
}
#endregion src\60-Report\Report-Detection.ps1

#region src\60-Report\Report-Console.ps1
function Write-OptRunSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Header 'SUMMARY'

    $applied = @($State.Decisions | Where-Object { $_.Decision -eq 'Applied' })
    $noop    = @($State.Decisions | Where-Object { $_.Decision -eq 'NoOp' })
    $off     = @($State.Decisions | Where-Object { $_.Decision -eq 'Off' })
    $failed  = @($State.Decisions | Where-Object { $_.Decision -eq 'Failed' })

    if ($State.DryRun) {
        Write-OptLog -Level Info "DRY RUN - $($applied.Count) change(s) would be made. Nothing was modified."
    }
    else {
        Write-OptLog -Level Good "$($State.Changes.Count) change(s) applied and recorded"
    }

    Write-OptLog -Level Plain ("  already correct : {0}" -f $noop.Count)
    Write-OptLog -Level Plain ("  gated off       : {0}" -f $off.Count)
    if ($failed.Count -gt 0) {
        Write-OptLog -Level Warn ("  failed          : {0}" -f $failed.Count)
        foreach ($f in $failed) { Write-OptLog -Level Detail "$($f.Section) $($f.Title): $($f.Reason)" }
    }

    $findings = @($State.Findings)
    if ($findings.Count -gt 0) {
        Write-OptLog -Level Header 'FINDINGS - fix these; they are not tweaks that succeeded'
        foreach ($f in $findings) {
            $lvl = switch ($f.Severity) { 'Critical' { 'Error' } 'Error' { 'Error' } default { 'Warn' } }
            Write-OptLog -Level $lvl "[$($f.Section)] $($f.Title)"
            Write-OptLog -Level Detail $f.Reason
        }
    }

    if (@($State.Manual).Count -gt 0) {
        Write-OptLog -Level Info "$(@($State.Manual).Count) manual checklist item(s) - see the report for the full text"
    }

    if ($State.RebootRequired) { Write-OptLog -Level Warn 'A REBOOT is required for some changes to take effect.' }
    if ($State.LogoffRequired) { Write-OptLog -Level Warn 'A SIGN-OUT is required for some shell/input changes to take effect.' }

    if (-not $State.DryRun -and $State.Paths) {
        Write-OptLog -Level Header 'ARTEFACTS'
        Write-OptLog -Level Plain "  report   : $($State.Paths.Report)"
        Write-OptLog -Level Plain "  manifest : $($State.Paths.Manifest)"
        Write-OptLog -Level Plain "  log      : $($State.Paths.Transcript)"
        Write-OptLog -Level Plain ''
        Write-OptLog -Level Plain '  To undo everything this run did:'
        Write-OptLog -Level Plain "      Optimize-CS2.ps1 -Rollback"
        Write-OptLog -Level Plain '  To re-verify after rebooting (reboot-deferred changes):'
        Write-OptLog -Level Plain "      Optimize-CS2.ps1 -VerifyOnly"
    }
}
#endregion src\60-Report\Report-Console.ps1

#region src\60-Report\Report-Markdown.ps1
<#
    Section 14 markdown report.

    Contains: applied changes by tier, skipped changes and why, the manual
    checklists, security tradeoffs accepted, the reboot flag, and the rollback
    command - all projected from the single decision list.
#>

function Write-OptMarkdownReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    if (-not $State.Paths) { return }

    $p  = $State.Profile
    $sb = New-Object System.Text.StringBuilder
    $add = { param($line) [void]$sb.AppendLine($line) }

    & $add "# CS2 / Windows 11 optimization report"
    & $add ''
    & $add "- **Run**: $($State.RunId)"
    & $add "- **When**: $($State.StartedUtc) (UTC)"
    & $add "- **Tier**: $($State.Tier)$(if ($State.DryRun) { '  **(DRY RUN - nothing was modified)**' })"
    & $add "- **Machine**: $env:COMPUTERNAME"
    & $add ''

    # --- detected profile ---
    & $add '## Detected system'
    & $add ''
    & $add '| | |'
    & $add '|---|---|'
    & $add "| CPU | $(([string]$p.CPU.Name).Trim()) - $($p.CPU.Microarch), $($p.CPU.PhysicalCores)C/$($p.CPU.LogicalCores)T, $($p.CPU.CcdCount) CCD, V-Cache $($p.CPU.HasVCache) |"
    & $add "| GPU | $((@($p.GPU.Adapters | ForEach-Object { $_.Name })) -join ', ') (driver $($p.GPU.Adapters[0].DriverVersion)) |"
    & $add "| Display | $((@($p.Display.Displays | ForEach-Object { "$($_.MonitorName) $($_.Width)x$($_.Height) @ $($_.CurrentRefreshHz)/$($_.MaxRefreshHz) Hz" })) -join '; ') |"
    & $add "| Memory | $([math]::Round(([int]$p.Memory.TotalMB)/1024)) GB $($p.Memory.DdrGeneration) @ $($p.Memory.SpeedMTs) MT/s, commit $($p.Memory.CommitPercentOfRam)% |"
    & $add "| Storage | boot $($p.Storage.BootBusType)/$($p.Storage.BootMediaType), $($p.Storage.BootFreeGB) GB free |"
    & $add "| Network | $($p.Network.ActiveAdapterName) - $($p.Network.ActiveLinkSpeed), driver by $($p.Network.ActiveDriverProvider) |"
    & $add "| Security | Secure Boot $(Format-OptTriState $p.Security.SecureBootEnabled), TPM $(Format-OptTriState $p.Security.TpmReady), VBS $(Format-OptTriState $p.Security.VbsRunning), HVCI $(Format-OptTriState $p.Security.HvciRunning), IOMMU $(Format-OptTriState $p.Security.IommuEnabled) |"
    & $add "| Anti-cheat | $((@($p.Security.AntiCheat | ForEach-Object { $_.Name })) -join ', ') |"
    & $add "| Boot | $($p.Boot.FirmwareType)$(if ($p.Boot.IsDualBoot) { ', dual-boot' }) |"
    & $add ''

    # --- findings first: they matter more than the changes ---
    $findings = @($State.Findings)
    if ($findings.Count -gt 0) {
        & $add '## Findings - fix these'
        & $add ''
        & $add 'These are problems to resolve, **not** optimizations that succeeded.'
        & $add ''
        foreach ($f in $findings) {
            & $add "### [$($f.Severity)] $($f.Title) (section $($f.Section))"
            & $add ''
            & $add $f.Reason
            & $add ''
        }
    }

    # --- applied changes by tier ---
    & $add '## Changes'
    & $add ''
    $applied = @($State.Decisions | Where-Object { $_.Decision -eq 'Applied' })
    if ($applied.Count -eq 0) {
        & $add '_No changes were applied._'
        & $add ''
    }
    else {
        & $add "$($applied.Count) change(s)$(if ($State.DryRun) { ' would be applied' } else { ' applied' }):"
        & $add ''
        & $add '| Section | Change | Detail |'
        & $add '|---|---|---|'
        foreach ($a in $applied) {
            & $add "| $($a.Section) | $($a.Title) | $($a.Reason -replace '\|', '\|') |"
        }
        & $add ''
    }

    # --- already correct ---
    $noop = @($State.Decisions | Where-Object { $_.Decision -eq 'NoOp' -and $_.Id -like 'S-*' })
    if ($noop.Count -gt 0) {
        & $add '## Already in the desired state'
        & $add ''
        & $add 'Nothing was written for these, and nothing was recorded for rollback.'
        & $add ''
        & $add '| Section | Item | Reason |'
        & $add '|---|---|---|'
        foreach ($n in $noop) { & $add "| $($n.Section) | $($n.Title) | $($n.Reason -replace '\|', '\|') |" }
        & $add ''
    }

    # --- skipped ---
    $off = @($State.Decisions | Where-Object { $_.Decision -eq 'Off' })
    if ($off.Count -gt 0) {
        & $add '## Skipped, and why'
        & $add ''
        & $add '| Section | Item | Reason |'
        & $add '|---|---|---|'
        foreach ($o in $off) { & $add "| $($o.Section) | $($o.Title) | $($o.Reason -replace '\|', '\|') |" }
        & $add ''
    }

    # --- verification ---
    $verification = @($State.Verification)
    if ($verification.Count -gt 0) {
        & $add '## Verification'
        & $add ''
        $pass = @($verification | Where-Object { $_.Result -eq 'PASS' }).Count
        $fail = @($verification | Where-Object { $_.Result -eq 'FAIL' })
        $defer = @($verification | Where-Object { $_.Result -eq 'DEFERRED' })
        & $add "- PASS: $pass"
        & $add "- FAIL: $($fail.Count)"
        & $add "- Deferred to reboot: $($defer.Count)"
        & $add ''
        if ($fail.Count -gt 0) {
            & $add '| Section | Item | Expected | Actual |'
            & $add '|---|---|---|---|'
            foreach ($f in $fail) { & $add "| $($f.Section) | $($f.Path)\$($f.Name) | $($f.Expected) | $($f.Actual) |" }
            & $add ''
        }
        if ($defer.Count -gt 0) {
            & $add 'Deferred items are **not** verified yet. Re-run with `-VerifyOnly` after rebooting.'
            & $add ''
        }
    }

    # --- manual checklists ---
    $manual = @($State.Manual)
    if ($manual.Count -gt 0) {
        & $add '## Manual checklists'
        & $add ''
        & $add 'These are not safely scriptable - see each note for why.'
        & $add ''
        foreach ($m in $manual) {
            & $add "### $($m.Title) (section $($m.Section))"
            & $add ''
            if ($m.Detail) { & $add '```'; & $add $m.Detail; & $add '```' }
            else { & $add $m.Reason }
            & $add ''
        }
    }

    # --- startup inventory ---
    if ($State['StartupInventory']) {
        & $add '## Startup inventory (report only)'
        & $add ''
        & $add 'Nothing here was disabled: the script cannot distinguish an anti-cheat component or peripheral driver from bloat.'
        & $add ''
        & $add '| Source | Name | Command |'
        & $add '|---|---|---|'
        foreach ($e in @($State['StartupInventory'])) {
            & $add "| $($e.Source) | $($e.Name) | $(([string]$e.Command) -replace '\|', '\|') |"
        }
        & $add ''
    }

    if ($State['AppxCandidates'] -and @($State['AppxCandidates']).Count -gt 0) {
        & $add '## Removable inbox apps (report only)'
        & $add ''
        & $add 'Not removed. Provisioned package removal is not reliably reversible, and this buys disk space and a few background tasks - **not frames**.'
        & $add ''
        foreach ($a in @($State['AppxCandidates'])) { & $add "- $a" }
        & $add ''
    }

    # --- honest measurement guidance ---
    & $add '## Did this actually help?'
    & $add ''
    & $add 'Be honest with the results. On this machine:'
    & $add ''
    & $add '**Genuinely measurable:**'
    & $add ''
    & $add '- NIC link speed (`Get-NetAdapter | Select Name,LinkSpeed`) - check before and after; if section 7.1 changed Green Ethernet / Gigabit Lite / EEE this is the single most verifiable win available.'
    & $add '- Boot time - `Get-WinEvent -LogName Microsoft-Windows-Diagnostics-Performance/Operational -FilterXPath "*[System[EventID=100]]"`. This is where sections 8.1, 8.5, 8.6 and 8.7 actually pay off.'
    & $add '- Idle committed bytes and process count.'
    & $add '- DPC latency (LatencyMon, 60 s idle + 60 s in a demo) around the section 7 and 2.4 changes.'
    & $add '- Frame-time 1% / 0.1% lows from a **fixed demo playback**, three runs, using PresentMon. Never a live match - it is not repeatable.'
    & $add ''
    & $add '**Not measurable - do not go looking:**'
    & $add ''
    & $add '- Section 4.2 priority separation (Windows already defaults to this behaviour).'
    & $add '- Section 6.3 device queue sizes (unmeasured).'
    & $add '- Section 7.3 Nagle (a TCP tweak; CS2 game traffic is UDP).'
    & $add '- Section 5.4 MMAgent - and if it was already in the target state on this machine, there is literally nothing to measure.'
    & $add '- Every telemetry, policy and app item: disk and RAM hygiene, not frame rate.'
    & $add ''
    & $add 'If a frame-time capture shows nothing outside run-to-run variance, **that is the expected result**, not a failed application.'
    & $add ''

    # --- anti-cheat verification ---
    if ($p.Security.HasKernelAntiCheat) {
        & $add '## Before you play'
        & $add ''
        & $add '1. **Reboot** - several changes only settle after one, and you want the anti-cheat evaluating the final state, not an intermediate one.'
        & $add '2. Re-run with `-VerifyOnly` to resolve the reboot-deferred checks.'
        & $add '3. **Launch the FACEIT AC client on its own, without queueing.** It runs its full system check at startup and shows pass/fail - zero ban surface, and it directly tests the thing you care about.'
        & $add '4. Only queue a match once that passes.'
        & $add ''
        & $add 'Keep measurement tooling (HWiNFO, LatencyMon, PresentMon, RTSS) and anti-cheat sessions strictly non-overlapping. Realistically that is the actual risk in this whole exercise - not the registry tweaks.'
        & $add ''
    }

    & $add '## Undo'
    & $add ''
    & $add '```'
    & $add 'Optimize-CS2.ps1 -Rollback'
    & $add '```'
    & $add ''
    # Built by concatenation rather than interpolation: a backtick is both the
    # markdown code fence and PowerShell's escape character, and mixing them in
    # one double-quoted string produces an unterminated string.
    & $add ('Manifest: `' + $State.Paths.Manifest + '`')
    & $add ''
    & $add 'Registry `.reg` exports under the backup folder are a **manual last resort only**. Rollback is value-level from the manifest: re-importing an exported key would restore values deleted elsewhere and would not delete values added since.'
    & $add ''

    try {
        Set-Content -LiteralPath $State.Paths.Report -Value $sb.ToString() -Encoding UTF8 -ErrorAction Stop
        Write-OptLog -Level Good "Report written to $($State.Paths.Report)"
    }
    catch {
        Write-OptLog -Level Warn "Could not write the report: $($_.Exception.Message)"
    }
}
#endregion src\60-Report\Report-Markdown.ps1

#region src\90-Main.ps1
<#
    Main entry point - phase ordering per spec 15, with two deliberate changes:

      - Section 3.8 (display refresh) runs EARLY rather than inside step 7's
        registry block. A display-mode change is the one thing here that can
        black-screen a machine, so it happens while there is minimal other state
        to unwind. CDS_TEST-first makes it near-riskless anyway.

      - Section 4.3 (bcdedit) still runs LAST, because it is boot-affecting.
#>

function Invoke-OptMain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $mutex = $null
    $restoreFrequencyChanged = $false

    try {
        # Two concurrent runs would corrupt the manifest.
        $mutex = New-Object System.Threading.Mutex($false, 'Global\Cs2Opt')
        if (-not $mutex.WaitOne(0)) {
            throw 'Another cs2-opt run is already in progress.'
        }

        Write-OptBanner -State $State
        [void](Start-OptTranscript -State $State)

        # --- phase 1: detection --------------------------------------------
        Write-OptLog -Level Info 'Detecting hardware and software profile...'
        [void](Initialize-OptInterop -State $State)

        if ($State.Parameters['ProfileFrom']) {
            $State.Profile = Import-OptProfile -Path $State.Parameters['ProfileFrom']
            Write-OptLog -Level Info "Profile loaded from $($State.Parameters['ProfileFrom']) (hardware not probed)"
        }
        else {
            $State.Profile = Get-OptProfile -State $State
        }

        if ($State.Parameters['CaptureProfile']) {
            Export-OptProfile -ProfileData $State.Profile -Path $State.Parameters['CaptureProfile']
            Write-OptLog -Level Good "Profile written to $($State.Parameters['CaptureProfile'])"
            return
        }

        # --- rollback / verify-only short circuits ---------------------------
        if ($State.Parameters['Rollback']) {
            $summary = Invoke-OptRollback -State $State -ManifestPath $State.Paths.Manifest -WhatIfOnly:$State.DryRun
            return $summary
        }

        if ($State.Parameters['VerifyOnly']) {
            $manifest = Read-OptManifest -Path $State.Paths.Manifest
            [void](Invoke-OptVerification -State $State -Changes @($manifest.Changes) -PostReboot)
            Write-OptVerificationReport -State $State
            return
        }

        # --- phase 2: gates -------------------------------------------------
        $gates = Resolve-OptGates -ProfileData $State.Profile -Tier $State.Tier -Options $State.Parameters
        Set-OptGateResults -State $State -GateResult $gates

        Write-OptDetectionReport -State $State

        if ($State.Aborted) {
            Write-OptLog -Level Error "ABORTED: $($State.AbortReason)"
            return
        }

        # --- fingerprint / re-run safety -------------------------------------
        if (Test-Path -LiteralPath $State.Paths.Manifest) {
            try {
                $prior = Read-OptManifest -Path $State.Paths.Manifest
                $fp = Test-OptFingerprintMatch -StoredFingerprint $prior.Fingerprint -CurrentFingerprint $State.Profile.Fingerprint
                if ($fp.Status -eq 'Mismatch') {
                    Write-OptLog -Level Warn "Hardware changed since the last run - $($fp.Detail)"
                    Write-OptLog -Level Detail 'Every gate is being re-evaluated from scratch. Previously-applied vendor-specific tweaks may now target absent hardware - consider -Rollback against the old manifest first.'
                }
            }
            catch { }
        }

        # --- phase 3: security preflight (FATAL) ------------------------------
        $pre = Invoke-OptSecurityPreflight -State $State
        if (-not $pre.Passed) {
            Write-OptLog -Level Error "ABORTED: $($State.AbortReason)"
            return
        }

        if ($State.DryRun) {
            Write-OptLog -Level Info 'Dry run: continuing through every section with mutations disabled, to produce the full planned manifest.'
        }

        # --- phase 4: restore point ------------------------------------------
        $skipRecovery = [bool]$State.Parameters['SkipRecovery']
        if ($skipRecovery) {
            Write-OptLog -Level Warn 'Recovery artifacts skipped (-SkipRecovery): no restore point, no .reg exports.'
            Write-OptLog -Level Detail 'The manifest and journal are still written, so -Rollback works exactly as normal.'
            [void](Add-OptDecision -State $State -Id 'S-RECOVERY' -Section '1' -Decision 'Off' `
                -Title 'Recovery artifacts' -Severity 'Warning' `
                -Reason 'skipped at the user request via -SkipRecovery. Value-level rollback from the manifest is unaffected; what is given up is recovery if the manifest itself is lost, and the coarse whole-system undo of a restore point.')
        }
        elseif (-not $State.DryRun -and -not $State.Parameters['SkipRestorePoint']) {
            $restoreFrequencyChanged = New-OptRestorePoint -State $State
        }

        # --- phase 5+: sections ----------------------------------------------
        # Each section echoes its own decisions; the summary line afterwards
        # accounts for the already-correct and gated-off outcomes that are
        # deliberately not printed one by one.
        $sectionRuns = @(
            @{ N = '2';  Run = { Invoke-OptSection02 -State $State } }   # power
            @{ N = '3';  Run = { Invoke-OptSection03 -State $State } }   # GPU, incl. 3.8 refresh early
            @{ N = '5';  Run = { Invoke-OptSection05 -State $State } }   # memory + storage
            @{ N = '4';  Run = { Invoke-OptSection04 -State $State } }   # scheduler (4.3 bcdedit gated inside)
            @{ N = '6';  Run = { Invoke-OptSection06 -State $State } }   # input
            @{ N = '8';  Run = { Invoke-OptSection08 -State $State } }   # background, telemetry, tasks
            @{ N = '7';  Run = { Invoke-OptSection07 -State $State } }   # network
            @{ N = '9';  Run = { Invoke-OptSection09 -State $State } }   # Defender exclusions
            @{ N = '10'; Run = { Invoke-OptSection10 -State $State } }   # VBS compliance - report only
            @{ N = '13'; Run = { Invoke-OptSection13 -State $State } }   # revert known-harmful tweaks
        )
        foreach ($sr in $sectionRuns) {
            & $sr.Run
            Write-OptSectionSummary -State $State -Section $sr.N
        }

        Invoke-OptManualChecklists -State $State

        # --- verification ------------------------------------------------------
        [void](Invoke-OptVerification -State $State)
        Write-OptVerificationReport -State $State

        # --- security postflight ----------------------------------------------
        if (-not $State.DryRun) {
            [void](Invoke-OptSecurityPostflight -State $State)
        }

        # --- reports -----------------------------------------------------------
        Write-OptManifest -State $State -Final
        Write-OptMarkdownReport -State $State
        Write-OptRunSummary -State $State
    }
    finally {
        # The restore-point frequency override MUST be undone, or the machine
        # keeps unlimited restore points forever.
        if ($restoreFrequencyChanged) { Restore-OptRestorePointFrequency -State $State }

        Stop-OptTranscript
        if ($mutex) {
            try { $mutex.ReleaseMutex() } catch { }
            $mutex.Dispose()
        }
    }
}

function New-OptRestorePoint {
    <#
        Returns $true when the frequency override was applied and must be undone.

        Windows rate-limits restore points to one per 24 h. On the reference
        machine a point already existed from earlier today, so Checkpoint-Computer
        SILENTLY NO-OPS without this override - and a safety net you believe in
        but do not have is worse than none.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    Write-OptLog -Level Info 'Creating a system restore point...'

    $srKey = 'SYSTEM\CurrentControlSet\Control\SystemRestore'
    $freqKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $changed = $false

    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
    }
    catch {
        Write-OptLog -Level Warn "Could not enable System Restore: $($_.Exception.Message)"
    }

    $original = Get-OptRegValueSafe -Hive HKLM -SubKey $freqKey -Name 'SystemRestorePointCreationFrequency'
    $State['RestoreFreqOriginal'] = $original

    try {
        $base = Get-OptRegistryHiveKey -Hive 'HKLM'
        $key = $base.CreateSubKey($freqKey)
        $key.SetValue('SystemRestorePointCreationFrequency', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.Dispose(); $base.Dispose()
        $changed = $true
    }
    catch {
        Write-OptLog -Level Warn "Could not set the restore-point frequency override: $($_.Exception.Message)"
    }

    $before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)

    try {
        Checkpoint-Computer -Description 'Pre-CS2-Opt' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
    }
    catch {
        Write-OptLog -Level Warn "Checkpoint-Computer failed: $($_.Exception.Message)"
    }

    # Assert the point actually landed rather than assuming it did.
    $after = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
    $newest = $after | Select-Object -Last 1

    if ($after.Count -gt $before.Count -and $newest -and [string]$newest.Description -eq 'Pre-CS2-Opt') {
        Write-OptLog -Level Good "Restore point created: $($newest.Description)"
    }
    else {
        Write-OptLog -Level Warn 'Restore point was NOT created. Note that System Restore does not cover HKCU, NIC properties, the pagefile, Defender exclusions, or app removals anyway - the manifest is the real undo mechanism.'
        [void](Add-OptDecision -State $State -Id 'S-RESTORE' -Section '1' -Decision 'Failed' `
            -Title 'System restore point' -Severity 'Warning' `
            -Reason 'could not be created - rely on -Rollback and the registry backups instead')
    }

    [void]$srKey  # referenced for clarity; frequency lives under $freqKey
    return $changed
}

function Restore-OptRestorePointFrequency {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $freqKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $original = $State['RestoreFreqOriginal']

    try {
        $base = Get-OptRegistryHiveKey -Hive 'HKLM'
        $key = $base.CreateSubKey($freqKey)
        if ($null -eq $original) {
            # It did not exist before - remove it so the 1440-minute default
            # applies again rather than leaving unlimited restore points on.
            $key.DeleteValue('SystemRestorePointCreationFrequency', $false)
        }
        else {
            $key.SetValue('SystemRestorePointCreationFrequency', [int]$original, [Microsoft.Win32.RegistryValueKind]::DWord)
        }
        $key.Dispose(); $base.Dispose()
    }
    catch {
        Write-OptLog -Level Warn "Could not restore the restore-point frequency setting: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

$OptParameters = @{
    Tier                  = $Tier
    DryRun                = [bool]$DryRun
    Rollback              = [bool]$Rollback
    ManifestPath          = $ManifestPath
    RemoveApps            = [bool]$RemoveApps
    RemoveOneDrive        = [bool]$RemoveOneDrive
    BitLockerAcknowledged = [bool]$BitLockerAcknowledged
    # -SkipRecovery subsumes -SkipRestorePoint, so passing it alone is enough.
    SkipRestorePoint      = ([bool]$SkipRestorePoint -or [bool]$SkipRecovery)
    SkipRecovery          = [bool]$SkipRecovery
    NoReboot              = [bool]$NoReboot
    VerifyOnly            = [bool]$VerifyOnly
    CaptureProfile        = $CaptureProfile
    ProfileFrom           = $ProfileFrom
    Sections              = $Sections
    ExcludeSections       = $ExcludeSections
    AllowNetworkRestart   = [bool]$AllowNetworkRestart
}

# -ProfileFrom means the hardware was not probed, so mutating would be reckless.
if ($ProfileFrom) { $OptParameters['DryRun'] = $true }

$script:Opt = New-OptState -Tier $Tier -Parameters $OptParameters
# Real runs echo decisions to the console; the test suite leaves this off.
$script:Opt['ConsoleDecisions'] = $true
[void](Initialize-OptPaths -State $script:Opt -ManifestPath $ManifestPath)

Invoke-OptMain -State $script:Opt
#endregion src\90-Main.ps1


