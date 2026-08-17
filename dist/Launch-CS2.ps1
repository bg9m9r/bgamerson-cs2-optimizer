#Requires -Version 5.1

<#
.SYNOPSIS
    Launches CS2 through Steam and removes physical core 0 from its CPU
    affinity - logical CPUs 0 and 1 when SMT/Hyper-Threading is on, logical
    CPU 0 when it is off.

.DESCRIPTION
    Windows concentrates work on the first core: kernel DPCs and ISRs default
    to CPU 0, and plenty of system processes end up scheduled there. Excluding
    it from the game's mask keeps CS2's threads off the core that is busiest
    with everything that is not the game.

    Deliberate boundaries:

      - This is a LAUNCHER, not part of the optimizer. The optimizer never
        touches affinity (spec 6.4/13): PINNING the game to chosen cores is
        counterproductive on single-CCD parts. EXCLUDING core 0 is the inverse
        operation - the game keeps every other core - and is applied here only
        because the user asked for it explicitly, per launch, reversibly.
      - The mechanism is SetProcessAffinityMask via .NET Process.ProcessorAffinity,
        the same documented API Task Manager's "Set affinity" uses. Nothing is
        injected into cs2.exe and nothing stays resident - this script sets the
        mask and exits. Restarting the game resets it.
      - On CPUs with fewer than 6 physical cores the exclusion is skipped and
        the game simply launches: giving up 1 of 4 cores costs more than core 0
        contention does.
      - Requires NO elevation. cs2.exe runs as you; adjusting your own
        process's affinity is a user-level operation.

.PARAMETER TimeoutSeconds
    How long to wait for cs2.exe to appear after asking Steam to launch it.
    Steam updates or first-run shader compilation can make this slow.

.PARAMETER NoLaunch
    Skip the Steam launch and only apply the mask to an already-running
    cs2.exe.

.EXAMPLE
    .\Launch-CS2.cmd
    .\Launch-CS2.ps1 -NoLaunch     # game already running, just fix affinity
#>
[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 180,
    [switch]$NoLaunch
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-Cs2AffinityPlan {
    <#
        Computes the affinity mask from the machine's topology.

        Returns @{ Apply; Reason; Mask; ExcludedCpus; LogicalCount }.
        Mask is $null when Apply is $false.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][int]$PhysicalCores,
        [Parameter(Mandatory)][int]$LogicalCores
    )

    if ($PhysicalCores -lt 6) {
        return @{
            Apply = $false; Mask = $null; ExcludedCpus = @(); LogicalCount = $LogicalCores
            Reason = "only $PhysicalCores physical cores - giving one up costs more than core 0 contention; launching without an affinity change"
        }
    }

    if ($LogicalCores -gt 62) {
        # A plain IntPtr mask covers one processor group (64 logical CPUs, and
        # PowerShell's signed IntPtr math gets awkward at the top bits).
        # Machines like that are Threadripper-class and out of scope here.
        return @{
            Apply = $false; Mask = $null; ExcludedCpus = @(); LogicalCount = $LogicalCores
            Reason = "$LogicalCores logical CPUs spans processor groups - affinity masks work per-group; launching without an affinity change"
        }
    }

    # SMT means each physical core owns a consecutive PAIR of logical CPUs, so
    # physical core 0 is logical 0+1 with SMT and logical 0 without.
    $smt = $LogicalCores -gt $PhysicalCores
    $excluded = if ($smt) { @(0, 1) } else { @(0) }

    $mask = [int64]0
    for ($cpu = 0; $cpu -lt $LogicalCores; $cpu++) {
        if ($excluded -notcontains $cpu) { $mask = $mask -bor ([int64]1 -shl $cpu) }
    }

    return @{
        Apply = $true; Mask = $mask; ExcludedCpus = $excluded; LogicalCount = $LogicalCores
        Reason = "excluding logical CPU $($excluded -join ' and ') (physical core 0$(if ($smt) { ', SMT pair' })) of $LogicalCores"
    }
}

function Set-Cs2Affinity {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [Parameter(Mandatory)][int64]$Mask
    )

    try {
        $Process.ProcessorAffinity = [IntPtr]$Mask
        # Read back rather than trusting the setter.
        $Process.Refresh()
        return ([int64]$Process.ProcessorAffinity -eq $Mask)
    }
    catch {
        Write-Host "  Could not set affinity on PID $($Process.Id): $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# Guard so tests can dot-source the functions above without launching a game.
if ($env:CS2OPT_LAUNCHER_TEST -eq '1') { return }

# --- topology ---------------------------------------------------------------
$procs = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
$physical = [int](($procs | Measure-Object -Property NumberOfCores -Sum).Sum)
$logical  = [int](($procs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum)

$plan = Get-Cs2AffinityPlan -PhysicalCores $physical -LogicalCores $logical

Write-Host ''
Write-Host "  CS2 launcher - core 0 exclusion" -ForegroundColor Cyan
Write-Host "  CPU: $physical cores / $logical threads -> $($plan.Reason)" -ForegroundColor Gray

# --- launch -----------------------------------------------------------------
$existing = @(Get-Process -Name 'cs2' -ErrorAction SilentlyContinue)

if (-not $NoLaunch -and $existing.Count -eq 0) {
    # Through Steam, not cs2.exe directly - launching the binary yourself just
    # bounces back through Steam anyway, and this path keeps overlays,
    # cloud sync and the anti-cheat handshake exactly as a normal launch.
    Write-Host '  Launching CS2 via Steam...' -ForegroundColor Gray
    Start-Process 'steam://rungameid/730'
}
elseif ($existing.Count -gt 0) {
    Write-Host "  cs2.exe already running (PID $(($existing | ForEach-Object { $_.Id }) -join ', '))" -ForegroundColor Gray
}
elseif ($NoLaunch) {
    Write-Host '  -NoLaunch: cs2.exe is not running, nothing to do.' -ForegroundColor Yellow
    exit 1
}

if (-not $plan.Apply) {
    Write-Host '  Done (no affinity change on this CPU).' -ForegroundColor Gray
    exit 0
}

# --- wait for the process ----------------------------------------------------
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$cs2 = $null
while ((Get-Date) -lt $deadline) {
    $cs2 = @(Get-Process -Name 'cs2' -ErrorAction SilentlyContinue)
    if ($cs2.Count -gt 0) { break }
    Start-Sleep -Milliseconds 500
}

if (-not $cs2 -or $cs2.Count -eq 0) {
    Write-Host "  cs2.exe did not appear within $TimeoutSeconds seconds - a Steam update or a" -ForegroundColor Yellow
    Write-Host '  slow first launch can cause this. Run again with -NoLaunch once the game is up.' -ForegroundColor Yellow
    exit 1
}

# Give the process a moment to finish early init before touching it.
Start-Sleep -Seconds 2

# --- apply -------------------------------------------------------------------
$ok = $true
foreach ($p in $cs2) {
    $before = [int64]$p.ProcessorAffinity
    if ($before -eq $plan.Mask) {
        Write-Host ("  PID {0}: affinity already 0x{1:X} - nothing to do" -f $p.Id, $before) -ForegroundColor Gray
        continue
    }
    if (Set-Cs2Affinity -Process $p -Mask $plan.Mask) {
        Write-Host ("  PID {0}: affinity 0x{1:X} -> 0x{2:X} (logical CPU {3} excluded)" -f `
            $p.Id, $before, $plan.Mask, ($plan.ExcludedCpus -join '+')) -ForegroundColor Green
    }
    else { $ok = $false }
}

if ($ok) {
    Write-Host '  Done. This lasts until the game exits; launching normally resets it.' -ForegroundColor Gray
    exit 0
}
exit 1
