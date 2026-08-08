# BGamerson's CS2 Optimizer Script

A one-shot, idempotent, **detection-driven** Windows 11 optimizer for competitive CS2 on FACEIT.

No background daemon. No scheduled task. No resident tweaker process. It runs once, records everything it did, and can undo all of it.

> **It will not disable Secure Boot, TPM, VBS, IOMMU or Memory Integrity.**
> On a machine with FACEIT Anti-Cheat installed those are *dependencies*, not optimization targets. Most CS2 optimization guides get this backwards. See [Why VBS stays on](#why-vbs-stays-on).

---

## What makes it different

Almost every "CS2 optimization script" is a flat list of `reg add` commands that runs the same way on every machine. This one is built around a detection layer: it probes the hardware first, then decides per-tweak whether the preconditions hold.

**A tweak whose preconditions aren't met is skipped and logged with the reason — never applied blindly.** Unknown hardware means *skip*, not *guess*.

Concretely, that means it will:

- refuse to set IFEO High priority on an Intel P/E hybrid part, where it fights Thread Director
- refuse to disable memory compression if your commit charge is already high — headroom matters, not capacity
- keep SysMain enabled if it finds a spinning disk, because prefetch genuinely helps there
- skip a NIC keyword the driver doesn't expose (and say so) rather than failing the whole block
- report "not present, nothing to disable" for Recall on a machine with no NPU, instead of writing a policy key and claiming a win
- detect and **revert** known-harmful tweaks other scripts leave behind — `hypervisorlaunchtype off`, disabled TCP auto-tuning, a disabled pagefile, a disabled `ScheduledDefrag`

It is also honest about what it can't do. Sections that aren't safely scriptable — AMD Adrenalin, the NVIDIA profile store, Steam launch options, BIOS — are emitted as checklists **generated from your detected hardware**, with your actual resolution, refresh rate and audio device substituted in.

---

## Download

**You do not need to build anything.** It ships pre-built as a single file.

### Option 1 — Releases page (easiest)

Open **[Releases](https://github.com/bg9m9r/bgamerson-cs2-optimizer/releases/latest)**, download `cs2-opt-<version>.zip`, extract it, then **right-click `Run-Optimize-CS2.cmd` → Run as administrator**.

> **If nothing seems to happen**, Windows has flagged the extracted files as internet-sourced. Unblock them once:
> ```powershell
> Get-ChildItem "C:\path\to\extracted\folder" | Unblock-File
> ```
> That is Mark of the Web, which blocks unsigned downloaded scripts under the default execution policy.

### Option 2 — one command

Paste into **PowerShell** to fetch it into `Downloads\cs2-opt`:

```powershell
$dir = "$env:USERPROFILE\Downloads\cs2-opt"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$base = 'https://raw.githubusercontent.com/bg9m9r/bgamerson-cs2-optimizer/main/dist'
Invoke-WebRequest "$base/Optimize-CS2.ps1"     -OutFile "$dir\Optimize-CS2.ps1"
Invoke-WebRequest "$base/Run-Optimize-CS2.cmd" -OutFile "$dir\Run-Optimize-CS2.cmd"
Get-ChildItem $dir | Unblock-File
explorer $dir
```

Then right-click `Run-Optimize-CS2.cmd` → **Run as administrator**.

*Deliberately not offered as an `irm … | iex` one-liner.* Piping a remote script straight into your shell is a bad habit in general, and it does not work here anyway — the script relies on `#Requires -RunAsAdministrator`, a `param()` block and command-line switches, none of which survive that pattern. Download it, read it, then run it.

---

## Quick start

Requires **Windows PowerShell 5.1** (not PowerShell 7 — see [below](#why-windows-powershell-51)) and an **elevated** prompt.

Always start here. It changes nothing and prints exactly what it would do:

```
Run-Optimize-CS2.cmd -DryRun
```

Read the report, then apply the lowest tier:

```
Run-Optimize-CS2.cmd -Tier Safe
```

Reboot, then resolve the checks that only settle after a restart:

```
Run-Optimize-CS2.cmd -VerifyOnly
```

To undo everything a run did:

```
Run-Optimize-CS2.cmd -Rollback
```

The `.cmd` launcher just invokes the script with `-NoProfile -ExecutionPolicy Bypass`, which also sidesteps the Mark-of-the-Web problem above. You can call `Optimize-CS2.ps1` directly if you prefer and your execution policy allows it.

---

## Tiers

Cumulative — `Aggressive` includes `Safe`, `Experimental` includes both.

| Tier | Contains |
|---|---|
| `Safe` | power plan, Fast Startup, filesystem, pagefile, refresh-rate enforcement, GameDVR/Game Mode, mouse acceleration, accessibility hotkeys, TCP stack |
| `Aggressive` *(default)* | + MMCSS, priority separation, IFEO process priority, NIC advanced properties, scheduled tasks, telemetry, shell surfaces, Defender exclusions |
| `Experimental` | + MPO disable, MMAgent, SysMain, device queue sizes, Nagle, DiagTrack |

`Experimental` items are the ones with a plausible "the machine feels worse" outcome. Apply them **one per reboot** — bundling them makes attribution impossible.

---

## Options

| Switch | Effect |
|---|---|
| `-DryRun` | Runs the full pipeline with mutation disabled and emits the complete manifest of what *would* change. Deliberately goes further than a detection-only preview: detection is the part that's already safe. |
| `-Tier <t>` | `Safe` / `Aggressive` / `Experimental`. Default `Aggressive`. |
| `-Sections 7` | Run only these sections. Prefix matching, so `8` covers `8.1`–`8.9`. Built for staged validation. |
| `-ExcludeSections 5.4` | Skip these. |
| `-Rollback` | Replay the last manifest in reverse. |
| `-VerifyOnly` | Re-verify the last manifest without applying anything — how reboot-deferred changes get a real result. |
| `-SkipRecovery` | Skip the restore point and `.reg` exports. **The manifest and journal are still written, so `-Rollback` still works.** |
| `-CaptureProfile <path>` | Dump the detected profile to JSON and exit. Attach it to bug reports; it doubles as a test fixture. |
| `-ProfileFrom <path>` | Load a captured profile instead of probing hardware. Implies `-DryRun`. |
| `-AllowNetworkRestart` | Permit the single adapter restart that section 7.1 needs to take effect. Expect a brief link bounce. |
| `-BitLockerAcknowledged` | Permit `bcdedit` changes while BitLocker is on. Read the warning first. |

Everything lands in `%ProgramData%\cs2-opt\`: `logs\`, `backup\`, `runs\<timestamp>\` (manifest, journal, markdown report), and `manifest.json` pointing at the latest run.

---

## Safety design

**Rollback is value-level, from the manifest.** Every change records its old value, its old value *kind*, whether the value existed beforehand, and whether the *key* existed beforehand — so rollback deletes what it created and restores what it replaced, with the original type.

**A change that was already correct is never recorded.** This matters more than it sounds. If a no-op were recorded as a change, `-Rollback` would "restore" a value to a state the machine was never in — for example re-enabling memory compression you had already disabled yourself.

**The manifest is written incrementally.** Every change is appended to a JSONL journal and flushed immediately, because this script restarts network adapters and changes display modes; a manifest written only at the end would leave changes applied and unrollbackable after a hang.

**Nothing outside three chokepoints can mutate the OS.** A build-time AST gate fails the build if any file calls a native tool directly, and `-DryRun` is enforced at those chokepoints rather than at hundreds of call sites, where it would eventually leak.

**Anti-cheat pre- and post-flight.** Secure Boot, TPM, VBS, IOMMU and every detected anti-cheat driver are captured before the run and re-checked after. If VBS drops, the script doesn't merely report it — it auto-rolls-back the security-adjacent changes and tells you not to reboot.

---

## Why VBS stays on

FACEIT requires VBS in order to support IOMMU, which is the mechanism that neutralizes DMA-card cheats. TPM 2.0 and Secure Boot became mandatory for all players on 25 November 2025; IOMMU and VBS have been enforced in expanding waves since April 2025.

So on a FACEIT machine, "VBS is not running" is a **blocking problem to fix**, not a tweak that succeeded. The script reports it as a critical finding with the remediation path, and will never write the DeviceGuard disable keys or emit `bcdedit /set hypervisorlaunchtype off`.

There is one place performance is still recoverable: VBS and HVCI are not the same thing, and FACEIT's published requirements name IOMMU and VBS but not HVCI. The script surfaces that as a **user-confirmed experiment with the reasoning spelled out** — and never auto-disables HVCI. If a future enforcement wave adds an HVCI check, an assumption baked into a script becomes a silent lockout.

---

## Why Windows PowerShell 5.1

`#Requires -Version 5.1` does *not* exclude PowerShell 7, so there's an explicit edition guard that refuses to run under Core.

Under PS7 the `Appx`, `DISM`, `MMAgent`, `NetAdapter`, `Defender`, `BitLocker`, `ScheduledTasks` and `Storage` modules all load through WindowsCompatibility implicit remoting. That returns deserialized objects with no methods, changes `-ErrorAction` semantics, and adds seconds per call. Chasing `-UseWindowsPowerShell` per module would be a permanent maintenance tax for zero user benefit.

PowerShell 7 is fine as a lint and test *host*; the script itself targets 5.1.

---

## Building from source

`dist/` is committed, so you can use the script without building. To rebuild after editing `src/`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build\Build-Script.ps1
```

The build enforces the invariants the tests rely on, and **fails** on any of:

1. a file that doesn't parse
2. top-level statements outside the header and main files (tests dot-source individual files, so they must be side-effect free)
3. assignment to a PowerShell automatic variable — notably `$Profile`, where the assignment *silently succeeds*
4. `ConvertTo-Json` without `-Depth` — the default of 2 would quietly truncate the profile and every rollback record
5. a native tool invoked outside the chokepoint
6. any non-ASCII character in source — 5.1 reads a BOM-less file as ANSI, so a stray literal becomes mojibake at runtime

It emits a per-file SHA256 banner into the built script, which `tests/Dist.Tests.ps1` uses to fail if `dist/` drifts out of sync with `src/`.

## Tests

```powershell
.\tests\Invoke-Tests.ps1
```

Re-launches itself under 5.1 (the runtime target — 7 hides real behavioural differences), loads Pester from `tools/Modules`, and runs PSScriptAnalyzer.

First-time bootstrap:

```powershell
Save-Module -Name Pester -MinimumVersion 5.0.0 -Path .\tools\Modules
```

Deliberately repo-local rather than `-Scope CurrentUser`, which lands in a OneDrive-redirected `Documents` tree on many machines.

The suite covers the gating matrix against synthetic hardware profiles (Intel hybrid, NVIDIA, laptop, HDD, wireless, BitLocker, domain-joined, VM, 8 GB) with no real hardware, plus the two tests that matter most:

- **No unrecorded mutations** — diffs a sandbox registry subtree before and after, and asserts the change set equals the manifest *in both directions*. A round-trip test can never catch "applied but not recorded", because it only replays what was recorded.
- **Rollback round-trip from a re-read file** — never the in-memory object, because most bugs in this class are serialization bugs (`byte[]` → int array, DWORD sign, absent vs empty string).

Registry tests run against a real sandbox key with a fail-closed interlock: a test that forgets to configure redirection *throws* rather than writing to the real hive.

### Refreshing the profile fixture

```powershell
.\tests\Update-Fixture.ps1
```

Always use this rather than `-CaptureProfile` directly. A raw capture contains device identifiers — NIC MAC addresses, disk serial numbers, audio endpoint GUIDs — and this script scrubs them before the fixture lands in the repo, then **fails loudly if anything survived**. No test asserts on a serial, a MAC, or the fingerprint hash, so scrubbing costs nothing.

---

## Layout

```
build/    Build-Script.ps1, build.psd1 (ordered file list), analyzer settings
src/      00-Header, 10-Core, 20-Interop, 30-Detect, 40-Gates, 50-Sections, 60-Report, 90-Main
tests/    Pester suites + captured profile and command-output fixtures
dist/     the built single-file script and its .cmd launcher
```

---

## Honest expectations

Read the report's "Did this actually help?" section before measuring anything.

**Genuinely measurable:** NIC link speed, boot time, idle committed bytes, DPC latency, and 1%/0.1% frame-time lows from a *fixed demo playback* (never a live match — it isn't repeatable).

**Not measurable, and labelled as such in the report:** priority separation, device queue sizes, Nagle (a TCP tweak; CS2 traffic is UDP), and MMAgent. Every telemetry, policy and inbox-app item is disk and RAM hygiene — not frame rate.

If a frame-time capture shows nothing outside run-to-run variance, that's the expected result, not a failed application.

Verify anti-cheat by launching the FACEIT AC client **on its own, without queueing** — it runs its full system check at startup, which is zero ban surface and directly tests the thing you care about. Keep measurement tooling and anti-cheat sessions strictly non-overlapping.
