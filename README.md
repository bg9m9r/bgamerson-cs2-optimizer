# bgamerson-cs2-optimizer

A one-shot, idempotent, **detection-driven** Windows 11 optimizer for competitive CS2 on FACEIT.

No background daemon. No scheduled task. No resident tweaker process. It runs once, records everything it did, and can undo all of it.

## Get it running

Open **PowerShell** (Start → type `powershell` → Enter; no need to run it as admin), paste this, press Enter:

```powershell
$d="$env:USERPROFILE\Downloads\bgamerson-cs2-optimizer"; md $d -Force >$null; foreach($f in 'Optimize-CS2.ps1','Run-Optimize-CS2.cmd','Launch-CS2.ps1','Launch-CS2.cmd'){ iwr "https://github.com/bg9m9r/bgamerson-cs2-optimizer/releases/latest/download/$f" -OutFile "$d\$f" }; gci $d | Unblock-File; & "$d\Run-Optimize-CS2.cmd" -DryRun
```

That downloads the latest release into `Downloads\bgamerson-cs2-optimizer`, unblocks the files, and starts a **dry run**: you get one UAC prompt, then a full report of what it *would* change on your machine. **Nothing is modified.**

Happy with the report? Apply the conservative tier, then reboot:

```powershell
& "$env:USERPROFILE\Downloads\bgamerson-cs2-optimizer\Run-Optimize-CS2.cmd" -Tier Safe
```

(Or double-click `Run-Optimize-CS2.cmd` in that folder — no arguments means the default `Aggressive` tier.) Undo everything a run did with `Run-Optimize-CS2.cmd -Rollback`. The rest of this page explains what it does and why; [Quick start](#quick-start) has the full apply → reboot → verify sequence.

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
- raise a **critical finding** on a dual-CCD X3D processor that is missing AMD's 3D V-Cache driver — the actual cause of the stutter people try to tweak away — instead of touching the scheduler
- detect and **revert** known-harmful tweaks other scripts leave behind — `hypervisorlaunchtype off`, disabled TCP auto-tuning, a disabled pagefile, a disabled `ScheduledDefrag` — and flag resident timer-resolution utilities, which are an anti-cheat risk

It is also honest about what it can't do. Sections that aren't safely scriptable — AMD Adrenalin, the NVIDIA profile store, Steam launch options, BIOS — are emitted as checklists **generated from your detected hardware**, with your actual resolution, refresh rate and audio device substituted in. The Steam checklist reads the launch options you *actually* have and flags the ones that contradict the advice (`-high`, `-threads`, a cap below your panel's refresh rate).

---

## Download

**You do not need to build anything.** It ships pre-built as a single file, and the one-liner at the top of this page is the recommended way to get it. Two alternatives:

**Releases page.** Open **[Releases](https://github.com/bg9m9r/bgamerson-cs2-optimizer/releases/latest)**, download `bgamerson-cs2-optimizer-<version>.zip`, extract it, then double-click `Run-Optimize-CS2.cmd` (it asks for admin rights itself).

> **If nothing seems to happen**, Windows has flagged the extracted files as internet-sourced. Unblock them once:
> ```powershell
> Get-ChildItem "C:\path\to\extracted\folder" | Unblock-File
> ```
> That is Mark of the Web, which blocks unsigned downloaded scripts under the default execution policy. The one-liner does this step for you.

**Bleeding edge.** The same four files are in [`dist/`](dist/) on `main`; releases are the tested builds, `main` may be ahead of them.

The one-liner downloads real files and then runs them — it is *deliberately not* an `irm … | iex` pipe. Piping a remote script straight into your shell is a bad habit in general, and it does not work here anyway: the script relies on a `param()` block, command-line switches and its own UAC self-elevation, none of which survive that pattern. The files stay in `Downloads\bgamerson-cs2-optimizer` where you can read them.

---

## Quick start

Requires **Windows PowerShell 5.1** (not PowerShell 7 — see [below](#why-windows-powershell-51)). Administrator rights are required; if you launch it unelevated it asks via a **UAC prompt** and continues in an elevated window. Pass `-NoElevate` to suppress the prompt and exit instead (for scripts and CI).

On start it makes **one** HTTPS request to GitHub's releases API (5-second timeout) and tells you if a newer release exists. That is the only network access in the script: it never downloads or installs anything, sends nothing about your machine, and simply notes it and continues when offline. `-NoUpdateCheck` turns it off; `-Rollback` and `-ProfileFrom` never check.

Always start here. It changes nothing and prints exactly what it would do:

```
Run-Optimize-CS2.cmd -DryRun
```

When a run finishes, the markdown report opens by itself in whatever handles `.md` files (Notepad if nothing does — Windows 11 Notepad renders Markdown). `-NoOpenReport` keeps it on disk only. Read the report, then apply the lowest tier:

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

## Launching CS2 with core 0 excluded

`dist\Launch-CS2.cmd` is a separate, optional game launcher: it starts CS2 through Steam, waits for `cs2.exe`, and removes **physical core 0** from its CPU affinity — logical CPUs 0 and 1 with SMT, logical CPU 0 without. Windows concentrates kernel DPCs/ISRs and system processes on the first core, so this keeps the game's threads off the core that is busiest with everything that isn't the game.

```
Launch-CS2.cmd
```

Why this lives outside the optimizer: the optimizer **never** sets affinity (pinning a game to chosen cores is counterproductive on single-CCD parts and rejected by the spec). Excluding core 0 is the inverse — the game keeps every other core — and even that is per-launch and opt-in, not a persistent system change.

Honest details:

- Mechanism is `SetProcessAffinityMask` — the same documented API Task Manager's *Set affinity* uses. Nothing is injected, nothing stays resident; the script sets the mask and exits. No admin rights needed.
- The exclusion lasts until the game exits. Launching normally resets it.
- On CPUs with fewer than 6 physical cores it launches without changing affinity — losing 1 of 4 cores costs more than core 0 contention.
- If the game is already running: `Launch-CS2.cmd -NoLaunch` just applies the mask.
- Right after launch, `cs2.exe` can refuse the change with *Access is denied* and then accept it a few seconds later. The launcher treats that as transient: it re-finds the process and retries every 2 s for up to 2 minutes (`-ApplyTimeoutSeconds`), and only declares success after two consecutive clean checks. The console only pauses if the retries run out.
- Whether this helps is measurable but small — treat it as an A/B experiment (fixed demo playback, 1%/0.1% lows), not a guaranteed win.

---

## Tiers

Cumulative — `Aggressive` includes `Safe`, `Experimental` includes both.

| Tier | Contains |
|---|---|
| `Safe` | power plan and power-scheme values, device power management (NIC, USB), Fast Startup, `bcdedit` timer cleanup (removal only), filesystem, pagefile, refresh-rate enforcement, GameDVR/Game Mode, CS2 per-app flags, mouse acceleration, accessibility hotkeys, TCP stack |
| `Aggressive` *(default)* | + MMCSS, priority separation, IFEO process priority, NIC advanced properties, UDP receive offload (URO) off, NVIDIA telemetry, scheduled tasks, background apps, telemetry and ETW loggers, AI/Copilot surfaces, shell surfaces, visual effects, Defender exclusions |
| `Experimental` | + MMAgent, SysMain, device queue sizes, Nagle, NIC interrupt affinity to core 0, `GlobalTimerResolutionRequests`, DiagTrack, MPO disable (see below) |

`Experimental` items are the ones with a plausible "the machine feels worse" outcome. Apply them **one per reboot** — bundling them makes attribution impossible. `-Rollback` undoes a whole run, not one item, so a bundled run can only be undone as a bundle.

MPO disable (3.2) goes one step further: it never applies from `-Tier Experimental` alone, because flicker can't be detected in software. It needs an explicit `-Tier Experimental -Sections 3.2`.

Inbox-app removal (8.8) and OneDrive removal (8.9) are **report-only** in every tier: the report lists the candidates, nothing is removed.

---

## Options

| Switch | Effect |
|---|---|
| `-DryRun` | Runs the full pipeline with mutation disabled and emits the complete manifest of what *would* change. Deliberately goes further than a detection-only preview: detection is the part that's already safe. |
| `-Tier <t>` | `Safe` / `Aggressive` / `Experimental`. Default `Aggressive`. |
| `-Sections 7` | Run only these sections. Prefix matching, so `8` covers `8.1`–`8.9`; a comma list works too (`-Sections 7.4,7.5`). Built for staged validation. |
| `-ExcludeSections 5.4` | Skip these. Same matching rules. |
| `-Rollback` | Replay the last manifest in reverse. |
| `-VerifyOnly` | Re-verify the last manifest without applying anything — how reboot-deferred changes get a real result. |
| `-SkipRecovery` | Skip the restore point and `.reg` exports. **The manifest and journal are still written, so `-Rollback` still works.** |
| `-SkipRestorePoint` | Skip only the restore point (`-SkipRecovery` implies it). |
| `-ManifestPath <path>` | Where the "latest run" manifest pointer lives. Default `%ProgramData%\cs2-opt\manifest.json`. |
| `-CaptureProfile <path>` | Dump the detected profile to JSON and exit. Attach it to bug reports; it doubles as a test fixture. |
| `-ProfileFrom <path>` | Load a captured profile instead of probing hardware. Implies `-DryRun`. |
| `-AllowNetworkRestart` | Permit the single adapter restart that section 7.1 needs to take effect. Expect a brief link bounce. Refused inside a remote-desktop session. |
| `-BitLockerAcknowledged` | Permit `bcdedit` changes while BitLocker is on — and only if a recovery-password protector is confirmed. Read the warning first. |
| `-NoElevate` | When unelevated, print a message and exit 2 instead of showing a UAC prompt. |
| `-NoUpdateCheck` | Skip the start-up release check (see [Quick start](#quick-start)). |
| `-NoOpenReport` | Don't open the markdown report when the run finishes. |
| `-RemoveApps`, `-RemoveOneDrive`, `-NoReboot` | Accepted for compatibility with the original spec; **no effect in this build.** Sections 8.8 and 8.9 are report-only, and the script never reboots on its own. |

Exit codes: `0` the run completed (individual tweaks that failed are reported as findings, not as a non-zero exit), `1` the run stopped on an unexpected error or was launched under PowerShell 7 (the manifest is still salvaged so `-Rollback` works), `2` refused by a safety gate — a virtual machine, or unelevated with `-NoElevate`.

Everything lands in `%ProgramData%\cs2-opt\` (falling back to `%TEMP%\cs2-opt\` if that isn't writable): `logs\`, `backup\<timestamp>\` (`.reg` exports, unless skipped), `runs\<timestamp>\` (`manifest.json`, `changes.jsonl` journal, `report.md`), and `manifest.json` pointing at the latest run.

---

## Safety design

**Rollback is value-level, from the manifest.** Every change records its old value, its old value *kind*, whether the value existed beforehand, and whether the *key* existed beforehand — so rollback deletes what it created and restores what it replaced, with the original type.

**A change that was already correct is never recorded.** This matters more than it sounds. If a no-op were recorded as a change, `-Rollback` would "restore" a value to a state the machine was never in — for example re-enabling memory compression you had already disabled yourself.

**The manifest is written incrementally.** Every change is appended to a JSONL journal and flushed immediately, because this script restarts network adapters and changes display modes; a manifest written only at the end would leave changes applied and unrollbackable after a hang.

**Nothing outside three chokepoints can mutate the OS.** A build-time AST gate fails the build if any file calls a native tool directly, and `-DryRun` is enforced at those chokepoints rather than at hundreds of call sites, where it would eventually leak.

**Anti-cheat pre- and post-flight.** Secure Boot, TPM, VBS, IOMMU and every detected anti-cheat driver are captured before the run and re-checked after. If VBS drops, the script doesn't merely report it — it auto-rolls-back the security-adjacent changes and tells you not to reboot.

---

## Why VBS stays on

FACEIT requires VBS in order to support IOMMU, which is the mechanism that neutralizes DMA-card cheats. TPM 2.0 and Secure Boot became mandatory for all players on 25 November 2025; IOMMU and VBS have been enforced in expanding waves since April 2025; and Windows 11 itself is required from **14 October 2026** — a Windows 10 machine with FACEIT AC installed gets a critical finding saying exactly that.

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

Four suites: the gating matrix against synthetic hardware profiles (Intel hybrid, NVIDIA, laptop, HDD, wireless, BitLocker, domain-joined, VM, 8 GB, dual-CCD X3D) with no real hardware; the engine (registry chokepoint, rollback, `netsh` and VDF parsers against captured fixtures, the network sections in a sandbox); `dist/` freshness; and the launcher's affinity math and retry loop (driven against the test host and the Idle process, never a game). Two tests matter most:

- **No unrecorded mutations** — diffs a sandbox registry subtree before and after, and asserts the change set equals the manifest *in both directions*. A round-trip test can never catch "applied but not recorded", because it only replays what was recorded.
- **Rollback round-trip from a re-read file** — never the in-memory object, because most bugs in this class are serialization bugs (`byte[]` → int array, DWORD sign, absent vs empty string).

Registry tests run against a real sandbox key with a fail-closed interlock: a test that forgets to configure redirection *throws* rather than writing to the real hive.

### Refreshing the profile fixture

```powershell
.\tests\Update-Fixture.ps1
```

Run it from an **elevated** shell (the capture needs admin rights). If a capture already exists, `-RawPath <file>` scrubs it without capturing again. Always use this rather than `-CaptureProfile` directly. A raw capture contains device identifiers — NIC MAC addresses, disk serial numbers, audio endpoint GUIDs — and this script scrubs them before the fixture lands in the repo, then **fails loudly if anything survived**. No test asserts on a serial, a MAC, or the fingerprint hash, so scrubbing costs nothing.

---

## Layout

```
build/     Build-Script.ps1, build.psd1 (ordered file list), analyzer settings
src/       00-Header, 10-Core, 20-Interop, 30-Detect, 40-Gates, 50-Sections, 60-Report, 90-Main
launcher/  Launch-CS2.ps1 (standalone; copied to dist by the build)
tests/     Pester suites + captured profile and command-output fixtures, Update-Fixture.ps1
tools/     repo-local Pester (not committed; see Tests)
dist/      Optimize-CS2.ps1 + Run-Optimize-CS2.cmd, Launch-CS2.ps1 + Launch-CS2.cmd
.github/   CI (build + test on every push) and the tag-triggered release workflow
```

Releases are cut by pushing a `v*` tag: CI rebuilds from source, runs the full suite, and only then publishes the zip and the four loose files.

---

## Honest expectations

Read the report's "Did this actually help?" section before measuring anything.

**Genuinely measurable:** NIC link speed, boot time, idle committed bytes, DPC latency, and 1%/0.1% frame-time lows from a *fixed demo playback* (never a live match — it isn't repeatable).

**Not measurable, and labelled as such in the report:** priority separation, device queue sizes, Nagle (a TCP tweak; CS2 traffic is UDP), UDP receive offload (it only merges equal-length datagrams, which CS2 rarely sends), and MMAgent. Every telemetry, policy and inbox-app item is disk and RAM hygiene — not frame rate.

**NIC interrupt affinity (Experimental, 7.5)** is designed as the pair to the launcher: the game leaves physical core 0, the NIC's interrupts and DPCs move onto it. It is community-measured, not lab-measured — A/B it the same way the launcher was.

**Researched and rejected (2026):** the Windows "Low Latency Profile" CPU boost (only fires for Start-menu and flyout launches), TCP receive segment coalescing (TCP only), UDP send offload (only sockets that opt in), `PowerThrottlingOff` (inert under the performance power plan), kernel-mode stack protection changes (security teardown), `DisablePagingExecutive`/`LargeSystemCache` (server-era), and the `cl_interp 0.015625` / `cl_interp_ratio 1` bundle (CS:GO-era; the in-game *Buffering* setting is the supported control now).

If a frame-time capture shows nothing outside run-to-run variance, that's the expected result, not a failed application.

Verify anti-cheat by launching the FACEIT AC client **on its own, without queueing** — it runs its full system check at startup, which is zero ban surface and directly tests the thing you care about. Keep measurement tooling and anti-cheat sessions strictly non-overlapping.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 BGamerson.

Use it, fork it, ship it, sell it. Just keep the copyright notice.

**No warranty.** This script modifies system configuration. It's built defensively — everything is gated on detected hardware, recorded to a manifest, and reversible with `-Rollback` — but you are running it on your own machine at your own risk. Read the `-DryRun` output before applying anything.

Nothing here is affiliated with or endorsed by Valve, FACEIT, AMD, NVIDIA, Intel or Microsoft.
