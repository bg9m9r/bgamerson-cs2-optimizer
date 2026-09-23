# Security

This script runs elevated and modifies system configuration. That is exactly why it is built to be inspectable, and why reports are taken seriously.

## What it touches, and what it never touches

- **Network:** exactly one HTTPS `GET` to `https://api.github.com/repos/bg9m9r/bgamerson-cs2-optimizer/releases/latest` at start-up, to compare its version with the latest release. It sends a User-Agent and nothing else, downloads nothing, and `-NoUpdateCheck` turns it off. There is no other network access anywhere in the script.
- **Writes:** registry values, `powercfg` / `netsh` / `fsutil` / `bcdedit` settings, scheduled-task and service state, Defender path/process exclusions, and the display mode. Every write goes through one of three chokepoint files (`src/10-Core/Invoke.ps1`, `Registry.ps1`, `RegistryBackup.ps1`); the build fails if any other file invokes a native tool.
- **Never:** disabling Secure Boot, TPM, VBS, IOMMU or Memory Integrity; disabling Defender real-time protection; removing provisioned apps or OneDrive (report-only); setting game CPU affinity from the optimizer; installing anything; running anything it downloaded; persisting anything (no service, task, or startup entry of its own).

## How to check a release before running it

1. **Provenance.** Every release is built by the public workflow in `.github/workflows/release.yml` from the tagged commit, and each file carries a signed build attestation. With the [GitHub CLI](https://cli.github.com/):

   ```powershell
   gh attestation verify .\Optimize-CS2.ps1 --repo bg9m9r/bgamerson-cs2-optimizer
   ```

   A pass means the file you hold is byte-identical to what that workflow produced from that commit.
2. **Checksum.** The SHA256 of `Optimize-CS2.ps1` is in each release's notes; compare with `Get-FileHash .\Optimize-CS2.ps1`.
3. **Read it.** The built script is a single plain-text file with no obfuscation; `dist/Optimize-CS2.ps1` in the repo is the same file, and a test fails the build if it drifts from `src/`.
4. **Dry run.** `Run-Optimize-CS2.cmd -DryRun` runs the full pipeline with every mutation disabled and writes the complete manifest of what a real run would change.
5. **VirusTotal.** Each release's notes link to VirusTotal reports for the published files. Note that section 9 adds Defender *exclusions* (not a disable) via `Add-MpPreference`, which a few heuristic engines flag on any script; the README explains what is excluded and why real-time protection stays on.

## Reporting a problem

If the script does something the report did not say it would, changes something it did not record, or you believe a tweak is unsafe for a configuration it does not gate on:

- Open a [GitHub issue](https://github.com/bg9m9r/bgamerson-cs2-optimizer/issues) with the run's `report.md` and `manifest.json` from `%ProgramData%\cs2-opt\runs\<timestamp>\`, or a `-CaptureProfile` dump (run `tests\Update-Fixture.ps1 -RawPath <file>` first if you want MAC addresses and serials scrubbed).
- For anything you would rather not post publicly, email **bg9m9r@proton.me**.

`-Rollback` reverses every recorded change of the last run, in reverse order, restoring original values and types.
