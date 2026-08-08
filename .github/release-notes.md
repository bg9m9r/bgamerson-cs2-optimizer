## Download

Grab **`{{ZIP}}`** below, extract it, then **right-click `Run-Optimize-CS2.cmd` and choose *Run as administrator***.

If nothing seems to happen, Windows flagged the extracted files as internet-sourced. Unblock them once:

```powershell
Get-ChildItem "C:\path\to\extracted\folder" | Unblock-File
```

## First run

Always start with a dry run. It changes nothing and prints exactly what it would do:

```
Run-Optimize-CS2.cmd -DryRun
```

Then apply the lowest tier:

```
Run-Optimize-CS2.cmd -Tier Safe
```

Reboot, then `Run-Optimize-CS2.cmd -VerifyOnly` to resolve the checks that only settle after a restart. `-Rollback` undoes everything a run did.

## Notes

- Requires **Windows PowerShell 5.1** and an elevated prompt. The script refuses to run under PowerShell 7 — see the README for why.
- It will **not** disable Secure Boot, TPM, VBS, IOMMU or Memory Integrity. On a machine with FACEIT Anti-Cheat those are dependencies, not optimization targets.
- Every tweak is gated on detected hardware. Anything whose preconditions are not met is skipped and logged with the reason, never applied blindly.
- Every change is recorded to a manifest and is reversible with `-Rollback`.

### Verify your download

`SHA256` of `Optimize-CS2.ps1`:

```
{{SHA}}
```
