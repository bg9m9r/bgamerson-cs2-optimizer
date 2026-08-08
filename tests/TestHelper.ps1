<#
    Shared test harness.

    Dot-sources the src tree into the caller's scope. This works only because
    every file except 00-Header.ps1 and 90-Main.ps1 contains function
    definitions and nothing else - a rule the build script enforces with an AST
    gate, precisely so that tests can load a single file without side effects.
#>

$script:Cs2OptRepoRoot = Split-Path -Parent $PSScriptRoot

function Get-Cs2OptSourceFiles {
    [CmdletBinding()]
    param([string[]]$Include)

    $manifest = Import-PowerShellDataFile (Join-Path $script:Cs2OptRepoRoot 'build\build.psd1')
    $files = @($manifest.Files | Where-Object { $_ -ne 'src\00-Header.ps1' -and $_ -ne 'src\90-Main.ps1' })

    if ($Include) {
        $files = @($files | Where-Object { $f = $_; @($Include | Where-Object { $f -like "*$_*" }).Count -gt 0 })
    }

    return @($files | ForEach-Object { Join-Path $script:Cs2OptRepoRoot $_ } | Where-Object { Test-Path -LiteralPath $_ })
}

# NOTE: there is deliberately no Import-Cs2OptSource helper.
#
# Dot-sourcing inside a function body defines the functions in THAT function's
# scope, which is torn down the moment it returns - so a wrapper would load the
# entire source tree into oblivion and every test would fail with
# "The term 'New-OptState' is not recognized".
#
# Callers must dot-source at their own scope:
#
#     BeforeAll {
#         . (Join-Path $PSScriptRoot 'TestHelper.ps1')
#         foreach ($f in (Get-Cs2OptSourceFiles)) { . $f }
#     }

function New-Cs2OptTestState {
    <#
        A run state wired to a disposable registry sandbox.

        The sandbox is enforced two ways:
          - RegistryRootMap rewrites HKLM: and HKCU: into the sandbox key
          - CS2OPT_TEST_ROOT arms the fail-closed interlock in
            Resolve-OptRegistryPath, so a test that forgets the map CANNOT
            write to the real hive - it throws instead.
    #>
    [CmdletBinding()]
    param(
        [string]$Tier = 'Experimental',
        [switch]$DryRun,
        [string]$SandboxRoot,
        [string]$PathsRoot,
        [System.Collections.IDictionary]$ProfileData
    )

    if (-not $SandboxRoot) { $SandboxRoot = "Software\Cs2OptTests\$([guid]::NewGuid())" }

    $state = New-OptState -Tier $Tier -Parameters @{ DryRun = [bool]$DryRun }
    $state.DryRun = [bool]$DryRun

    $state.RegistryRootMap = @{
        'HKLM:' = "HKCU\$SandboxRoot\HKLM"
        'HKCU:' = "HKCU\$SandboxRoot\HKCU"
    }
    $env:CS2OPT_TEST_ROOT = "HKCU\$SandboxRoot"

    if ($PathsRoot) { [void](Initialize-OptPaths -State $state -Root $PathsRoot) }
    if ($ProfileData) { $state.Profile = $ProfileData }

    $state['SandboxRoot'] = $SandboxRoot
    return $state
}

function Remove-Cs2OptTestState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)

    $env:CS2OPT_TEST_ROOT = $null
    if ($State['SandboxRoot']) {
        Remove-Item -LiteralPath "HKCU:\$($State['SandboxRoot'])" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function New-Cs2OptTestProfile {
    <#
        Builds a synthetic hardware profile by diffing from the captured
        reference profile.

        This is what makes ~46 gating-matrix rows testable against Intel hybrid
        parts, NVIDIA cards, laptops, HDD libraries, wireless-only machines,
        BitLocker, domain join, VMs and 8 GB systems - with zero real hardware.

        Overrides are dot-paths: @{ 'CPU.Vendor' = 'Intel' }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([System.Collections.IDictionary]$Override = @{})

    $path = Join-Path $script:Cs2OptRepoRoot 'tests\fixtures\profiles\reference-amd-x3d.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Reference profile fixture missing at $path. Regenerate with: Optimize-CS2.ps1 -CaptureProfile <path>"
    }

    $profileData = ConvertTo-OptHashtable -Object ((Get-Content -LiteralPath $path -Raw) | ConvertFrom-Json)

    foreach ($key in $Override.Keys) {
        $parts = $key -split '\.'
        $node = $profileData
        for ($i = 0; $i -lt $parts.Count - 1; $i++) {
            if (-not $node.Contains($parts[$i]) -or $null -eq $node[$parts[$i]]) {
                $node[$parts[$i]] = [ordered]@{}
            }
            $node = $node[$parts[$i]]
        }
        $node[$parts[-1]] = $Override[$key]
    }

    return $profileData
}

function Get-Cs2OptGateDecision {
    <#
        Convenience: resolve gates for a profile and return the decision for one
        gate id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ProfileData,
        [Parameter(Mandatory)][string]$GateId,
        [string]$Tier = 'Aggressive',
        [System.Collections.IDictionary]$Options = @{}
    )

    $result = Resolve-OptGates -ProfileData $ProfileData -Tier $Tier -Options $Options
    return @($result.Decisions | Where-Object { $_.Id -eq $GateId }) | Select-Object -First 1
}

function Get-Cs2OptSandboxSnapshot {
    <#
        Recursive snapshot of the sandbox subtree: every value's full path, its
        data, AND its kind. Kind is captured because a rollback that restores
        the right data with the wrong type is still a bug.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$SandboxRoot)

    $snapshot = @{}
    $rootPath = "HKCU:\$SandboxRoot"
    if (-not (Test-Path -LiteralPath $rootPath)) { return $snapshot }

    $stack = New-Object System.Collections.Stack
    $stack.Push($rootPath)

    while ($stack.Count -gt 0) {
        $path = $stack.Pop()
        $key = $null
        try {
            $sub = $path -replace '^HKCU:\\', ''
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::CurrentUser,
                        [Microsoft.Win32.RegistryView]::Registry64)
            $key = $base.OpenSubKey($sub)
            if (-not $key) { continue }

            foreach ($name in $key.GetValueNames()) {
                $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $kind  = $key.GetValueKind($name)
                $rendered = if ($value -is [byte[]]) { [System.Convert]::ToBase64String($value) }
                            elseif ($value -is [string[]]) { $value -join "`u{241F}" }
                            else { [string]$value }
                $snapshot["$sub\$name"] = "$kind|$rendered"
            }
            foreach ($child in $key.GetSubKeyNames()) { $stack.Push("$path\$child") }
            $base.Dispose()
        }
        catch { }
        finally { if ($key) { $key.Dispose() } }
    }

    return $snapshot
}

function Compare-Cs2OptSnapshot {
    <#
        Symmetric diff of two snapshots -> the set of value paths that differ.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Before,
        [Parameter(Mandatory)][System.Collections.IDictionary]$After
    )

    $changed = New-Object System.Collections.ArrayList
    foreach ($k in $Before.Keys) {
        if (-not $After.Contains($k)) { [void]$changed.Add($k); continue }
        if ($Before[$k] -ne $After[$k]) { [void]$changed.Add($k) }
    }
    foreach ($k in $After.Keys) {
        if (-not $Before.Contains($k)) { [void]$changed.Add($k) }
    }
    # Returned WITHOUT the array-preserving leading comma. Callers wrap this in
    # @(...), and `@(f())` keeps the outer wrapper of a `return ,@()` instead of
    # unrolling it the way a plain assignment does - which would collapse every
    # differing key into a single joined element.
    return @($changed | Sort-Object -Unique)
}
