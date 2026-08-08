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
