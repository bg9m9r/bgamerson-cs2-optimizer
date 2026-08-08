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
