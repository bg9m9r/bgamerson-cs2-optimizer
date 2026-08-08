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
