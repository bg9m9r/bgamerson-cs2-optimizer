@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # The script is a user-facing console tool. Write-Host is the only output
        # stream that reliably lands in Start-Transcript, so it is deliberate.
        'PSAvoidUsingWriteHost',

        # Function nouns are domain terms (Set-OptRegistryValue, Resolve-OptGates).
        'PSUseSingularNouns',

        # The param block in 00-Header.ps1 is fixed by spec 1.1 and includes
        # switches whose names PSSA considers reserved-ish.
        'PSReviewUnusedParameter',

        # Empty catch blocks are load-bearing here, not sloppy.
        #
        # The detection layer probes classes and commands that are LEGITIMATELY
        # ABSENT on many machines: Win32_Battery on a desktop, MSFT_DmaGuard on
        # older builds, Get-Tpm on a machine without one, dsregcmd on a
        # workgroup box. "Not present" is a normal answer, not an error, and
        # spec 1.5.3 requires detection failures to degrade to an Unknown
        # skeleton rather than surface as noise.
        #
        # Real failures are still captured: Invoke-OptDetector records every
        # exception into $Profile.DetectionErrors, which the detection report
        # prints. Adding a Write-Debug to each of these 21 sites would produce
        # output nobody reads while changing nothing about the behaviour.
        'PSAvoidUsingEmptyCatchBlock',

        # This script's dry-run contract is -DryRun (fixed by spec 1.1), not
        # -WhatIf, and it is enforced at exactly three mutation chokepoints
        # (Set-OptRegistryValue, Invoke-OptNativeCommand, Invoke-OptCmdletChange)
        # with a test asserting those chokepoints are never asked to mutate.
        #
        # Bolting SupportsShouldProcess onto each internal helper as well would
        # create a SECOND, parallel suppression mechanism that could drift out of
        # step with the first - so one could be honoured while the other was not.
        # One enforced mechanism is safer than two competing ones.
        'PSUseShouldProcessForStateChangingFunctions'
    )

    Rules = @{
        # Positional args into reg.exe / powercfg / netsh wrappers are a live
        # hazard in this codebase - every native call must be explicit.
        PSAvoidUsingPositionalParameters = @{ Enable = $true }

        PSUseDeclaredVarsMoreThanAssignments = @{ Enable = $true }

        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
    }
}
