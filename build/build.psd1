@{
    # Explicit ordered file list. Deliberately NOT a glob - concatenation order
    # is load-bearing (helpers must be defined before the sections that call
    # them), and a glob would silently reorder on rename.
    OutputScript = 'dist\Optimize-CS2.ps1'
    OutputCmd    = 'dist\Run-Optimize-CS2.cmd'

    # Files permitted to contain top-level statements. Everything else must be
    # function definitions only, so tests can dot-source a single file without
    # side effects.
    TopLevelAllowed = @(
        'src\00-Header.ps1'
        'src\90-Main.ps1'
    )

    # The mutation chokepoints. Only these files may invoke native tools or
    # call mutating cmdlets directly; the AST gate fails the build otherwise.
    # This is what keeps "nothing outside the platform layer can mutate the OS"
    # a mechanical property rather than a convention.
    PlatformFiles = @(
        'src\10-Core\Invoke.ps1'
        'src\10-Core\Registry.ps1'
        'src\10-Core\RegistryBackup.ps1'
    )

    Files = @(
        'src\00-Header.ps1'

        'src\10-Core\State.ps1'
        'src\10-Core\Paths.ps1'
        'src\10-Core\Logging.ps1'
        'src\10-Core\Decision.ps1'
        'src\10-Core\Invoke.ps1'
        'src\10-Core\Tier.ps1'
        'src\10-Core\ChangeRecord.ps1'
        'src\10-Core\RegistryBackup.ps1'
        'src\10-Core\Registry.ps1'
        'src\10-Core\Manifest.ps1'
        'src\10-Core\Verify.ps1'
        'src\10-Core\Rollback.ps1'

        'src\20-Interop\Interop-Bootstrap.ps1'
        'src\20-Interop\Interop-Display.ps1'
        'src\20-Interop\Interop-Mouse.ps1'
        'src\20-Interop\Interop-Cpu.ps1'

        'src\30-Detect\DetectorFramework.ps1'
        'src\30-Detect\Detect-Os.ps1'
        'src\30-Detect\Detect-Cpu.ps1'
        'src\30-Detect\Detect-Gpu.ps1'
        'src\30-Detect\Detect-Memory.ps1'
        'src\30-Detect\Detect-Storage.ps1'
        'src\30-Detect\Detect-Network.ps1'
        'src\30-Detect\Detect-Display.ps1'
        'src\30-Detect\Detect-Audio.ps1'
        'src\30-Detect\Detect-Input.ps1'
        'src\30-Detect\Detect-Power.ps1'
        'src\30-Detect\Detect-Security.ps1'
        'src\30-Detect\Detect-Games.ps1'
        'src\30-Detect\Detect-Boot.ps1'
        'src\30-Detect\Detect-Virtualization.ps1'
        'src\30-Detect\Get-OptProfile.ps1'

        'src\40-Gates\GateMatrix.ps1'
        'src\40-Gates\Resolve-OptGates.ps1'

        'src\50-Sections\Section-00-SecurityFlight.ps1'
        'src\50-Sections\Section-02-Power.ps1'
        'src\50-Sections\Section-03-Gpu.ps1'
        'src\50-Sections\Section-04-Scheduler.ps1'
        'src\50-Sections\Section-05-MemStorage.ps1'
        'src\50-Sections\Section-06-Input.ps1'
        'src\50-Sections\Section-07-Network.ps1'
        'src\50-Sections\Section-08-Background.ps1'
        'src\50-Sections\Section-09-Defender.ps1'
        'src\50-Sections\Section-10-Vbs.ps1'
        'src\50-Sections\Section-13-BadTweaks.ps1'
        'src\50-Sections\Section-Manual.ps1'

        'src\60-Report\Report-Detection.ps1'
        'src\60-Report\Report-Console.ps1'
        'src\60-Report\Report-Markdown.ps1'

        'src\90-Main.ps1'
    )
}
