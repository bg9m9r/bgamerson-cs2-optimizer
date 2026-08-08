BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:DistPath = Join-Path $script:RepoRoot 'dist\Optimize-CS2.ps1'
}

Describe 'Built artifact' {

    # dist\ is committed to the repo so the script can be grabbed and run as a
    # single file. That is only safe if a stale build cannot ship silently -
    # otherwise someone edits src, forgets to rebuild, and runs outdated logic
    # against their machine. These tests are that guard.

    It 'exists' {
        Test-Path -LiteralPath $script:DistPath | Should -BeTrue -Because 'run build\Build-Script.ps1'
    }

    It 'parses' {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($script:DistPath, [ref]$null, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It 'is up to date with every source file' {
        # The build banner records a 16-char SHA256 prefix per source file.
        # Comparing those against the files on disk detects staleness without
        # duplicating the build's concatenation logic (which would drift).
        $dist = Get-Content -LiteralPath $script:DistPath -Raw

        $banner = @([regex]::Matches($dist, '(?m)^#\s{4}([0-9A-F]{16})\s\s(src\\.+?)\s*$'))
        $banner.Count | Should -BeGreaterThan 0 -Because 'the build banner should list every source file'

        $stale = New-Object System.Collections.ArrayList
        foreach ($m in $banner) {
            $recorded = $m.Groups[1].Value
            $rel      = $m.Groups[2].Value
            $path     = Join-Path $script:RepoRoot $rel

            if (-not (Test-Path -LiteralPath $path)) {
                [void]$stale.Add("$rel (in the build but missing from src)")
                continue
            }
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.Substring(0, 16)
            if ($actual -ne $recorded) { [void]$stale.Add($rel) }
        }

        $stale | Should -BeNullOrEmpty -Because 'dist is stale - re-run build\Build-Script.ps1 and commit the result'
    }

    It 'includes every file the build manifest lists' {
        $manifest = Import-PowerShellDataFile (Join-Path $script:RepoRoot 'build\build.psd1')
        $dist = Get-Content -LiteralPath $script:DistPath -Raw
        foreach ($rel in $manifest.Files) {
            if ($rel -eq 'src\00-Header.ps1') { continue }   # emitted unwrapped, no #region
            $dist | Should -BeLike "*#region $rel*" -Because "$rel should be in the built script"
        }
    }

    It 'ships the launcher alongside it' {
        Test-Path -LiteralPath (Join-Path $script:RepoRoot 'dist\Run-Optimize-CS2.cmd') | Should -BeTrue
    }
}
