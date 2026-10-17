. "$PSScriptRoot\common.ps1"
Push-Location $ProjectRoot
try {
    foreach ($engine in @('validator', 'scorer')) {
        if (-not (Test-Path -LiteralPath "build\$engine.exe")) { throw 'Native engine missing. Run .\scripts\build.ps1 first.' }
    }
    Write-Host 'Dashboard: http://127.0.0.1:5000 (Ctrl+C to stop)'
    Invoke-Checked -Executable (Get-ProjectPython) -Arguments @('app.py')
} finally { Pop-Location }
