. "$PSScriptRoot\common.ps1"
Push-Location $ProjectRoot
try {
    Invoke-Checked -Executable (Get-ProjectPython) -Arguments @('-m', 'unittest', 'discover', '-s', 'tests', '-v')
} finally { Pop-Location }
