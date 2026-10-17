param(
    [string]$PythonPath = 'python',
    [switch]$AllowNetwork
)
. "$PSScriptRoot\common.ps1"
Push-Location $ProjectRoot
try {
    Invoke-Checked -Executable $PythonPath -Arguments @('-c', 'import sys; assert sys.version_info >= (3,10)')
    if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
        Invoke-Checked -Executable $PythonPath -Arguments @('-m', 'venv', '.venv')
    }
    $projectPython = Get-ProjectPython
    & $projectPython -c "import flask; from importlib.metadata import version; assert int(version('Flask').split('.')[0]) == 3"
    if ($LASTEXITCODE -ne 0) {
        if (-not $AllowNetwork) {
            throw 'Flask 3 is missing. After approving network access, rerun setup with -AllowNetwork.'
        }
        Invoke-Checked -Executable $projectPython -Arguments @('-m', 'pip', 'install', '-r', 'requirements.txt')
    }
    Write-Host 'Setup complete.'
} finally { Pop-Location }
