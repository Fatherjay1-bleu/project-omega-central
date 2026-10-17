param([string]$Gcc = 'gcc', [string]$Gxx = 'g++')
. "$PSScriptRoot\common.ps1"
Push-Location $ProjectRoot
try {
    New-Item -ItemType Directory -Force -Path 'build' | Out-Null
    Invoke-Checked -Executable $Gcc -Arguments @('-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', 'native/validator.c', '-o', 'build/validator.exe', '-lm')
    Invoke-Checked -Executable $Gxx -Arguments @('-std=c++17', '-Wall', '-Wextra', '-Werror', '-O2', '-static-libgcc', '-static-libstdc++', 'native/scorer.cpp', '-o', 'build/scorer.exe')
    Write-Host 'C validator and C++ scorer compiled successfully.'
} finally { Pop-Location }
