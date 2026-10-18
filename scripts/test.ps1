. "$PSScriptRoot\common.ps1"
Push-Location $ProjectRoot
try {
    # Run the main test suite (platform, sprint2, sprint3).
    # test_public_demo is run separately below because public_demo.py mutates
    # the shared Flask app object at import time (before_request hook, view
    # function replacement), which would affect the other tests if loaded in
    # the same process.
    Invoke-Checked -Executable (Get-ProjectPython) -Arguments @(
        '-m', 'unittest',
        'tests.test_platform', 'tests.test_sprint2', 'tests.test_sprint3',
        '-v'
    )
    # Public demo tests run in a separate process for isolation.
    Invoke-Checked -Executable (Get-ProjectPython) -Arguments @(
        '-m', 'unittest', 'tests.test_public_demo', '-v'
    )
} finally { Pop-Location }
