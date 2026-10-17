# Project Omega Central — SentinelOps AI

A local Windows cybersecurity event analysis prototype using **synthetic events**.
Python/Flask orchestrates a compiled C validator and C++ risk scorer. No production
telemetry, credentials, external APIs, or active AI model integrations are used.

## Windows setup

Prerequisites: Windows 10/11, PowerShell 5.1+, Python 3.10+ with pip/venv,
GCC/G++ with C11/C++17 support (for example a MinGW-w64 UCRT toolchain), and Git
for version control. Installation and downloads require the workspace owner's
approval. Scripts never install compilers or alter system settings.

From the repository root in PowerShell:

```powershell
# Uses an existing Python interpreter. Explicit path is supported.
.\scripts\setup.ps1 -PythonPath 'C:\path\to\python.exe'
# If Flask is absent, approve the download before using this flag:
.\scripts\setup.ps1 -PythonPath 'C:\path\to\python.exe' -AllowNetwork
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\run.ps1
```

With Python on PATH, omit `-PythonPath`. An activated environment is unnecessary.
For compilers outside PATH:

```powershell
.\scripts\build.ps1 -Gcc 'C:\path\to\gcc.exe' -Gxx 'C:\path\to\g++.exe'
```

Keep the toolchain's `bin` directory on the current process PATH if its runtime
DLLs require it. The build statically links GCC/C++ runtime support where possible.
Open **http://127.0.0.1:5000**; stop with Ctrl+C. Debug mode is disabled. This uses
Flask's development server for local demonstration only. If PowerShell policy
blocks scripts, use an organization-approved execution method; scripts do not
change execution policy. Missing tools or Flask are reported as setup errors.

## Data and architecture

`data/events.json` defines four synthetic examples, one per risk class.
`GET /` displays results; `GET /api/events` returns JSON. There is no upload route.
Every request reanalyzes the fixtures through both compiled engines.

An event has exactly these fields:

| Field | Contract |
| --- | --- |
| `id`, `source` | Nonempty printable text, at most 128 characters |
| `severity` | Integer 0–10 |
| `failed_logins` | Integer 0–1,000,000 |
| `suspicious_process` | JSON boolean |

Python validates the JSON schema before converting numeric fields to the native
wire format: `severity failed_logins suspicious_flag`, separated by whitespace.
Both native tools independently reject malformed, extra, nonfinite, fractional,
or out-of-range input. C emits `VALID` or `INVALID`; C++ emits `score RISK`.
Subprocesses use a five-second timeout, no shell, and checked output. Engine
failures surface as HTTP 503. HTML values are escaped by Jinja.

Score = `min(100, severity*6 + min(failed_logins,10)*2 + suspicious_flag*20)`.
Risk classes: LOW 0–24, MEDIUM 25–49, HIGH 50–79, CRITICAL 80–100. This is an
illustrative deterministic heuristic, not a calibrated detection model. Scores
are always even, so tests exercise both sides of the 25 threshold with 24 and 26.

## Development and verification

See `AGENTS.md` for standards. Tests use Python's standard `unittest` framework
and real compiled binaries, plus failure-injection tests for unavailable engines.
They cover valid and malformed events, numeric bounds, scoring classes, dashboard
rendering, JSON output, escaped HTML, timeouts, and invalid native responses.
Builds enable `-Wall -Wextra -Werror`. Generated binaries and virtual environments
are ignored by Git. The Windows GitHub Actions workflow builds and tests after
a future authorized push; this task does not publish or trigger remote CI.

Once Git is available, initialize local version control with `git init` and review
changes with `git status`. Do not commit dependencies, credentials, or binaries.

## Future IBM Bob and Gemini integration

Neither IBM Bob nor Gemini is active. IBM Bob could assist reviewed development
and testing. A future optional Gemini provider could summarize validated events
for an analyst. Any implementation needs explicit external-access approval,
redacted or synthetic inputs, secret management, bounded timeouts, auditability,
and a fallback when unavailable. Model output must never override native
validation or deterministic scores. There are no SDKs, API keys, or outbound
requests in this prototype.
