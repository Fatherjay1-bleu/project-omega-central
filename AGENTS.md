# Project Omega Central — SentinelOps AI

## Architecture
`app.py` serves a local Flask dashboard. `sentinel/orchestrator.py` checks synthetic
JSON events, invokes the C validator and C++ scorer over standard input, and
returns results to the dashboard. Native programs accept a narrow numeric wire
format, never shell commands. `data/events.json` contains synthetic fixtures.

## Development standards
- Work only inside this workspace; preserve existing functional code and fixtures.
- Ask before downloads, software installation, network access, or system changes.
- Never ingest credentials or production telemetry by default. Never publish or deploy.
- Use Python 3.10+, C11, C++17, and Windows-compatible paths. Invoke subprocesses
  with argument lists, a timeout, and no shell. Fail closed on invalid engine output.
- Keep native binaries generated, not committed. Build with strict warnings.
- Keep the dashboard on loopback with debug mode disabled.

## Testing
Run `./scripts/build.ps1` then `./scripts/test.ps1` before considering changes done.
Tests must exercise the compiled engines, malformed input, score boundaries,
orchestration, and Flask routes. Do not claim tests passed unless executed.

## Future integrations
IBM Bob could assist development through reviewed patches and test generation.
Gemini could supply optional analyst summaries through a future provider adapter.
Neither integration is implemented or active. Any adapter must be opt-in, use
synthetic/redacted data, keep secrets out of source, and require approval before
external requests. Native validation and scoring remain authoritative.
