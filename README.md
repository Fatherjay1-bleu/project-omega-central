# Project Omega Central — SentinelOps AI

**Explainable cybersecurity event scoring and correlation, developed with IBM Bob.**
**Hackathon track:** Students / Early Career — Explore, Fix, and Build.

SentinelOps AI is a synthetic cybersecurity demonstration combining **Python/Flask**, a compiled **C validation engine**, and a compiled **C++ risk scorer**. Python provides event validation, batch orchestration, transparent score contributions, and six deterministic correlation rules. **The scoring engine is not a trained AI model.** IBM Bob was used as a development assistant. Gemini inference is not integrated.

## Live demonstration (read-only public container)

The Docker-based public demo runs Gunicorn and compiles its native C/C++ engines during its Linux build. It accepts no user-supplied event data; POST requests are rejected with HTTP 405. **Live Railway deployment:** https://project-omega-central-production.up.railway.app\n\nVerified public demonstration routes:

- `/` — dashboard of packaged synthetic events
- `/demo` — three-scenario index (JSON)
- `/demo/scenario/1` — normal low-risk activity
- `/demo/scenario/2` — authentication incident
- `/demo/scenario/3` — critical cluster exercising all six correlation-rule types

See [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md) for the hosting procedure, Docker smoke-test instructions, security notes, and URL checks. **Do not submit a localhost or GitHub URL as a live deployed application.**

## Windows development setup

Requirements: Windows 10/11, PowerShell, Git, Python 3.10+, GCC/G++ with C11/C++17 support (MSYS2 UCRT64 is verified).

```powershell
git clone https://github.com/Fatherjay1-bleu/project-omega-central.git
cd project-omega-central
$env:Path = "C:\msys64\ucrt64\bin;$env:Path"
.\scripts\setup.ps1
# If Flask is absent and downloads are approved:
# .\scripts\setup.ps1 -AllowNetwork
.\scripts\build.ps1
.\scripts\test.ps1
.\scripts\run.ps1
```

Open http://127.0.0.1:5000 locally. This uses Flask's **development server** bound to loopback, not public hosting. Use Ctrl+C to stop.

## Architecture and score

```text
Synthetic fixtures / local JSON POST
             |
      Python / Flask
             |
   Schema and batch validation
             |
      C native validator
             |
      C++ native scorer
             |
      Python explanations
       + 6 correlations
             |
     Dashboard / JSON API
```

Event fields are `id`, `source`, `severity` (0–10), `failed_logins` (0–1,000,000), and `suspicious_process` (boolean).

```text
score = min(100, severity*6 + min(failed_logins,10)*2
                 + (20 if suspicious_process else 0))
```

LOW = 0–24; MEDIUM = 25–49; HIGH = 50–79; CRITICAL = 80–100. This is a transparent demonstration heuristic, **not** a trained, calibrated threat prediction model.

## APIs in the local development application

- `GET /` — Flask dashboard of the synthetic default fixtures
- `GET /api/events` — legacy event output
- `GET /api/v2/report` — explanation, risk distribution, and correlation findings
- `POST /api/v3/analyze` — in-memory batch analysis with 256 KiB request limit and 500-event cap; returns partial validation errors, explained scores, correlation findings and distribution

The **public Docker entrypoint disables all POST operations**, including `/api/v3/analyze`. The interactive ingestion API is meant only for local demo/testing and is not a public production endpoint.

Example local-only request:

```powershell
$body = '{"events":[{"id":"DEMO-1","source":"synthetic-host","severity":8,"failed_logins":12,"suspicious_process":true}]}'
Invoke-RestMethod http://127.0.0.1:5000/api/v3/analyze -Method POST -ContentType application/json -Body $body
```

This produces score **88**, risk **CRITICAL**.

## Scenario fixtures

- `data/demo_scenario_1.json`: three LOW events, no correlations
- `data/demo_scenario_2.json`: login-failure cluster and CORR-001 (S2-003 score = 50)
- `data/demo_scenario_3.json`: high-risk cluster triggering CORR-001–006 rule types

## Tests and validation

```powershell
.\scripts\build.ps1
.\scripts\test.ps1
```

**155 tests passed** on Windows after Sprint 3 merge, including the compiled C/C++ programs. The [Windows GitHub Actions CI](https://github.com/Fatherjay1-bleu/project-omega-central/actions) also passed on commit `d58ed00`. A separate [Linux Docker workflow](.github/workflows/public-demo.yml) tests public scenario routes and rejects POST ingestion (results must be checked on the new PR).

## Changes made during the hackathon

- Sprint 1: hardened parsing, HTTP headers, error handling, reproducible Windows build/test pipeline
- Sprint 2: explainable score breakdown, bounded batches, correlation rules CORR-001–004, improved dashboard
- Sprint 3: safeguarded event-ingestion API, correlation rules CORR-005–006, three demo scenarios and expanded tests
- Deployment: Linux Docker build of original native engines, Gunicorn WSGI server and read-only synthetic-only public demo

## Limitations and roadmap

This is **not a production security product**. It does not ingest actual infrastructure telemetry, authenticate users, train a model, or provide live AI inference. Scoring is deterministic. Future extensions include authenticated/rate-limited telemetry ingestion, production observability, configurable rules, and opt-in AI summaries with privacy controls.

See [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md) for the judge-facing demo and [VALIDATION.md](VALIDATION.md) for the original early environment notes (which were superseded by verified later runs).
