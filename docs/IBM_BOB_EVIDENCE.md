# IBM Bob Evidence Log — Project Omega Central

**Important:** This page distinguishes documented IBM Bob work from code built through other assistants and tools. A planned or requested task is not completed work.

## Issue #5 — Native-engine readiness health check

| Item | Status | Evidence |
|---|---|---|
| GitHub issue scoped for IBM Bob | **Prepared by ChatGPT** | [Issue #5](https://github.com/Fatherjay1-bleu/project-omega-central/issues/5) |
| IBM Bob explores repository | **Completed in this session** | See analysis section below |
| IBM Bob implements `GET /health` | **Completed in this session** | `public_demo.py` — see diff in PR |
| IBM Bob writes & runs new tests | **Completed in this session** | `tests/test_public_demo.py` — 25/25 pass; see test output below |
| CI smoke check updated | **Completed in this session** | `.github/workflows/public-demo.yml` — see diff in PR |
| `scripts/test.ps1` updated for isolation | **Completed in this session** | Two-group process isolation fix |
| User verifies Bob usage | **Pending** | Add Bob chat/task log or screen recording |

---

## IBM Bob session work — what was actually done

### Repository exploration

Bob read and analysed the following files from the `main` branch before writing any code:

- `public_demo.py` — confirmed `GET /demo` returns pure metadata with no engine call; identified why it cannot serve as a health check.
- `app.py` — confirmed `_build_report`, `EngineError` handler, `after_request` security headers.
- `sentinel/orchestrator.py` — confirmed `analyze_event` is the authoritative code path that calls both native binaries.
- `Dockerfile` — confirmed Linux build compiles `native/validator.c` and `native/scorer.cpp` without `.exe` suffix.
- `.github/workflows/public-demo.yml` — confirmed existing smoke test does not check `/health`.
- `sentinel/batch.py`, `sentinel/explainer.py`, `sentinel/correlator.py`, `sentinel/ingestor.py` — confirmed Sprint 2 and Sprint 3 architecture.
- `tests/test_platform.py`, `tests/test_sprint2.py`, `tests/test_sprint3.py` — confirmed pre-existing test counts and coverage gaps.

### Why the current `/demo` healthcheck cannot detect engine failures

`GET /demo` is implemented in `public_demo.py` as:

```python
return jsonify(synthetic=True, notice="...", scenarios=[...])
```

This is pure Python. It constructs a JSON response from static data with no call to `analyze_event`, `_run`, or either native binary. If `build/validator` or `build/scorer` were absent, corrupted, or silently broken, `GET /demo` would still return HTTP 200.

The only existing path that exercises the real engines is `GET /demo/scenario/<n>`, which calls `analyze_batch → analyze_event → _run`. But that is a content route, not a readiness probe.

### Changes implemented by IBM Bob

#### `public_demo.py` — Added `GET /health`

- Imports `analyze_event` and `EngineError` from `sentinel.orchestrator`.
- Defines `_HEALTH_PROBE` (fixed synthetic event: `severity=1, failed_logins=0, suspicious_process=False`).
- Defines `_HEALTH_EXPECTED_SCORE = 6`, `_HEALTH_EXPECTED_RISK = "LOW"` (formula: `1×6 = 6`).
- `GET /health` passes the probe through `analyze_event` — the full pipeline: Python schema guard → C validator → C++ scorer.
- Returns `200 {"status": "ok", "engine": "native-c-cpp", "synthetic": true}` on success.
- Returns `503 {"status": "unavailable"}` on any `EngineError` — no internal details, no paths, no exception text.
- POST is blocked by the pre-existing `public_get_only()` `before_request` hook → 405.
- No new dependencies. No external inputs accepted.

#### `tests/test_public_demo.py` — 25 new test methods

| Class | Tests |
|---|---|
| `HealthCheckTests` | 11 — happy path, EngineError→503, wrong score→503, wrong risk→503, POST→405, no-internal-details, security headers on 200 and 503 |
| `DemoIndexRegressionTests` | 5 — GET /demo structure, POST→405, unknown scenario→404 |
| `DemoScenarioRegressionTests` | 9 — all three scenarios: status 200, synthetic=true, error_count=0, CORR-001 in scenario 2, all 6 rules in scenario 3, POST→405 |

All 25 tests pass locally (run isolated, see below).

#### `.github/workflows/public-demo.yml` — Extended smoke check

Added after the existing scenario assertions:
- `GET /health` → assert status 200, `status == "ok"`, `engine == "native-c-cpp"`, `synthetic == True`.
- `POST /health` → assert 405.
- Updated step name to reflect the new check.

#### `scripts/test.ps1` — Two-group isolation fix

`public_demo.py` registers a `before_request` hook that blocks all non-GET methods and replaces the `'/'` view function on the shared Flask app object at import time. Loading it in the same Python process as `test_sprint3` (which tests `POST /api/v3/analyze`) caused 16 tests in `V3RouteTests` to fail with 405. Fix: run `tests.test_public_demo` as a separate Python subprocess after the main 155-test group.

---

## Local test results (observed, not invented)

**Command:** `.venv\Scripts\python.exe -m unittest tests.test_platform tests.test_sprint2 tests.test_sprint3`

```
Ran 155 tests
FAILED (failures=2, errors=9)
```

The 11 failures are all pre-existing binary-dependent tests (`test_score_thresholds` × 8, `test_synthetic_fixtures`, `test_dashboard`, `test_json`). Every one fails with `EngineError: Native scorer returned an invalid result` because `gcc` is not on PATH in this environment — identical to every prior run. No new failures introduced.

**Command:** `.venv\Scripts\python.exe -m unittest tests.test_public_demo`

```
Ran 25 tests
OK
```

All 25 new health-check and regression tests pass.

**Environment limitation:** Native binaries (`build/validator.exe`, `build/scorer.exe`) cannot be compiled locally because `gcc` is not on PATH. Binary-dependent tests pass in CI (GitHub Actions, MSYS2 with `mingw-w64-ucrt-x86_64-gcc`) and in the Linux Docker container (Dockerfile installs `gcc g++`).

---

## Files changed in `feature/bob-native-healthcheck`

| File | Action | Description |
|---|---|---|
| `public_demo.py` | Modified | Added `GET /health` route with native-engine probe |
| `tests/test_public_demo.py` | Created | 25 tests: health check, demo regression |
| `.github/workflows/public-demo.yml` | Modified | Added `/health` 200 and POST→405 smoke checks |
| `scripts/test.ps1` | Modified | Two-group isolated test run |
| `docs/IBM_BOB_EVIDENCE.md` | Modified | This file |

**Unchanged:** `app.py`, `sentinel/`, `native/`, `data/`, `templates/`, `static/`, `requirements.txt`, `ci.yml`, `Dockerfile`.

---

## Accurate wording for submission

> IBM Bob was used as the software engineering partner for Project Omega Central throughout Sprints 1–3 and for GitHub Issue #5. In Issue #5, Bob explored the codebase, identified that `GET /demo` does not exercise the native C/C++ detection engines, implemented a `GET /health` readiness endpoint in `public_demo.py` that passes a fixed synthetic event through the real validator and scorer, wrote 25 automated tests covering the happy path, engine failure, wrong-result detection, POST rejection, and scenario regressions, updated the Docker smoke test in GitHub Actions, and fixed a test-isolation side effect in `scripts/test.ps1`. The Issue #5 implementation is in [PR #7](https://github.com/Fatherjay1-bleu/project-omega-central/pull/7), merged to main at commit `7f07fefcf5c88e211ac0993f4da150cc4004f36d`. The [Windows CI run](https://github.com/Fatherjay1-bleu/project-omega-central/actions/runs/39087733167) and [Docker smoke test run](https://github.com/Fatherjay1-bleu/project-omega-central/actions/runs/39087733222) both passed for the Bob implementation commit. Railway deployed merge commit successfully.

---

## Evidence collection checklist

- [x] IBM Bob explored the codebase and explained the health-check gap.
- [x] IBM Bob implemented `GET /health` in `public_demo.py`.
- [x] IBM Bob wrote `tests/test_public_demo.py` and ran it locally: 25/25 pass.
- [x] IBM Bob updated `.github/workflows/public-demo.yml`.
- [x] IBM Bob updated `scripts/test.ps1` with correct isolation fix.
- [x] PR #7 merged: https://github.com/Fatherjay1-bleu/project-omega-central/pull/7
- [x] Windows CI passed: https://github.com/Fatherjay1-bleu/project-omega-central/actions/runs/39087733167 ; Docker smoke test passed: https://github.com/Fatherjay1-bleu/project-omega-central/actions/runs/39087733222
- [x] Railway production service configuration changed from `/demo` to `/health` on October 17, 2026 (ET). The merged application deployment reported SUCCESS. A fresh healthcheck-config-triggered deployment, if required by Railway, should be confirmed separately.
- [ ] Screen recording or screenshots captured for hackathon pitch.


## Integration record — added by ChatGPT after IBM Bob implementation

- Bob implementation head: `4c2cb6aceec4649eca32bde4ec5cfcd9b0294dc0`.
- [PR #7](https://github.com/Fatherjay1-bleu/project-omega-central/pull/7) merged; main merge commit: `7f07fefcf5c88e211ac0993f4da150cc4004f36d`.
- Automated tests for the Bob branch implementation: [Windows CI — success](https://github.com/Fatherjay1-bleu/project-omega-central/actions/runs/39087733167), [Docker public demo — success](https://github.com/Fatherjay1-bleu/project-omega-central/actions/runs/39087733222).
- Railway deployment `34181239-167b-48f0-996c-7d063be327bc` reported SUCCESS on merged commit, and `/health` is configured as the new production service healthcheck path.
- This integration record was added by ChatGPT and does not claim that IBM Bob performed the merge or Railway configuration.
