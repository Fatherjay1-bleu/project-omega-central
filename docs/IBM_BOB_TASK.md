# IBM Bob Implementation Task — Project Omega Central

**Status: Awaiting execution in IBM Bob.** This document was prepared by ChatGPT; it is **not** evidence that Bob has modified or reviewed this project.

## Mission: Explore → Fix → Build → Test

You are IBM Bob acting as the engineer on [GitHub issue #5](https://github.com/Fatherjay1-bleu/project-omega-central/issues/5) in repository `Fatherjay1-bleu/project-omega-central`. Complete the task yourself in the development environment. Do not only propose code: implement the changes, execute the tests, and report your actual outputs. Use a new Git branch `feature/bob-native-healthcheck`.

### 1. Explore
Inspect `app.py`, `public_demo.py`, `sentinel/orchestrator.py`, `Dockerfile`, `.github/workflows/public-demo.yml`, and the tests. Explain briefly why the current Railway `/demo` HTTP health check may pass even if the C validator or C++ scorer is broken.

### 2. Build the missing capability
- Add **GET /health** to `public_demo.py` (or a small documented helper).
- Exercise **both** native binaries by passing a fixed, synthetic event through the existing `analyze_event` orchestration function. No inbound event content or user data.
- On healthy validated results, respond `200` with a small JSON payload, e.g. `{"status":"ok","engine":"native-c-cpp","synthetic":true}`. Do not return host identifiers, paths, or diagnostics that expose internals.
- On native startup/scoring failure, return a generic `503` JSON result such as `{"status":"unavailable"}` with no exception details.
- Preserve the public **GET-only** rule and existing scenario URLs/responses.

### 3. Test your own implementation
- Add automated tests for (a) valid live-engine response; (b) simulated `EngineError` and safe 503 response; (c) POST to `/health` denied; (d) no regressions in all three scenario routes.
- Update `.github/workflows/public-demo.yml` to smoke-check `GET /health` returns `200` and the expected status.
- Run the repo's documented test commands in your environment, including existing Windows tests where available, and the Linux Docker smoke test through GitHub Actions. Report the exact commands, count, and outcomes. **Never claim a test passed without observing it.**

### 4. Commit and document Bob's actual work
- Commit the **code changes made by IBM Bob** with an accurate descriptive commit message on `feature/bob-native-healthcheck`. Open a PR to `main` linking issue #5.
- In the PR body include: your analysis, files changed, test outputs, and verification screenshots/transcript from the IBM Bob session.
- Update `docs/IBM_BOB_EVIDENCE.md` with links to actual evidence. Do not write invented metrics or claim unrelated parts of the project were authored by Bob.
- Do not merge to production until CI passes and the user reviews the change; Railway `/health` routing can be updated afterward.

## User instruction to IBM Bob (paste directly)

> IBM Bob: take ownership of GitHub issue #5 in Project Omega Central. Explore the codebase, implement a real native C/C++ readiness endpoint, write and run tests, create a PR, and provide evidence of your own actions (actual task transcript or screenshots, commit SHA, and CI links). Do the coding and testing yourself; don't only give recommendations. Do not attribute any earlier project files to yourself.
