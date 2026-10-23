# Omega Central production deployment checklist

Status: **verification required**. This document does not assert that Railway is currently healthy.

## CI verification
- Confirm default branch and the exact commit being deployed.
- Run Python unit tests and C/C++ build/tests on Windows and CI.
- Require CI to pass before deployment; record workflow run links.
- Verify IBM Bob integration claims against committed workflows and evidence.

## Railway readiness
- Verify project/service identity, deployment SHA, start command, runtime environment and health endpoint.
- Check public URL independently of Railway's dashboard.
- Confirm secrets are environment variables, not committed files.
- Validate startup, graceful shutdown, error handling, logs and resource limits.

## Outage recovery
1. Check Railway provider status and service deployment events.
2. Distinguish platform-wide outage from application crash or misconfiguration.
3. Check build logs and runtime logs for the deployed SHA.
4. Roll back to last known-good release if an application regression is confirmed.
5. Recheck health endpoint and user-facing workflow after recovery.

## Release gate
No production-ready label until repeatable build, green tests, authenticated admin access (if applicable), secret review, health checks, and rollback have been demonstrated with evidence.
