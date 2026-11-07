# Omega Central: Railway outage and recovery runbook

This document applies to the **public synthetic-only demonstration**, not a production telemetry service. Do not enable ingestion or add real customer event data during recovery.

## When Railway reports an incident

1. Consult https://status.railway.com/ and record the incident status and affected regions/products. Do not infer an application defect from an infrastructure outage.
2. Avoid repeated redeploys and unnecessary configuration changes while the platform is degraded.
3. Continue GitHub development and CI independently. Do not merge unrelated emergency changes into the deployment branch.
4. Review any Railway security advisory separately. If secrets may have been exposed, inventory and rotate affected credentials in the relevant providers; never place secrets in GitHub issues, logs, or chat.

## After the provider declares recovery

1. In Railway, inspect the project, service, environment, active deployment status, deployed commit SHA, region, and build/runtime logs.
2. Confirm the deployed commit matches the reviewed GitHub main branch. Record any drift.
3. Check the HTTPS homepage, static console assets, `/demo`, three `/demo/scenario/{1,2,3}` endpoints, and `/health`. `/health` should return HTTP 200 with `status: ok`, `engine: native-c-cpp`, and `synthetic: true`; otherwise investigate before release.
4. Verify public `POST /api/v3/analyze` and `POST /health` return HTTP 405. Do not submit real telemetry.
5. Confirm Railway health-check path is `/health` (where supported) and check restart counts, errors, latency, and resource usage.
6. Validate environment variables by **name and necessity only**. Rotate affected secrets in the provider and Railway, then deploy and confirm old credentials no longer work. Never print secret values.
7. Review GitHub Actions checks for the exact deployed commit. Ensure Linux Docker smoke tests and Windows regression tests are green.
8. If the new release is unhealthy, use Railway's verified previous healthy deployment as a rollback target. Record the rollback commit and rerun all smoke checks.
9. Record incident timeline, impact, recovery evidence, and any follow-up actions.

## Release gates

- Provider reports recovered and Railway dashboard/API are accessible.
- GitHub checks pass for the candidate commit.
- Public API remains read-only and synthetic-only.
- Native-engine readiness probe passes; failure returns 503 without internal diagnostics.
- Secrets reviewed/rotated as applicable; no exposed credentials.
- A rollback target and on-call owner are identified.

**Stop:** A healthy demo is not authorization to enable real telemetry ingestion, privileged workstation actions, or live AI inference. Those require separate architecture, security review, and explicit approval.
