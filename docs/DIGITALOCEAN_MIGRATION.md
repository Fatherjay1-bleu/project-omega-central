# DigitalOcean App Platform migration — Omega Central

## Status
Candidate deployment specification only. No DigitalOcean app, billing resource, DNS cutover, or secret has been created. Railway remains the existing deployment until an approved cutover.

## Preconditions
- Confirm DigitalOcean account, payment approval, and chosen region/plan before creating paid resources.
- Review `.do/app.yaml` against the current DigitalOcean App Platform specification in the console. The service uses the existing Dockerfile, port 8080, and `/health` native C/C++ readiness check.
- Ensure the DigitalOcean GitHub integration is authorized for this repository. For a private repository, grant only the required repository access.
- Review GitHub main branch protection and CI; do not turn on auto-deploy until tests and security review pass.
- Review credentials potentially affected by the October 2026 Railway security incident and rotate any at-risk tokens before migration. Do not copy secrets into source control.

## Deployment procedure
1. Run local tests and `docker build -t omega-central-demo .`.
2. Start container: `docker run --rm -p 18080:8080 omega-central-demo`.
3. Confirm GET `/health` returns 200 with `status=ok`, `engine=native-c-cpp`, `synthetic=true`.
4. Confirm GET `/`, `/demo`, and all three `/demo/scenario/{1,2,3}` endpoints; ensure POST `/health` and `/api/v3/analyze` return 405.
5. In DigitalOcean App Platform, create a new app from GitHub or import the reviewed `.do/app.yaml`. Confirm the plan and estimated charges before provisioning. Leave Railway running.
6. Test the temporary DigitalOcean URL over HTTPS, including `/health`, UI assets, synthetic scenario correctness, access restrictions, logs, and failure recovery.
7. Validate alerts, rollback behavior, costs, and a security review. Only then approve traffic cutover; if a custom domain is used, separately plan DNS and certificate verification.
8. Monitor the new deployment and retain the Railway rollback option until acceptance criteria are met.

## Release gates
- GitHub CI green on the exact deployed SHA
- Native-engine health check healthy after deployment
- No real customer data ingestion; public demo remains synthetic and read-only
- Security headers and TLS verified
- No secrets exposed in GitHub or logs
- Explicit owner approval for paid provisioning and final traffic cutover

## Rollback
If acceptance tests fail, do not switch traffic. If a later cutover fails, restore the previously working DNS or routing configuration and validate Railway health before declaring recovery.
