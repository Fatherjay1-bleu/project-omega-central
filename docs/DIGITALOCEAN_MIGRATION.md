# DigitalOcean App Platform migration — Omega Central

## Phase 6 status and authorization
DigitalOcean App Platform is the selected migration target. This PR prepares readiness only.
Railway remains production. Merging this PR does not authorize provisioning, deployment,
DNS changes, traffic cutover, or Railway retirement. Paid provisioning and production
cutover each require separate explicit owner approval.

## Verified baseline — October 23, 2026
Read-only Railway inspection:
- Project: sentinelops-ai-hackathon (`5d3da772-21f8-4af9-9a9d-f6531871bf2b`).
- Environment: production (`86ac1dbc-37c8-4b3d-93a1-a3c9b707769c`).
- Active service: project-omega-central (`ea766255-910b-4564-b301-4386d0343dd4`).
- Production URL: https://project-omega-central-production.up.railway.app
- Latest deployment: `4f0e28fd-e505-4129-92cc-978d6b4ca141`, SUCCESS;
  source `42180f6c4210d272bccdbe5a2239158833fcec89`, main.
- Dockerfile builder, port 8080, health path /health, timeout 180 seconds,
  one replica in us-east4-eqdc4a. No service variables or staged changes reported.
- Railway reports the latest deployment can be redeployed and rolled back.
  These flags are time-sensitive, not proof of a successful rollback drill.
- The separate sentinelops-demo service has no deployments or public domains;
  do not use it as the fallback.
- No custom domains were returned. The Railway-generated hostname cannot be
  moved to DigitalOcean; use a separately approved custom domain or update
  consumer links during an approved cutover.
- Live HTTP health is UNVERIFIED: the web request tool could not access the URL,
  and the local HTTPS client failed authentication. Control-plane SUCCESS alone
  does not establish current application health.

Recheck this baseline immediately before any approved operation.

## Candidate specification review
`.do/app.yaml` is a candidate paid-service specification, not an executed migration.
It uses the existing Dockerfile, port 8080, native C/C++ /health readiness probe,
one instance, and deploy_on_push: false. Keep automatic deployment disabled.
The branch is main: verify the actual DigitalOcean build commit matches the
approved release SHA; a branch name is not an immutable release pin.

Reference reviewed: https://docs.digitalocean.com/products/app-platform/reference/app-spec/
The Dockerfile source, port and health-check approach match the documented model.
DigitalOcean account-side validation, plan availability, pricing and deployment
behavior have NOT been tested. Validate the complete spec using the current
DigitalOcean validator before provisioning; review routing compatibility and
the basic-xxs plan in the intended account. Do not treat this PR as validation
of current cost or capacity.

## Approval gates
1. Readiness review: record reviewer, intended release SHA, and test evidence.
2. Paid provisioning: owner approves the specific DigitalOcean account/team,
   region, plan, monthly estimate/limit, and trial duration. No resource creation
   before this approval. Do not assume credits make infrastructure free.
3. Traffic cutover: after candidate acceptance, owner separately approves the
   exact routing/link changes, maintenance window, rollback owner and thresholds.
4. Railway retirement: separate approval only after the observation window and
   rollback acceptance. Keep the working service and its source available.

## Preparation without infrastructure changes
- Preserve the owner's $0 GitHub Actions paid-spending budget; do not modify
  billing, enable paid runners, dispatch workflows, or rerun existing jobs.
  This readiness documentation commit uses [skip ci]. Required checks may remain
  pending; never bypass them to merge or deploy.
- Retain main's CI cost-saving changes (PR #11). This branch predates them;
  resolve against current main before release without replacing its workflows.
- Run ./scripts/build.ps1 then ./scripts/test.ps1 in a prepared local workspace.
  Build the Docker image locally and exercise its native engines. Record actual
  results and tool versions; do not claim success from configuration inspection.
- Confirm GitHub integration has only required repository access. Inspect
  credentials only if needed; do not copy secrets to source, logs or this record.
  Assess rotation from verified exposure evidence, not an assumed incident.
- Inventory any external data/state before migration. This demo processes
  packaged synthetic fixtures; stop and design backup/restore if persistent
  state or external integrations have since been added.
- Capture current Railway deployment/config, domain mappings, DNS records and TTL
  where applicable. Keep the snapshot free of secret values.

## Candidate validation after paid provisioning approval
1. Import the reviewed specification to create the approved parallel app.
   Leave Railway and its domain configuration intact.
2. Record DigitalOcean app/deployment IDs, actual source SHA, resolved spec,
   temporary HTTPS URL, approved plan and cost estimate. Check SHA against
   exact-release CI and local test evidence.
3. On the temporary URL, require GET /health = 200 with status=ok,
   engine=native-c-cpp, synthetic=true; GET / and /demo = 200; and both
   /static/console.js and /static/console.css = 200.
4. Check all three /demo/scenario/{1,2,3} endpoints: synthetic=true and
   error_count=0. Scenario 1 has no correlation findings; scenario 2 includes
   CORR-001; scenario 3 includes CORR-001 through CORR-006.
5. In the isolated candidate only, verify POST /health and /api/v3/analyze
   return 405, TLS/security headers, logs without secrets, and unavailable-engine
   failure behavior. Never stop or corrupt production engines for a drill.
6. Rehearse recovery on the candidate; record elapsed recovery time and results.
   Recheck Railway health from a working HTTPS client before cutover approval.
7. Define monitoring owner and alert destination. Proposed acceptance window:
   30 minutes of health checks once per minute with zero failed probes; review
   logs and resource usage. Agree on a longer observation period before retirement.

## Cutover record (complete only after separate approval)
Record owner approval, UTC timestamp, approved SHA and deployment IDs, original
and replacement routing/link values, DNS TTL if used, health evidence for both
platforms, monitoring owner, and recovery target. For DNS, wait for applicable
TTL and verify authoritative and client resolution plus certificates.
If no custom domain exists, list every consumer URL/link to change and restore.
Keep automatic deploys disabled during the migration window.

## Rollback procedure
Trigger rollback for a failed readiness probe confirmed on two consecutive
checks one minute apart, incorrect synthetic results, security regression, or
owner decision. For a security issue, stop the cutover immediately.
1. Before cutover: abort acceptance; leave traffic on Railway. Investigate the
   isolated candidate. Do not create more resources or delete the app without
   appropriate authorization.
2. After cutover: the designated operator restores the recorded original DNS,
   routing or consumer links under the approved rollback plan. Validate Railway
   /health and synthetic scenarios first where possible; if unhealthy, escalate
   and do not declare recovery merely because routing was restored.
3. If Railway code recovery is needed, inspect available deployments again.
   The recorded successful deployment above is the baseline; do not select the
   empty sentinelops-demo service. Redeployment/rollback changes production and
   requires approval unless explicitly included in the approved rollback plan.
4. Verify HTTPS, /health, dashboard/assets and scenarios through the restored
   public entry point. Check DNS propagation where applicable and record elapsed
   recovery time. Proposed recovery target: 15 minutes plus outstanding DNS TTL;
   this is a planning target, not a measured guarantee.
5. Keep both platforms available during investigation. Record failure, action,
   operator, timestamps and recovery evidence. Obtain approval before retrying
   cutover or retiring infrastructure.

## Validation limitations for this readiness revision
Documentation/configuration inspection only. Local clone failed because the
host Git HTTPS credential layer was unavailable. Native build/test scripts,
Docker smoke tests, live health, DigitalOcean validator and rollback drill
were not executed successfully. These remain release gates, not waived checks.
