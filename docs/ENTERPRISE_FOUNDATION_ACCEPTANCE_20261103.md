# Enterprise foundation — isolated pilot acceptance plan

Status: design and test-first planning only; not production-ready. This branch must not change the public hackathon demo or enable customer ingestion.

## Trust boundaries
- **Public demo:** synthetic fixtures only, read-only, no customer identity, no telemetry ingestion, no production secrets. Existing POST rejection is a regression requirement.
- **Enterprise staging:** separate environment, credentials, datastore, domain, deploy pipeline, and access policies. No connection to the public demo datastore.
- **Tenant identity:** OIDC with issuer, audience, signature, expiration and nonce validation; server-side organization membership and deny-by-default RBAC. Never trust tenant IDs or roles from user-controlled request fields.
- **Ingestion:** only authenticated, scoped connectors; explicit tenant binding, schema/size/rate limits, replay protection, bounded queues and quarantine of malformed events.
- **Data:** tenant isolation at every query/write boundary, encryption in transit and at rest, deletion/retention policy, redact secrets and personal data from logs.
- **Operations:** least-privilege secrets, audit events, backup/restore drills, security alerts, SLOs and rollback procedure. No automatic containment.

## Test-first acceptance checklist (all pending)
- [ ] Public demo GET routes remain synthetic and POST /api/v3/analyze returns 405; no change to the existing demo deployment.
- [ ] Unauthenticated and malformed OIDC requests deny; wrong issuer/audience, expired/replayed tokens deny.
- [ ] Tenant A cannot read/write Tenant B records even with forged tenant_id, object IDs or changed role claims.
- [ ] Roles default deny; privileged actions require explicit server-side grants and audit entries.
- [ ] Ingestion rejects oversized, malformed, duplicate, out-of-scope and over-rate events without leaking data.
- [ ] Cross-tenant logs, exports, errors, cache keys and correlation output do not leak data.
- [ ] Secrets scanning, dependency audit and Python/C/C++ regression run on a private staging branch.
- [ ] Staging deploy passes health, failure injection, backup/restore and rollback tests.
- [ ] Independent security review signs off before any customer data or production activation.

## Delivery order
1. Preserve and baseline the public demo; capture actual CI and Railway evidence.
2. Define tenant, principal, role and event schemas plus threat model; add failing isolation tests.
3. Implement identity and authorization adapters behind a disabled-by-default enterprise feature flag.
4. Implement tenant-scoped storage and authenticated ingestion in an isolated staging environment.
5. Complete security, resilience, privacy and operations acceptance evidence.

## Explicit non-goals for this branch
No live customer data, no public POST enablement, no new cloud spending, no production deployment, no secret provisioning, and no claim of compliance certification. Require separate approval before any of these actions.
