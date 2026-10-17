# SentinelOps AI — public read-only demonstration

**Scope:** This container serves **synthetic fixtures only**, without credentials, external AI, production telemetry, or user-supplied event ingestion. The existing local `POST /api/v3/analyze` remains available only when developers run `app.py` locally. Public Docker deployment uses `public_demo:application` and responds to POST with 405.

## Railway (Docker-based)

1. Connect the Railway app in ChatGPT or sign in to [Railway](https://railway.com/), then connect the GitHub repository `Fatherjay1-bleu/project-omega-central`.
2. **Deploy this branch** (`feature/hackathon-public-demo`) until it has passed CI and has been merged; thereafter deploy `main`. Select a **Dockerfile** deployment, not Nixpacks.
3. No API keys, database, external services, or secrets are needed. The container uses `PORT` from the hosting platform, defaulting to 8080.
4. Generate a public HTTPS domain in the hosting dashboard. Wait for a healthy deployment; do **not** use the GitHub URL or a localhost URL as the submission demo link.
5. From a different device or browser, confirm `https://<your-domain>/`, `/demo`, and each `/demo/scenario/1`, `/2`, `/3` work.
6. Verify `POST /api/v3/analyze` returns HTTP **405** on the public domain.
7. Keep the deployment active during judging. If the provider offers idle/sleep behavior, check the URL immediately before submitting.

### Container verification (where Docker is available)

```powershell
docker build -t sentinelops-demo .
docker run --rm -p 8080:8080 sentinelops-demo
```

In a second terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/demo
Invoke-RestMethod http://127.0.0.1:8080/demo/scenario/3
```

### Security and limitations

This is a hackathon demonstration, **not a production security service**. No authentication or rate limiting is provided, so it deliberately only accepts read-only public requests and never analyzes arbitrary public input. The C validator and C++ scorer are built in the container and executed in subprocesses. Public HTTP is served by Gunicorn behind the hosting provider's HTTPS edge; do not publicly expose Flask's development server. No synthetic fixture includes real personal data. Use repository CI plus off-device HTTPS checks for deployment acceptance.

### Submission URLs

- Repo: https://github.com/Fatherjay1-bleu/project-omega-central
- Public demo: **enter the URL only after hosting has generated and verified it**.
- Video: **enter the published YouTube URL only after upload**.
