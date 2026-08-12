# AI-SIEM Deployment Runbook

## Deployment posture

The repository includes a Docker image, a Render Blueprint, and a Fly.io manifest. These files are deployment templates; they do not perform an external deployment and do not contain credentials. A live URL must be reported only after the platform has been configured and the health endpoint has been verified.

Production-like deployments should use `AI_SIEM_AUTH_MODE=jwt`, a randomly generated `AI_SIEM_JWT_SECRET`, explicit `AI_SIEM_JWT_ISSUER`, explicit `AI_SIEM_JWT_AUDIENCE`, and a restrictive `AI_SIEM_ALLOWED_ORIGIN`. Provider credentials must be entered as platform-managed secrets named `ABUSEIPDB_API_KEY` and `OTX_API_KEY`; they must never be committed to Git.

## Local container verification

Build and run the container with a development-only token:

```bash
docker build --pull -t ai-siem:local .
docker run --rm --name ai-siem-local -p 8000:8000 \
  -e AI_SIEM_AUTH_MODE=legacy \
  -e AI_SIEM_API_KEY=local-only-token \
  -e AI_SIEM_ALLOWED_ORIGIN=http://localhost:5173 \
  ai-siem:local
```

The readiness check is `GET /api/health`. All authenticated routes still require a bearer token. Do not use the development legacy mode or a development token in an internet-facing service.

## Render

Create a Render service from `render.yaml`, provide `AI_SIEM_ALLOWED_ORIGIN`, and add provider keys only when enrichment is required. The blueprint generates a JWT secret and mounts a persistent disk for SQLite. Set `autoDeploy` to true only after the repository branch protection and CI checks are in place. After deployment, verify `/api/health`, inspect the service logs for startup errors, and perform an authenticated `/api/me` request using a short-lived JWT issued by the organization's identity system.

## Fly.io

Create the application and volume using the Fly CLI, then set secrets through the platform rather than the manifest:

```bash
fly launch --no-deploy --copy-config
fly volumes create ai_siem_data --size 1 --region iad
fly secrets set AI_SIEM_JWT_SECRET='REPLACE_WITH_RANDOM_SECRET' AI_SIEM_ALLOWED_ORIGIN='https://soc.example.com'
fly deploy
```

The manifest uses HTTPS, an internal port of 8000, and a health check. Set `min_machines_running` according to the required availability objective and database design. SQLite on a single mounted volume is appropriate for a demo or single-writer deployment; a multi-region production SOC should select PostgreSQL and/or OpenSearch with backups and tested failover.

## Rollback and evidence

Before promoting a release, record the image digest, Git commit, migration state, environment variable names, and health-check result. Roll back to the previous image or platform release if readiness fails, authentication is misconfigured, or tenant-scoped reads do not match the expected tenant. Do not roll back by copying secrets into a shell history or repository file.
