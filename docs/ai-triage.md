# AI-SIEM: OpenAI advisory triage (opt-in preview)

This is a **bounded, analyst-initiated feature**, not enterprise-scale AI
orchestration. Core log collection, detection, storage and alerting never depend
on an LLM provider, and there is no automatic network or host containment.

## Configuration

Set all of the following **server-side**, using your runtime secret manager:

```bash
export AI_SIEM_AI_ENABLED=true
export AI_SIEM_AI_EXTERNAL_OPT_IN=true
export AI_SIEM_AI_PROVIDER=openai
export AI_SIEM_AI_MODEL='<supported-model-from-your-OpenAI-account>'
export OPENAI_API_KEY='<secret>'
export AI_SIEM_AI_MAX_REQUESTS_PER_MINUTE=3
```

For Docker, **do not put the API key in Compose YAML or source control**.
The opt-in `docker-compose.ai.yml` overlay mounts a secret file instead of
passing the key through a container environment variable:

```bash
# Create a secret file outside the repo using a safe interactive editor
# then restrict access (example path; never commit its contents).
chmod 600 /path/to/private/openai-key
export AI_SIEM_AI_LOCAL_SECRET_FILE=/path/to/private/openai-key
export AI_SIEM_AI_MODEL='<supported-model-from-your-account>'
export AI_SIEM_API_KEY='<your-backend-auth-secret>'
docker compose -f docker-compose.yml -f docker-compose.ai.yml up --build
```

The overlay sets `AI_SIEM_AI_API_KEY_FILE=/run/secrets/openai_api_key`,
which takes precedence over the environment key. The base Compose file
continues to work with AI disabled.

The endpoint is `POST /api/ai/alerts/{alert_id}/analyze`. It requires a
bearer identity with analyst/admin role. It does not accept a user prompt,
model override or API key from the HTTP request body. API key is never included
in the response, audit record, or documentation example.

External transfer is disabled by default and requires the opt-in flag.
The request uses the OpenAI Responses API, `store: false`, a structured
JSON schema and bounded output tokens. **store:false does not in itself
guarantee zero retention across all provider services**; review applicable
provider data controls, contracts and regional processing requirements.

## Information sent off-premises

**Only** alert ID, rule ID, rule title, severity, tactic/technique, number of
related events and a maximum of 12 linked event metadata records:
event ID, timestamp, source, event type, outcome. **Not sent**: raw logs,
command lines, hostname, usernames, IP addresses, process attributes, notes,
attachments, threat-intelligence payloads or arbitrary analyst prompts.
Metadata may still be sensitive; only opt in when permitted by policy.

The gateway validates schema, limits and citations; fabricated event IDs
cause rejection. AI results are advisory-only, not a suppression rule or
an automated response action. Upstream outages produce an error, not a
change to SIEM detection status. This first version returns results to the
caller but does not persist AI job histories.

## Production gaps

- Replace per-process AI call guard with centralized tenant-aware quotas,
  spend caps, distributed queues, accounting, and concurrency controls.
- Integrate a real secret manager and per-tenant BYOK with credential rotation.
- Add durable analysis jobs, cancellation, model/prompt version tracking,
  evaluation datasets, analyst dispositions and replay.
- Extend to other AI providers behind explicit provider adapters with data
  residency, consent, and no implicit cross-provider fallback.
- Independently evaluate privacy, prompt injection, provider terms and
  cost policies before live customer telemetry is enabled.
