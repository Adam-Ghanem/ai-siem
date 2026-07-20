# AI-SIEM Agents

These agents make the project work with **real logs** instead of only bundled sample data.

## Linux log agent

The Linux agent tails local log files and sends new lines to the backend `/api/ingest` endpoint with the configured Bearer token.

Start the backend first:

```bash
export AI_SIEM_OPERATOR_KEY='operator-token'
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Keep the key in the environment rather than a command-line argument:

```bash
export AI_SIEM_AGENT_KEY='operator-token'
```

The agent checks `AI_SIEM_AGENT_KEY` first, then the Operator and legacy keys.
Use an Operator credential for ingestion instead of giving a collector Admin
access.

Run the agent against real Linux authentication logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/auth.log \
  --api http://localhost:8000
```

On Fedora/RHEL/Kali-like systems, the authentication log may be:

```bash
python agents/linux_log_agent.py \
  --file /var/log/secure \
  --api http://localhost:8000
```

For web logs:

```bash
python agents/linux_log_agent.py \
  --file /var/log/nginx/access.log \
  --file /var/log/apache2/access.log \
  --api http://localhost:8000
```

Use `--from-start` in a lab if you want to ingest existing content from the beginning of the file. Without it, the agent starts from the current end of each file and only sends new lines.

The agent stores offsets atomically in `.agent_state/linux_offsets.json`. It
commits an offset only after the backend accepts the batch, so temporary
delivery failures are retried instead of silently losing lines. Remote API
connections require HTTPS, redirects are refused, and response bodies are
bounded.

## Lab example

In one terminal, keep the backend running. In another, run the agent. Then generate real logs by doing normal admin activity on your own machine, such as SSH login attempts, sudo usage, or web requests to a local Nginx/Apache server. New parsed events should appear in the dashboard after refresh.
