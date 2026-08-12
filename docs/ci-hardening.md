# CI Hardening Handoff

The intended CI additions are present in the local working diff but could not be pushed by the current GitHub token because GitHub rejected updates to `.github/workflows/ci.yml` without the `workflows` permission. A maintainer with that permission should apply the following checks to the workflow:

```yaml
- name: Check frontend JavaScript syntax
  run: node --check frontend/app.js

- name: Check patch whitespace
  run: git diff --check

- name: Build production container
  run: docker build --pull --tag ai-siem:ci .

- name: Container health smoke test
  shell: bash
  run: |
    set -euo pipefail
    docker run --detach --name ai-siem-ci --publish 18000:8000 \
      --env AI_SIEM_AUTH_MODE=legacy \
      --env AI_SIEM_API_KEY=ci-only-token \
      --env AI_SIEM_ALLOWED_ORIGIN=http://localhost:5173 \
      ai-siem:ci
    trap 'docker logs ai-siem-ci || true; docker rm --force ai-siem-ci || true' EXIT
    for attempt in {1..20}; do
      if curl --fail --silent http://127.0.0.1:18000/api/health; then
        exit 0
      fi
      sleep 1
    done
    exit 1
```

The workflow must continue to run the complete unit suite, Bandit, `pip-audit`, and Python compilation. The local sandbox could not execute `docker build` because no Docker daemon is installed; the workflow is the authoritative environment for this check.
