# SOC Runbook

## SSH Brute Force

1. Validate source IP and target asset.
2. Check if any login succeeded after repeated failures.
3. Block malicious source IP.
4. Enforce MFA and rotate exposed credentials.
5. Document the incident.

## Suspicious PowerShell

1. Isolate the endpoint if execution is suspicious.
2. Collect process tree and command-line evidence.
3. Review persistence locations.
4. Hunt for the same command across other hosts.
5. Start remediation.

## Admin Account Created

1. Validate change request.
2. Disable account if unauthorized.
3. Audit privileged group membership.
4. Review creator account activity.
5. Reset credentials if compromise is suspected.
