# SOC Runbook

## Alert ownership and SLA

1. Assign every High or Critical alert to an Operator.
2. Move it to `acknowledged` or `investigating` before its SLA deadline.
3. Record the decision and evidence in the resolution note.
4. Use `resolved` or `false_positive` only with a meaningful resolution note.
5. Review `/api/operations/history` for the immutable workflow trail.

## Notification channel check

1. Confirm channel enabled state through `/api/notifications/status` as Admin.
2. Send a synthetic test through `/api/notifications/test`.
3. If delivery fails, check outbound HTTPS/DNS access without printing the URL.
4. Rotate the webhook if it may have been exposed.
5. Keep raw-target delivery disabled unless the receiving system is approved for
   that data.

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
