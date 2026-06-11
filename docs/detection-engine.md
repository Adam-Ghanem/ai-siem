# Detection Engine

The detection engine maps log messages to detection rules.

## Current Detection Logic

- Failed SSH / brute force -> T1110 Credential Access
- Encoded PowerShell -> T1059.001 Execution
- Port scan -> T1046 Discovery
- Admin account creation -> T1136 Persistence
- SQL injection attempt -> T1190 Initial Access

## Output Alert Fields

- ID
- Title
- Severity
- Confidence
- Source
- Asset
- MITRE tactic
- MITRE technique
- Status
- Recommendation

## Future Improvements

- Sigma rule parser
- Time-window correlation
- False positive suppression
- Risk-based alert prioritization
- Asset criticality scoring
