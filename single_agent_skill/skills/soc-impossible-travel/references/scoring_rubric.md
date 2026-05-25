# Scoring Rubric & ThreatDecisionRecord assembly

## Per-factor EvidenceScore bands (0–100)

| Band   | Meaning   | Examples                                                       |
|--------|-----------|----------------------------------------------------------------|
| 0      | None      | Tool returned no signal at all.                                |
| 1–30   | Low       | Single weak indicator, plausible benign explanation.           |
| 31–60  | Medium    | Multiple indicators, no smoking gun.                           |
| 61–80  | High      | Strong signal, corroborated by at least one other data source. |
| 81–100 | Critical  | Unambiguous compromise indicator (e.g., signin after disable). |

## Risk weights (used by PACO for aggregation)

```json
{
  "LocationAnomaly":              15,
  "AuthenticationAnomaly":        15,
  "TokenAnomaly":                 20,
  "BruteForcePattern":            10,
  "MfaAbuse":                     20,
  "PostLoginSuspiciousActivity":  15,
  "OAuthAbuse":                   10,
  "MailboxManipulation":          10,
  "HighPrivilegeUser":            10,
  "DisabledAccountSignIn":         5
}
```

## ThreatDecisionRecord (intermediate object)

After scoring all 10 factors, assemble:

```json
{
  "Detection":  { /* NormalizedDetection */ },
  "Context":    { /* output of get_user_context */ },
  "RiskEvidenceItems": [
    {"RiskFactor": "LocationAnomaly", "Type": "geo_anomaly",
     "Value": "Seattle→Lagos in 17 min (~31000 km/h)",
     "Reason": "Impossible travel velocity with Malicious IoC IP 198.51.100.7.",
     "EvidenceScore": 95},
    // ... 9 more entries, one per risk factor
  ],
  "RiskFactors": {
    "LocationAnomaly": true,
    "AuthenticationAnomaly": true,
    // ... boolean for every factor (true if score > 0)
  }
}
```

Always emit a `RiskEvidence` for every factor — use `EvidenceScore: 0` when the
tool returned no signal. This keeps the verdict reasoning auditable.

## Decision thresholds (input to PACO)

- **AccountCompromised** — any single factor at 85+, OR ≥3 factors at 50+, OR a
  `DisabledAccountSignIn` score ≥90.
- **BenignAnomaly** — no factor above 30, evidence consistent with normal user
  behaviour (e.g., business travel + clean IPs + full MFA).
- **Inconclusive** — somewhere in the middle, missing critical data.

## Confidence

- **High** — multiple corroborating high-score factors **or** a single 90+ score
  with corroborating context.
- **Medium** — one or two mid-band factors with plausible alternative
  explanations.
- **Low** — sparse data, conflicting signals.
