# Test Cases

Each JSON file in this folder represents an **Impossible Travel** investigation scenario
the workflow can be exercised against. The notebook (`01-investigation.ipynb`) discovers
the files at runtime and lets you switch between cases via a single variable.

## File schema

```jsonc
{
  "name": "Human-readable scenario name",
  "description": "What this scenario tests / why it's interesting",
  "expected_verdict": "AccountCompromised | BenignAnomaly | Inconclusive",
  "expected_confidence": "High | Medium | Low",

  // The Sentinel-style detection that triggers the investigation
  "detection": {
    "ThreatScenario": "AccountCompromise",
    "PrimaryEntityType": "User",
    "PrimaryEntityId": "<UPN>",
    "IoC_IPs": ["..."],
    "IoC_Locations": ["..."],
    "IoC_Devices": ["..."],
    "IoC_Applications": ["..."],
    "IoC_Domains": ["..."],
    "DetectionTime": "ISO-8601",
    "Severity": "Low | Medium | High"
  },

  // Mock data sources the 10 @tool functions query.
  // In production these are replaced by Sentinel / Entra / Defender MCP calls.
  "data_sources": {
    "signin_logs":             [ /* interactive sign-ins */ ],
    "noninteractive_signin_logs": [ /* service / token sign-ins */ ],
    "failed_signins":          [ /* failed auth attempts */ ],
    "audit_logs":              [ /* Entra ID / Exchange admin audit events */ ],
    "security_alerts":         [ /* Defender / Sentinel alerts */ ],
    "mailbox_rules":           [ /* Exchange inbox rules */ ],
    "ip_reputation":           { "<ip>": { ... } },
    "entra_user":              { /* Entra ID profile */ },
    "ad_user_context":         { /* on-prem AD profile */ }
  }
}
```

## Bundled scenarios

| # | File | Scenario | Expected verdict |
|---|------|----------|------------------|
| 1 | `01_clear_compromise.json`      | Impossible travel + malicious IP + brute force + MFA tamper + OAuth consent + mailbox forwarding on a high-privilege user. | AccountCompromised (High) |
| 2 | `02_benign_business_travel.json`| NYC → London over 8 hours, clean IPs, full MFA, no anomalies. | BenignAnomaly (High) |
| 3 | `03_mfa_fatigue_attack.json`    | Password spray followed by MFA push bombing, eventual approval, MFA method swapped. | AccountCompromised (Medium-High) |
| 4 | `04_oauth_consent_phishing.json`| Phished password + malicious OAuth consent; attacker signs in from Frankfurt 8 min after the Seattle session → impossible travel + persistent OAuth backdoor. | AccountCompromised (High) |
| 5 | `05_disabled_account_signin.json`| Terminated employee's cached refresh tokens are replayed from Amsterdam and Bucharest 7 min apart — successful Graph + Exchange calls trigger impossible travel against a disabled account. | AccountCompromised (High) |

## Adding your own scenario

1. Copy any existing JSON file and rename it (a numeric prefix keeps the list ordered).
2. Replace `detection` with your IoCs and the affected UPN.
3. Populate `data_sources` so every record's `UPN` matches `detection.PrimaryEntityId`.
4. The mock data only needs to be _internally consistent_ — the 10 risk-evaluation agents will read whatever you provide.
5. In the notebook, set `TEST_CASE = "<your-filename-without-.json>"` and re-run the data + run cells.

## Tips

- To force a low-evidence run, leave most `data_sources` arrays empty — agents will return `EvidenceScore: 0` for those factors.
- To test the privileged-user gate, give `entra_user.Roles` an entry like `"Global Administrator"` or `"Exchange Administrator"` — PACO will then mark destructive actions with `requiresApproval: true`.
- IP reputation is a dictionary keyed by the IP string; missing entries are treated as `Reputation: "Unknown"`.
