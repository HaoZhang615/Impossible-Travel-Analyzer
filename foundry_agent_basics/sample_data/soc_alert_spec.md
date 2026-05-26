# SOC Alert Triage — Reference Specification

## Overview
This document describes the standard alert types, severity levels, and triage
procedures used by the Security Operations Center (SOC) when handling
Microsoft Sentinel detections in an Azure/Entra ID environment.

## Alert Types

| Alert Type                    | Severity | MITRE ATT&CK Tactic         | Description |
|-------------------------------|----------|------------------------------|-------------|
| Impossible Travel             | High     | Initial Access (T1078)       | Sign-ins from geographically distant locations within an infeasible timeframe |
| Brute Force / Password Spray  | Medium   | Credential Access (T1110)    | Multiple failed sign-in attempts followed by a success from the same IP |
| MFA Fatigue Attack            | High     | Credential Access (T1621)    | Rapid sequence of MFA push notifications indicating an attacker bombing the user |
| OAuth Consent Phishing        | High     | Credential Access (T1528)    | User grants excessive permissions to a suspicious third-party application |
| Suspicious Inbox Rule         | Medium   | Collection (T1114)           | Mailbox rule created to forward or delete emails matching financial keywords |
| Disabled Account Sign-In      | Critical | Persistence (T1078)          | Successful authentication on an account that should be disabled |
| Token Replay                  | High     | Credential Access (T1528)    | A refresh token is used from a different IP/device than the original session |
| Risky Sign-In (Entra ID P2)   | Medium   | Initial Access (T1078)       | Entra ID Identity Protection flags a sign-in as risky based on multiple signals |

## Severity Levels

| Level    | SLA (Acknowledge) | SLA (Resolve) | Escalation Path |
|----------|--------------------|---------------|-----------------|
| Critical | 5 min              | 30 min        | Immediate page to L3 + CISO |
| High     | 15 min             | 2 hours       | L2 analyst, escalate to L3 if unresolved |
| Medium   | 1 hour             | 8 hours       | L1 triage, pass to L2 if confirmed |
| Low      | 4 hours            | 24 hours      | L1 triage, document and close if benign |

## Key Data Sources

| Source                        | Platform            | Data |
|-------------------------------|---------------------|------|
| Sign-in Logs                  | Entra ID            | Interactive & non-interactive sign-in events |
| Audit Logs                    | Entra ID            | Directory changes — MFA resets, role assignments, app consent |
| Unified Audit Log             | Microsoft 365       | Mailbox rules, file access, SharePoint activity |
| Security Alerts               | Microsoft Sentinel  | Correlated detections from analytics rules |
| IP Reputation                 | Threat Intelligence | ISP, geolocation, Tor/VPN/proxy flags |
| Identity Protection           | Entra ID P2         | Risk state, risk level, risk detections |

## Triage Decision Framework

SOC analysts use the **PACO** framework for final verdicts:

| Verdict              | Meaning |
|----------------------|---------|
| **AccountCompromised** | Strong evidence of unauthorized access — remediate immediately |
| **LikelyCompromised** | Probable compromise with some ambiguity — remediate and investigate |
| **Suspicious**        | Anomalous activity that warrants monitoring — do not remediate yet |
| **BenignAnomaly**     | Explainable by legitimate business activity — close alert |
| **InsufficientData**  | Not enough signal to make a determination — gather more data |

## Risk Factors Evaluated

1. **Location Anomaly** — distance/velocity between sign-in locations
2. **Authentication Anomaly** — unusual auth methods, missing MFA
3. **Token Anomaly** — token reuse from mismatched IP/device
4. **Brute Force Pattern** — failed sign-in clusters before success
5. **MFA Abuse** — fatigue attacks or MFA method changes
6. **Post-Login Activity** — sensitive operations after suspicious sign-in
7. **OAuth Abuse** — consent grants with excessive permissions
8. **Mailbox Manipulation** — forwarding rules targeting financial content
9. **High Privilege User** — Global Admin, Exchange Admin, etc.
10. **Disabled Account Sign-In** — sign-in on a disabled account

## Pricing / Licensing

| Item                                  | List Price (USD/user/mo) |
|---------------------------------------|--------------------------|
| Microsoft Sentinel (Pay-as-you-go)    | ~$2.46 per GB ingested   |
| Entra ID P2 (Identity Protection)     | $9.00                    |
| Microsoft 365 E5 Security             | $14.00                   |
| Microsoft Defender for Cloud Apps     | $3.50                    |
| Microsoft Defender for Identity       | $5.50                    |
