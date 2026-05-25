# SOC Impossible-Travel Investigation — Workflow Overview

This skill drives a 5-phase investigation against a Microsoft Sentinel Impossible-Travel
detection. The agent owns the full pipeline that the multi-agent design splits across
10 specialist agents + an aggregator + a PACO orchestrator.

## Phases

1. **Parse** the `NormalizedDetection` payload from the user message — extract
   `PrimaryEntityId` (UPN), `IoC_IPs`, `IoC_Locations`, `Severity`, `DetectionTime`.
2. **Enrich** — call `get_user_context(upn)`. This returns Entra ID + AD profile
   including the `Risk_HighPrivilegeUser` and `Risk_DisabledAccountSignIn` flags.
3. **Evaluate the 10 risk factors** — for **every** factor below, call the matching
   tool, consult the matching reference doc, and produce a `RiskEvidence` record.

   | # | Risk factor                       | Tool                                | Reference                          |
   |---|-----------------------------------|-------------------------------------|------------------------------------|
   | 1 | LocationAnomaly                   | `evaluate_location_anomaly`         | `01_location_anomaly.md`           |
   | 2 | AuthenticationAnomaly             | `evaluate_authentication_anomaly`   | `02_authentication_anomaly.md`     |
   | 3 | TokenAnomaly                      | `evaluate_token_anomaly`            | `03_token_anomaly.md`              |
   | 4 | BruteForcePattern                 | `evaluate_brute_force_pattern`      | `04_brute_force_pattern.md`        |
   | 5 | MfaAbuse                          | `evaluate_mfa_abuse`                | `05_mfa_abuse.md`                  |
   | 6 | PostLoginSuspiciousActivity       | `evaluate_post_login_activity`      | `06_post_login_activity.md`        |
   | 7 | OAuthAbuse                        | `evaluate_oauth_abuse`              | `07_oauth_abuse.md`                |
   | 8 | MailboxManipulation               | `evaluate_mailbox_manipulation`     | `08_mailbox_manipulation.md`       |
   | 9 | HighPrivilegeUser                 | `evaluate_high_privilege_user`      | `09_high_privilege_user.md`        |
   |10 | DisabledAccountSignIn             | `evaluate_disabled_account_signin`  | `10_disabled_account_signin.md`    |

4. **Score** — apply `scoring_rubric.md` to every `RiskEvidence` (0–100 scale,
   low/medium/high bands) and assemble the `ThreatDecisionRecord`.
5. **Decide (PACO)** — per `paco_decision_template.md`, emit a final
   `InvestigationVerdict` with `verdict`, `confidence`, `reasoning`, `actionPlan`,
   `narrative`.

## Tool-calling rules

- Pass `IoC_IPs` to tools that accept `ioc_ips` as a **JSON-array string**,
  e.g. `'["203.0.113.42","198.51.100.7"]'`.
- For Phase 1 distance/velocity calculation **always** use `scripts/haversine.py`
  and `scripts/travel_velocity.py` (deterministic). Do not estimate in your head.
- For IP reputation, the tool already enriches via the bundled feed. The
  `scripts/ip_reputation_lookup.py` helper is only for ad-hoc spot checks.

## Critical correlation patterns

- Impossible travel + malicious IP + brute force → **strong** compromise indicator.
- MFA bypass + MFA method change → attacker persistence.
- Post-login activity + mailbox forwarding rules → active data exfiltration.
- OAuth consent + ReadWrite permissions → application-based persistence.
- `Risk_HighPrivilegeUser = true` **amplifies** severity of every other risk; mark
  destructive actions with `requiresApproval: true`.
- Successful sign-in on a disabled account is a stand-alone strong compromise
  indicator even if travel is plausible.
