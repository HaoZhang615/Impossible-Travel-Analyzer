# 06 — PostLoginSuspiciousActivity

**Tool:** `evaluate_post_login_activity(upn, ioc_ips)`

## What we evaluate

- **Security alerts** raised on the UPN (Defender XDR, Sentinel).
- **Suspicious app access** from the IoC IPs (Graph bulk reads, Exchange
  PowerShell, eDiscovery, mailbox exports).
- **Privilege changes** in the audit log (`UserManagement` category — role
  assignments, group additions).
- **Lateral movement** indicators (sign-ins to internal apps from external IPs).

## Scoring guidance

| Pattern                                                                  | Band     |
|--------------------------------------------------------------------------|----------|
| No alerts and no IoC-IP app access                                       | 0–10     |
| Single low-severity alert, no privilege changes                          | 11–30    |
| Multiple alerts OR app access from IoC IP                                | 50–70    |
| Privilege escalation AND data-access alerts from IoC IP                  | 85–100   |

`Type`: `data_exfiltration`, `privilege_escalation`, `lateral_movement`, `none`.
