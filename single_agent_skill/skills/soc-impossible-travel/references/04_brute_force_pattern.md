# 04 — BruteForcePattern

**Tool:** `evaluate_brute_force_pattern(upn, ioc_ips)`

## What we evaluate

- **Failed sign-in volume** within the detection window.
- **Rapid succession** — 3+ failures clustered within minutes (default threshold).
- **Source clustering** on the IoC IPs vs. spray across many UPNs.
- **`followed_by_success`** — a successful sign-in from the same IoC IP after the
  failed burst is the strongest indicator.

## Scoring guidance

| Pattern                                                                                | Band     |
|----------------------------------------------------------------------------------------|----------|
| 0 failed sign-ins                                                                      | 0        |
| <3 failures and no success on IoC IP                                                   | 1–20     |
| 3+ failures in a short window from a non-IoC IP                                        | 30–50    |
| 3+ failures **OR** password-spray pattern from IoC IP, no subsequent success           | 50–70    |
| Failed burst **followed_by_success** from the same IoC IP                              | 85–100   |

`Type`: `brute_force`, `password_spray`, `none`.
