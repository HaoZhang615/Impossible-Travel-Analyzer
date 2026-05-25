# 01 — LocationAnomaly

**Tool:** `evaluate_location_anomaly(upn, ioc_ips)`

## What we evaluate

- **Impossible travel velocity** between successful sign-ins (distance / Δtime).
- **IP reputation** of every IoC IP and every sign-in IP (Malicious, Suspicious,
  Clean, Unknown).
- **VPN / proxy / Tor exit** indicators on the source IPs.
- **Geographic clustering** vs. the user's `Country` from `get_user_context`.

## Deterministic helpers (use them)

For any two successful sign-ins from different geo coordinates:

1. Call `scripts/haversine.py --lat1 <lat> --lon1 <lon> --lat2 <lat> --lon2 <lon>`
   → `{"km": <distance>}`.
2. Compute Δseconds between the two `Timestamp` values.
3. Call `scripts/travel_velocity.py --km <km> --seconds <delta>` →
   `{"km_per_hour": <v>, "impossible": <bool>}`. `impossible` is true when
   sustained velocity exceeds **900 km/h** (typical commercial jet ceiling).

If you do not have coordinates in the sign-in record, estimate from the
`Location` string using common-knowledge city coordinates (Seattle ≈ 47.61,-122.33;
Lagos ≈ 6.52, 3.38; London ≈ 51.51, -0.13; Frankfurt ≈ 50.11, 8.68; Amsterdam ≈
52.37, 4.90; Bucharest ≈ 44.43, 26.10; New York ≈ 40.71, -74.01).

## Scoring guidance

| Signal pattern                                                                   | EvidenceScore band |
|----------------------------------------------------------------------------------|--------------------|
| No anomalies; coherent travel; all IPs Clean                                     | 0–10               |
| Plausible travel with one Unknown IP                                             | 11–30              |
| `impossible: true` OR one Malicious IoC IP                                       | 50–70              |
| `impossible: true` AND Malicious IP (or VPN+Malicious combo)                     | 80–100             |

Set `Type` to one of `geo_anomaly`, `clean_travel`, `vpn_only`, `malicious_ip`.
Put the velocity (km/h) and the two cities in `Value`. Explain the verdict in
`Reason` in <=2 sentences.
