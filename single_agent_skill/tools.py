"""Data-source @tool functions for the single-agent Impossible Travel investigator.

Identical mock data backing as the multi-agent workflow on `main` — each tool
returns the same JSON shape, so the single agent (driven by the
`soc-impossible-travel` skill) can gather evidence with parity to the 10
sub-agents in the multi-agent design.

In production, every `_get_*` lookup would be replaced by a Sentinel / Entra /
Defender MCP call. For the workshop they read from `test_cases/*.json` hydrated
via :func:`load_test_case` or :func:`load_test_cases_dir`.
"""
from __future__ import annotations

import json
from pathlib import Path

from agent_framework import tool

# ─────────────────────────────────────────────────────────────
# In-memory data sources — populated by load_test_case[s_dir]
# ─────────────────────────────────────────────────────────────

SIGNIN_LOGS_BY_UPN: dict[str, list[dict]] = {}
NONINT_SIGNIN_LOGS_BY_UPN: dict[str, list[dict]] = {}
FAILED_SIGNINS_BY_UPN: dict[str, list[dict]] = {}
AUDIT_LOGS_BY_UPN: dict[str, list[dict]] = {}
SECURITY_ALERTS_BY_UPN: dict[str, list[dict]] = {}
MAILBOX_RULES_BY_UPN: dict[str, list[dict]] = {}
IP_REPUTATION: dict[str, dict] = {}
ENTRA_USERS: dict[str, dict] = {}
AD_USERS: dict[str, dict] = {}

HIGH_PRIV_ROLES = {
    "Global Administrator",
    "Exchange Administrator",
    "Security Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Global Reader",
}
HIGH_PRIV_GROUPS = {"Executive-Access", "Domain Admins", "Enterprise Admins"}


def reset_data_sources() -> None:
    SIGNIN_LOGS_BY_UPN.clear()
    NONINT_SIGNIN_LOGS_BY_UPN.clear()
    FAILED_SIGNINS_BY_UPN.clear()
    AUDIT_LOGS_BY_UPN.clear()
    SECURITY_ALERTS_BY_UPN.clear()
    MAILBOX_RULES_BY_UPN.clear()
    IP_REPUTATION.clear()
    ENTRA_USERS.clear()
    AD_USERS.clear()


def _ingest_case(case: dict) -> None:
    ds = case.get("data_sources", {})
    for row in ds.get("signin_logs", []):
        SIGNIN_LOGS_BY_UPN.setdefault(row.get("UPN", ""), []).append(row)
    for row in ds.get("noninteractive_signin_logs", []):
        NONINT_SIGNIN_LOGS_BY_UPN.setdefault(row.get("UPN", ""), []).append(row)
    for row in ds.get("failed_signins", []):
        FAILED_SIGNINS_BY_UPN.setdefault(row.get("UPN", ""), []).append(row)
    for row in ds.get("audit_logs", []):
        AUDIT_LOGS_BY_UPN.setdefault(row.get("UPN", ""), []).append(row)
    for row in ds.get("security_alerts", []):
        SECURITY_ALERTS_BY_UPN.setdefault(row.get("UPN", ""), []).append(row)
    for row in ds.get("mailbox_rules", []):
        MAILBOX_RULES_BY_UPN.setdefault(row.get("UPN", ""), []).append(row)
    IP_REPUTATION.update(ds.get("ip_reputation", {}))
    entra = ds.get("entra_user", {})
    if entra.get("UPN"):
        ENTRA_USERS[entra["UPN"]] = entra
    ad = ds.get("ad_user_context", {})
    if ad.get("UPN"):
        AD_USERS[ad["UPN"]] = ad


def load_test_case(path: str | Path) -> dict:
    """Load a single test-case JSON, replacing any previously-loaded data."""
    reset_data_sources()
    with open(path, encoding="utf-8") as f:
        case = json.load(f)
    _ingest_case(case)
    return case


def load_test_cases_dir(directory: str | Path) -> int:
    """Load all ``*.json`` test cases from a directory (additive)."""
    n = 0
    for path in sorted(Path(directory).glob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                case = json.load(f)
            _ingest_case(case)
            n += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[load_test_cases_dir] Failed to load {path.name}: {exc}")
    return n


# ─────────────────────────────────────────────────────────────
# Internal accessors
# ─────────────────────────────────────────────────────────────

def _get_signin_logs(upn: str) -> list[dict]:
    return SIGNIN_LOGS_BY_UPN.get(upn, [])


def _get_noninteractive_signin_logs(upn: str) -> list[dict]:
    return NONINT_SIGNIN_LOGS_BY_UPN.get(upn, [])


def _get_failed_signins(upn: str) -> list[dict]:
    return FAILED_SIGNINS_BY_UPN.get(upn, [])


def _get_audit_logs(upn: str) -> list[dict]:
    return AUDIT_LOGS_BY_UPN.get(upn, [])


def _get_security_alerts(upn: str) -> list[dict]:
    return SECURITY_ALERTS_BY_UPN.get(upn, [])


def _get_mailbox_rules(upn: str) -> list[dict]:
    return MAILBOX_RULES_BY_UPN.get(upn, [])


def _get_ip_reputation(ip: str) -> dict:
    return IP_REPUTATION.get(ip, {"IP": ip, "Reputation": "Unknown"})


def _get_entra_user(upn: str) -> dict:
    return ENTRA_USERS.get(upn, {})


def _get_ad_user(upn: str) -> dict:
    return AD_USERS.get(upn, {})


# ─────────────────────────────────────────────────────────────
# Tools exposed to the single agent
# ─────────────────────────────────────────────────────────────


@tool
def get_user_context(upn: str) -> str:
    """Return enriched user context (Entra ID + AD profile) for a UPN.

    Use this in Phase 2 (Enrich) before evaluating risk factors. Output
    includes Roles, Groups, AccountEnabled, MFARegistered, RiskState plus
    pre-computed flags Risk_HighPrivilegeUser and Risk_DisabledAccountSignIn.
    """
    entra = _get_entra_user(upn)
    ad = _get_ad_user(upn)
    roles = set(entra.get("Roles", []))
    groups = set(entra.get("Groups", []))
    return json.dumps({
        "UPN": upn,
        "DisplayName": entra.get("DisplayName", ad.get("DisplayName", "")),
        "JobTitle": entra.get("JobTitle", ""),
        "Department": entra.get("Department", ad.get("Department", "")),
        "Country": ad.get("OfficeLocation", ""),
        "Manager": ad.get("Manager", ""),
        "AccountEnabled": entra.get("AccountEnabled", True),
        "MFARegistered": entra.get("MFARegistered", True),
        "Roles": list(roles),
        "Groups": list(groups),
        "RiskState": entra.get("RiskState", "none"),
        "LastPasswordChange": entra.get("LastPasswordChange", ""),
        "Risk_HighPrivilegeUser": bool(roles & HIGH_PRIV_ROLES or groups & HIGH_PRIV_GROUPS),
        "Risk_DisabledAccountSignIn": not entra.get("AccountEnabled", True),
    })


@tool
def evaluate_location_anomaly(upn: str, ioc_ips: str) -> str:
    """Evaluate geographic anomalies: impossible-travel velocity, IP reputation, VPN/proxy use.

    Args:
        upn: User principal name.
        ioc_ips: JSON array string of IoC IPs from the detection (e.g. '["1.2.3.4"]').
    """
    ip_list = json.loads(ioc_ips) if isinstance(ioc_ips, str) else ioc_ips
    signins = _get_signin_logs(upn)
    ip_reports = {ip: _get_ip_reputation(ip) for ip in ip_list}
    return json.dumps({
        "sign_in_locations": [
            {"IP": s["IPAddress"], "Location": s["Location"], "Time": s["Timestamp"]}
            for s in signins
        ],
        "ip_reputation": ip_reports,
        "malicious_ip_detected": any(r.get("Reputation") == "Malicious" for r in ip_reports.values()),
        "vpn_proxy_detected": any(r.get("IsProxy") or r.get("IsVPN") for r in ip_reports.values()),
    })


@tool
def evaluate_authentication_anomaly(upn: str) -> str:
    """Evaluate authentication method anomalies: deviation from normal auth patterns."""
    signins = _get_signin_logs(upn)
    methods = [s["AuthMethod"] for s in signins]
    return json.dumps({
        "auth_methods_used": methods,
        "normal_method": "Password+MFA",
        "anomalous_sessions": [
            {"IP": s["IPAddress"], "Method": s["AuthMethod"], "Time": s["Timestamp"]}
            for s in signins
            if s["AuthMethod"] != "Password+MFA"
        ],
        "mfa_bypassed": any("MFA" not in m for m in methods),
        "device_compliance_failures": [s["IPAddress"] for s in signins if not s.get("DeviceCompliant", True)],
    })


@tool
def evaluate_token_anomaly(upn: str) -> str:
    """Evaluate token anomalies: concurrent sessions, unusual token issuers."""
    signins = _get_signin_logs(upn)
    sessions = [s["SessionId"] for s in signins]
    nonint = _get_noninteractive_signin_logs(upn)
    return json.dumps({
        "active_sessions": sessions,
        "concurrent_sessions": len(set(sessions)) > 1,
        "session_count": len(set(sessions)),
        "noninteractive_activity": [
            {"IP": s["IPAddress"], "App": s["AppDisplayName"], "Time": s["Timestamp"]}
            for s in nonint
        ],
        "unusual_token_issuers": [s["TokenIssuer"] for s in signins if s["TokenIssuer"] != "AzureAD"],
    })


@tool
def evaluate_brute_force_pattern(upn: str, ioc_ips: str) -> str:
    """Evaluate brute-force patterns: failed sign-in surges, password spray indicators.

    Args:
        upn: User principal name.
        ioc_ips: JSON array string of IoC IPs from the detection.
    """
    ip_list = json.loads(ioc_ips) if isinstance(ioc_ips, str) else ioc_ips
    failed = _get_failed_signins(upn)
    return json.dumps({
        "total_failed_attempts": len(failed),
        "failed_from_ioc_ips": [f for f in failed if f["IPAddress"] in ip_list],
        "time_window": f"{failed[0]['Timestamp']} to {failed[-1]['Timestamp']}" if failed else "N/A",
        "rapid_succession": len(failed) >= 3,
        "followed_by_success": len(failed) > 0
        and any(s["Status"] == "Success" and s["IPAddress"] in ip_list for s in _get_signin_logs(upn)),
    })


@tool
def evaluate_mfa_abuse(upn: str) -> str:
    """Evaluate MFA abuse: recent MFA method changes, MFA fatigue indicators."""
    audit = _get_audit_logs(upn)
    mfa_changes = [
        a for a in audit
        if any(
            "AuthenticationMethod" in str(p.get("Name", ""))
            or "StrongAuthentication" in str(p.get("Name", ""))
            for p in a.get("ModifiedProperties", [])
        )
    ]
    return json.dumps({
        "mfa_method_changes": mfa_changes,
        "changes_count": len(mfa_changes),
        "recent_mfa_modification": len(mfa_changes) > 0,
        "changed_after_suspicious_login": len(mfa_changes) > 0,
    })


@tool
def evaluate_post_login_activity(upn: str, ioc_ips: str) -> str:
    """Evaluate post-login suspicious activity: data access, privilege escalation, lateral movement.

    Args:
        upn: User principal name.
        ioc_ips: JSON array string of IoC IPs from the detection.
    """
    ip_list = json.loads(ioc_ips) if isinstance(ioc_ips, str) else ioc_ips
    alerts = _get_security_alerts(upn)
    audit = _get_audit_logs(upn)
    nonint = _get_noninteractive_signin_logs(upn)
    return json.dumps({
        "security_alerts": alerts,
        "suspicious_app_access": [
            {"App": s["AppDisplayName"], "IP": s["IPAddress"], "Time": s["Timestamp"]}
            for s in nonint
            if s["IPAddress"] in ip_list
        ],
        "privilege_changes": [a for a in audit if a.get("Category") == "UserManagement"],
        "total_alerts": len(alerts),
        "post_compromise_indicators": len(alerts) + len(nonint),
    })


@tool
def evaluate_oauth_abuse(upn: str) -> str:
    """Evaluate OAuth abuse: suspicious consent grants, high-privilege app permissions."""
    consent_events = [a for a in _get_audit_logs(upn) if a.get("Activity") == "Consent to application"]
    return json.dumps({
        "consent_grants": consent_events,
        "suspicious_apps": [a.get("TargetApp") for a in consent_events],
        "high_privilege_permissions": [
            p for a in consent_events for p in a.get("Permissions", []) if "Write" in p or "ReadWrite" in p
        ],
        "consent_count": len(consent_events),
        "suspicious_consent_detected": len(consent_events) > 0,
    })


@tool
def evaluate_mailbox_manipulation(upn: str) -> str:
    """Evaluate mailbox manipulation: inbox rule creation, forwarding to external addresses."""
    rules = _get_mailbox_rules(upn)
    alerts = [a for a in _get_security_alerts(upn) if "inbox rule" in a.get("AlertType", "").lower()]
    return json.dumps({
        "inbox_rules": rules,
        "external_forwarding": [r for r in rules if "@" in r.get("Actions", {}).get("ForwardTo", "")],
        "delete_after_forward": [r for r in rules if r.get("Actions", {}).get("DeleteMessage")],
        "related_alerts": alerts,
        "manipulation_detected": len(rules) > 0,
    })


@tool
def evaluate_high_privilege_user(upn: str) -> str:
    """Evaluate whether the user holds high-privilege roles or group memberships."""
    user = _get_entra_user(upn)
    roles = set(user.get("Roles", []))
    groups = set(user.get("Groups", []))
    return json.dumps({
        "roles": list(roles),
        "groups": list(groups),
        "high_privilege_roles": list(roles & HIGH_PRIV_ROLES),
        "high_privilege_groups": list(groups & HIGH_PRIV_GROUPS),
        "is_high_privilege": bool(roles & HIGH_PRIV_ROLES or groups & HIGH_PRIV_GROUPS),
    })


@tool
def evaluate_disabled_account_signin(upn: str) -> str:
    """Evaluate whether sign-in activity is coming from a disabled account."""
    user = _get_entra_user(upn)
    signins = _get_signin_logs(upn)
    return json.dumps({
        "account_enabled": user.get("AccountEnabled", True),
        "signin_attempts": len(signins),
        "signin_after_disable": not user.get("AccountEnabled", True) and len(signins) > 0,
        "risk_state": user.get("RiskState", "none"),
    })


ALL_TOOLS = [
    get_user_context,
    evaluate_location_anomaly,
    evaluate_authentication_anomaly,
    evaluate_token_anomaly,
    evaluate_brute_force_pattern,
    evaluate_mfa_abuse,
    evaluate_post_login_activity,
    evaluate_oauth_abuse,
    evaluate_mailbox_manipulation,
    evaluate_high_privilege_user,
    evaluate_disabled_account_signin,
]
