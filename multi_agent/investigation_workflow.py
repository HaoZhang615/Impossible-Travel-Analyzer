"""Shared Impossible Travel investigation workflow.

Used by:
  - 01-investigation.ipynb   — local run, single test case via :func:`load_test_case`
  - hosted_agent/main.py     — container, all bundled cases via :func:`load_test_cases_dir`

In production the ``@tool`` functions would query Microsoft Sentinel / Entra ID /
Defender XDR via MCP. For the workshop they read from the JSON scenarios under
``test_cases/`` (or whichever directory the caller hydrates from).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agent_framework import (
    Agent,
    AgentExecutor,
    AgentExecutorRequest,
    AgentExecutorResponse,
    Executor,
    Message,
    Workflow,
    WorkflowBuilder,
    WorkflowContext,
    handler,
    tool,
)


# ─────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────


class RiskFactorName(str, Enum):
    """The 10 risk factors evaluated during an Impossible Travel investigation."""

    LOCATION_ANOMALY = "LocationAnomaly"
    AUTHENTICATION_ANOMALY = "AuthenticationAnomaly"
    TOKEN_ANOMALY = "TokenAnomaly"
    BRUTE_FORCE_PATTERN = "BruteForcePattern"
    MFA_ABUSE = "MfaAbuse"
    POST_LOGIN_SUSPICIOUS_ACTIVITY = "PostLoginSuspiciousActivity"
    OAUTH_ABUSE = "OAuthAbuse"
    MAILBOX_MANIPULATION = "MailboxManipulation"
    HIGH_PRIVILEGE_USER = "HighPrivilegeUser"
    DISABLED_ACCOUNT_SIGNIN = "DisabledAccountSignIn"


class NormalizedDetection(BaseModel):
    """Sentinel analytics rule output — the trigger for investigation."""

    ThreatScenario: str = "AccountCompromise"
    PrimaryEntityType: str = "User"
    PrimaryEntityId: str  # UPN
    IoC_IPs: list[str] = Field(default_factory=list)
    IoC_Locations: list[str] = Field(default_factory=list)
    IoC_Devices: list[str] = Field(default_factory=list)
    IoC_Applications: list[str] = Field(default_factory=list)
    IoC_Domains: list[str] = Field(default_factory=list)
    DetectionTime: str = ""
    Severity: str = "High"


class ContextEnrichment(BaseModel):
    """AD/Entra enrichment from the Context Agent."""

    UPN: str
    DisplayName: str = ""
    JobTitle: str = ""
    Department: str = ""
    Country: str = ""
    Manager: str = ""
    AccountEnabled: bool = True
    MFARegistered: bool = True
    Roles: list[str] = Field(default_factory=list)
    Groups: list[str] = Field(default_factory=list)
    RiskState: str = "none"
    LastPasswordChange: str = ""
    Risk_HighPrivilegeUser: bool = False
    Risk_DisabledAccountSignIn: bool = False


class RiskEvidence(BaseModel):
    """A single risk factor evaluation result produced by a sub-agent."""

    RiskFactor: str
    Type: str = ""
    Value: str = ""
    Reason: str = ""
    EvidenceScore: int = Field(default=0, ge=0, le=100)


class ThreatDecisionRecord(BaseModel):
    """Assembled record combining context enrichment and all risk evidence."""

    Detection: NormalizedDetection
    Context: ContextEnrichment
    RiskEvidenceItems: list[RiskEvidence] = Field(default_factory=list)
    RiskFactors: dict[str, bool] = Field(default_factory=dict)


class ActionItem(BaseModel):
    """A single remediation action in the action plan."""

    action: str
    target: str = ""
    value: str = ""
    riskFactor: str = ""
    destructive: bool = False
    requiresApproval: bool = False


class InvestigationVerdict(BaseModel):
    """PACO's final determination."""

    verdict: str  # AccountCompromised | BenignAnomaly | Inconclusive
    confidence: str  # High | Medium | Low
    reasoning: str
    actionPlan: list[ActionItem] = Field(default_factory=list)
    narrative: str = ""


# ─────────────────────────────────────────────────────────────
# Data sources — populated by load_test_case[s_dir]
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


def reset_data_sources() -> None:
    """Clear all in-memory data sources (used between test-case switches)."""
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
    """Merge one test-case JSON's ``data_sources`` block into the module dicts."""
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
    """Load a single test-case JSON, replacing any previously-loaded data.

    Returns the parsed case dict so callers can grab metadata like
    ``case["detection"]`` and ``case["expected_verdict"]``.
    """
    reset_data_sources()
    with open(path, encoding="utf-8") as f:
        case = json.load(f)
    _ingest_case(case)
    return case


def load_test_cases_dir(directory: str | Path) -> int:
    """Load all ``*.json`` test cases from a directory (additive). Returns count loaded."""
    n = 0
    for path in sorted(Path(directory).glob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                case = json.load(f)
            _ingest_case(case)
            n += 1
        except Exception as exc:  # noqa: BLE001 — diagnostic only
            print(f"[load_test_cases_dir] Failed to load {path.name}: {exc}")
    return n


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
# Privilege sets (shared between ContextEnricher and the high-priv tool)
# ─────────────────────────────────────────────────────────────

HIGH_PRIV_ROLES = {
    "Global Administrator",
    "Exchange Administrator",
    "Security Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Global Reader",
}
HIGH_PRIV_GROUPS = {"Executive-Access", "Domain Admins", "Enterprise Admins"}


# ─────────────────────────────────────────────────────────────
# 10 @tool functions — one per risk factor
# ─────────────────────────────────────────────────────────────


@tool
def evaluate_location_anomaly(upn: str, ioc_ips: str) -> str:
    """Evaluate geographic anomalies: impossible travel velocity, IP reputation, VPN/proxy usage."""
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
    """Evaluate brute force patterns: failed sign-in surges, password spray indicators."""
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
    """Evaluate post-login suspicious activity: data access, privilege escalation, lateral movement."""
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
    """Evaluate mailbox manipulation: inbox rule creation, email forwarding to external addresses."""
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


# ─────────────────────────────────────────────────────────────
# ThreatDecisionPolicy
# ─────────────────────────────────────────────────────────────

THREAT_DECISION_POLICY: dict[str, Any] = {
    "ThreatScenario": "AccountCompromise",
    "Description": (
        "Policy governing account compromise scenarios including impossible travel, "
        "credential theft, MFA abuse, and post-compromise activity."
    ),
    "RiskModel": {
        "RiskWeights": {
            "LocationAnomaly": 15,
            "AuthenticationAnomaly": 15,
            "TokenAnomaly": 20,
            "BruteForcePattern": 10,
            "MfaAbuse": 20,
            "PostLoginSuspiciousActivity": 15,
            "OAuthAbuse": 10,
            "MailboxManipulation": 10,
            "HighPrivilegeUser": 10,
            "DisabledAccountSignIn": 5,
        },
        "EvidenceMultiplier": {
            "Enabled": True,
            "Rules": [
                {"MinScore": 80, "Multiplier": 1.0},
                {"MinScore": 50, "Multiplier": 0.6},
                {"MinScore": 0, "Multiplier": 0.3},
            ],
        },
        "AggregationStrategy": "MAX",
    },
    "ActionModel": {
        "RiskFactorActionMap": {
            "LocationAnomaly": ["revokeUserSessions", "blockSourceIP"],
            "AuthenticationAnomaly": ["revokeUserSessions", "enforcePasswordReset"],
            "TokenAnomaly": ["revokeUserSessions", "enforcePasswordReset"],
            "BruteForcePattern": ["blockSourceIP"],
            "MfaAbuse": ["resetMfaMethods", "revokeUserSessions", "enforcePasswordReset"],
            "PostLoginSuspiciousActivity": ["disableUserAccount", "revokeUserSessions"],
            "OAuthAbuse": ["revokeOAuthConsent", "revokeUserSessions"],
            "MailboxManipulation": ["removeInboxRules", "revokeUserSessions"],
            "HighPrivilegeUser": ["escalateToTier2"],
            "DisabledAccountSignIn": ["disableUserAccount", "revokeUserSessions"],
        },
        "ActionDefinitions": {
            "revokeUserSessions": {"Destructive": False, "ExecutionConstraints": []},
            "enforcePasswordReset": {"Destructive": False, "ExecutionConstraints": []},
            "blockSourceIP": {"Destructive": False, "ExecutionConstraints": []},
            "disableUserAccount": {"Destructive": True, "ExecutionConstraints": ["Risk_HighPrivilegeUser"]},
            "resetMfaMethods": {"Destructive": True, "ExecutionConstraints": []},
            "revokeOAuthConsent": {"Destructive": True, "ExecutionConstraints": []},
            "removeInboxRules": {"Destructive": False, "ExecutionConstraints": []},
            "escalateToTier2": {"Destructive": False, "ExecutionConstraints": []},
        },
    },
    "PolicyEngine": {"AutoThreshold": 50, "SemiThreshold": 25},
}


# ─────────────────────────────────────────────────────────────
# Executors
# ─────────────────────────────────────────────────────────────


class ContextEnricher(Executor):
    """Deterministic context enrichment — queries AD/Entra and enriches the detection."""

    @handler
    async def enrich(self, prompt: str, ctx: WorkflowContext[AgentExecutorRequest]) -> None:
        """Local-notebook entry point: caller passes the detection JSON as a plain string."""
        await self._run(prompt, ctx)

    @handler
    async def enrich_from_messages(
        self, messages: list[Message], ctx: WorkflowContext[AgentExecutorRequest]
    ) -> None:
        """Hosted-agent entry point: ``workflow.as_agent()`` passes a list[Message].

        We expect the deployed agent to be invoked with a single user message whose
        text content is the JSON detection payload (the same payload the local
        notebook sends via ``workflow.run(detection.model_dump_json())``).
        """
        text = ""
        for msg in messages:
            for content in msg.contents:
                if hasattr(content, "text") and content.text:
                    text = content.text
                    break
                if isinstance(content, str):
                    text = content
                    break
            if text:
                break
        if not text:
            raise ValueError("ContextEnricher received no input text from the conversation.")
        await self._run(text, ctx)

    async def _run(self, prompt: str, ctx: WorkflowContext[AgentExecutorRequest]) -> None:
        detection = NormalizedDetection.model_validate_json(prompt)
        upn = detection.PrimaryEntityId

        entra = _get_entra_user(upn)
        ad = _get_ad_user(upn)

        roles = set(entra.get("Roles", []))
        groups = set(entra.get("Groups", []))

        enrichment = ContextEnrichment(
            UPN=upn,
            DisplayName=entra.get("DisplayName", ad.get("DisplayName", "")),
            JobTitle=entra.get("JobTitle", ""),
            Department=entra.get("Department", ad.get("Department", "")),
            Country=ad.get("OfficeLocation", ""),
            Manager=ad.get("Manager", ""),
            AccountEnabled=entra.get("AccountEnabled", True),
            MFARegistered=entra.get("MFARegistered", True),
            Roles=list(roles),
            Groups=list(groups),
            RiskState=entra.get("RiskState", "none"),
            LastPasswordChange=entra.get("LastPasswordChange", ""),
            Risk_HighPrivilegeUser=bool(roles & HIGH_PRIV_ROLES or groups & HIGH_PRIV_GROUPS),
            Risk_DisabledAccountSignIn=not entra.get("AccountEnabled", True),
        )

        enriched_payload = json.dumps({
            "detection": detection.model_dump(),
            "context": enrichment.model_dump(),
        })

        print(
            f"  🔍 Context Enricher: {enrichment.DisplayName} | Dept={enrichment.Department} | "
            f"HighPriv={enrichment.Risk_HighPrivilegeUser} | Disabled={enrichment.Risk_DisabledAccountSignIn}"
        )

        await ctx.send_message(
            AgentExecutorRequest(
                messages=[Message("user", contents=[enriched_payload])],
                should_respond=True,
            )
        )


class RiskAggregator(Executor):
    """Deterministic aggregator — assembles ThreatDecisionRecord from all risk evidence."""

    @handler
    async def aggregate(
        self,
        results: list[AgentExecutorResponse],
        ctx: WorkflowContext[AgentExecutorRequest],
    ) -> None:
        all_evidence: list[RiskEvidence] = []
        detection_data: dict | None = None
        context_data: dict | None = None

        for resp in results:
            for msg in resp.full_conversation:
                text = ""
                for content in msg.contents:
                    if hasattr(content, "text"):
                        text = content.text or ""
                        break
                    if isinstance(content, str):
                        text = content
                        break
                if not text:
                    continue
                try:
                    all_evidence.append(RiskEvidence.model_validate_json(text))
                    continue
                except Exception:
                    pass
                try:
                    data = json.loads(text)
                    if "RiskFactor" in data:
                        all_evidence.append(RiskEvidence.model_validate(data))
                    if "detection" in data and detection_data is None:
                        detection_data = data["detection"]
                    if "context" in data and context_data is None:
                        context_data = data["context"]
                except Exception:
                    pass

        risk_factors = {rf.value: False for rf in RiskFactorName}
        for e in all_evidence:
            risk_factors[e.RiskFactor] = e.EvidenceScore > 0

        record = ThreatDecisionRecord(
            Detection=NormalizedDetection.model_validate(detection_data) if detection_data
            else NormalizedDetection(PrimaryEntityId="unknown"),
            Context=ContextEnrichment.model_validate(context_data) if context_data
            else ContextEnrichment(UPN="unknown"),
            RiskEvidenceItems=all_evidence,
            RiskFactors=risk_factors,
        )

        print(
            f"  📊 Risk Aggregator: {len(all_evidence)} evidence records, "
            f"{sum(risk_factors.values())} active / {len(risk_factors)} total risk factors"
        )

        await ctx.send_message(
            AgentExecutorRequest(
                messages=[Message("user", contents=[record.model_dump_json(indent=2)])],
                should_respond=True,
            )
        )


# ─────────────────────────────────────────────────────────────
# Workflow assembly
# ─────────────────────────────────────────────────────────────


def _risk_agent_instructions(risk_factor: str, extra: str = "") -> str:
    return (
        f"You are a security analyst specializing in {risk_factor} detection.\n"
        f"Your task:\n"
        f"1. Parse the enriched context from the user message to get the UPN and IoC_IPs.\n"
        f"2. Call your tool to gather evidence for the {risk_factor} risk factor.\n"
        f"3. Analyze the tool output and produce a RiskEvidence record.\n"
        f"4. Set RiskFactor to \"{risk_factor}\".\n"
        f'5. Set Type to a short category label (e.g., "geo_anomaly", "auth_deviation", "brute_force").\n'
        f"6. Set Value to the key finding summary.\n"
        f"7. Set Reason to a clear, concise explanation of your assessment.\n"
        f"8. Set EvidenceScore (0-100): 0=no evidence, 1-30=low, 31-60=medium, 61-100=high.\n"
        f"{extra}\n"
        f"Return ONLY the structured RiskEvidence — no extra commentary."
    )


def _paco_instructions() -> str:
    return (
        "You are PACO — the Principal Automated Compliance Orchestrator.\n\n"
        "## Your Mission\n"
        "You receive a ThreatDecisionRecord containing:\n"
        "- A NormalizedDetection (the Sentinel alert trigger)\n"
        "- A ContextEnrichment (AD/Entra user profile)\n"
        "- A list of RiskEvidence records from 10 specialized risk analysts\n\n"
        "## ThreatDecisionPolicy\n"
        f"{json.dumps(THREAT_DECISION_POLICY, indent=2)}\n\n"
        "## Instructions\n"
        "1. Review ALL risk evidence holistically — look for corroborating patterns.\n"
        "2. Determine the verdict: AccountCompromised, BenignAnomaly, or Inconclusive.\n"
        "3. Set confidence: High (strong corroborating evidence), Medium (some indicators), "
        "Low (weak/ambiguous).\n"
        "4. Generate an actionPlan — select appropriate actions from the ActionModel.\n"
        "5. For each action, set the target (user/IP/app), the triggering riskFactor, "
        "and whether it's destructive.\n"
        "6. For privileged users (Risk_HighPrivilegeUser=true), mark destructive actions "
        "with requiresApproval=true.\n"
        "7. Write a clear narrative summarizing the investigation timeline and findings.\n\n"
        "## Key Correlation Patterns\n"
        "- Impossible travel + malicious IP + brute force → strong compromise indicator\n"
        "- MFA bypass + MFA method change → attacker persistence\n"
        "- Post-login activity + mailbox rules → active data exfiltration\n"
        "- OAuth consent + high-privilege permissions → application-based persistence\n"
        "- HighPrivilegeUser amplifies severity of all detected risks\n\n"
        "Return ONLY the structured InvestigationVerdict."
    )


# Ordered registry of (agent_name, risk_factor, tool_fn, extra_instructions).
_RISK_AGENT_SPECS: list[tuple[str, str, Any, str]] = [
    ("LocationAnomalyAgent", "LocationAnomaly", evaluate_location_anomaly,
     "Pass both the upn and ioc_ips (as JSON array string) to your tool."),
    ("AuthenticationAnomalyAgent", "AuthenticationAnomaly", evaluate_authentication_anomaly, ""),
    ("TokenAnomalyAgent", "TokenAnomaly", evaluate_token_anomaly, ""),
    ("BruteForcePatternAgent", "BruteForcePattern", evaluate_brute_force_pattern,
     "Pass both the upn and ioc_ips (as JSON array string) to your tool."),
    ("MfaAbuseAgent", "MfaAbuse", evaluate_mfa_abuse, ""),
    ("PostLoginActivityAgent", "PostLoginSuspiciousActivity", evaluate_post_login_activity,
     "Pass both the upn and ioc_ips (as JSON array string) to your tool."),
    ("OAuthAbuseAgent", "OAuthAbuse", evaluate_oauth_abuse, ""),
    ("MailboxManipulationAgent", "MailboxManipulation", evaluate_mailbox_manipulation, ""),
    ("HighPrivilegeUserAgent", "HighPrivilegeUser", evaluate_high_privilege_user, ""),
    ("DisabledAccountSignInAgent", "DisabledAccountSignIn", evaluate_disabled_account_signin, ""),
]


@dataclass
class WorkflowComponents:
    """Everything :func:`build_workflow` produces — handy for DevUI and tests."""

    workflow: Workflow
    context_enricher: ContextEnricher
    risk_aggregator: RiskAggregator
    risk_agents: list[Agent] = field(default_factory=list)
    risk_executors: list[AgentExecutor] = field(default_factory=list)
    paco_agent: Agent | None = None
    paco_executor: AgentExecutor | None = None


def build_workflow(client, paco_client=None, *, store: bool = False) -> WorkflowComponents:
    """Build the ImpossibleTravelInvestigation workflow graph.

    Args:
        client: ``FoundryChatClient`` used by the 10 risk sub-agents.
        paco_client: ``FoundryChatClient`` used by PACO. Defaults to ``client``.
        store: Pass through to each agent's ``default_options["store"]``.
            Set ``True`` locally if you want Foundry to persist threads;
            ``False`` (default) is appropriate for the hosted-agent container.

    Returns:
        A :class:`WorkflowComponents` bundle. Use ``.workflow`` to run, and
        ``.risk_agents`` / ``.paco_agent`` for DevUI.
    """
    paco_client = paco_client or client

    context_enricher = ContextEnricher(id="ContextEnricher")
    risk_aggregator = RiskAggregator(id="RiskAggregator")

    risk_agents: list[Agent] = []
    risk_executors: list[AgentExecutor] = []
    for name, risk_factor, tool_fn, extra in _RISK_AGENT_SPECS:
        agent = Agent(
            client=client,
            name=name,
            description=f"Evaluates the {risk_factor} risk factor for impossible travel investigations.",
            instructions=_risk_agent_instructions(risk_factor, extra),
            tools=[tool_fn],
            default_options={"response_format": RiskEvidence, "store": store},
        )
        risk_agents.append(agent)
        risk_executors.append(AgentExecutor(agent, context_mode="last_agent"))

    paco_agent = Agent(
        client=paco_client,
        name="PACO",
        description="Principal Automated Compliance Orchestrator — makes the final investigation verdict.",
        instructions=_paco_instructions(),
        default_options={"response_format": InvestigationVerdict, "store": store},
    )
    paco_executor = AgentExecutor(paco_agent, context_mode="last_agent")

    workflow = (
        WorkflowBuilder(
            name="ImpossibleTravelInvestigation",
            start_executor=context_enricher,
            output_from=[paco_executor],
        )
        .add_fan_out_edges(context_enricher, risk_executors)
        .add_fan_in_edges(risk_executors, risk_aggregator)
        .add_edge(risk_aggregator, paco_executor)
        .build()
    )

    return WorkflowComponents(
        workflow=workflow,
        context_enricher=context_enricher,
        risk_aggregator=risk_aggregator,
        risk_agents=risk_agents,
        risk_executors=risk_executors,
        paco_agent=paco_agent,
        paco_executor=paco_executor,
    )
