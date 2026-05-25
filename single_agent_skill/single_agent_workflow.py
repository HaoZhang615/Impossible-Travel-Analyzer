"""Single-agent Impossible Travel investigator (file-based Agent Skill version).

Counterpart to the multi-agent ``investigation_workflow`` on ``main`` — collapses
the 10 risk sub-agents, the deterministic enricher/aggregator, and the PACO
orchestrator into a **single** :class:`agent_framework.Agent` driven by the
``soc-impossible-travel`` file-based skill.

Used by:
  - ``01-investigation.ipynb`` — local run, single test case via :func:`load_test_case`
  - ``hosted_agent/main.py``    — container, all bundled cases via :func:`load_test_cases_dir`
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agent_framework import Agent, SkillsProvider

from subprocess_script_runner import subprocess_script_runner
from tools import ALL_TOOLS, load_test_case, load_test_cases_dir  # re-exported

__all__ = [
    "RiskFactorName",
    "NormalizedDetection",
    "ContextEnrichment",
    "RiskEvidence",
    "ThreatDecisionRecord",
    "ActionItem",
    "InvestigationVerdict",
    "build_agent",
    "load_test_case",
    "load_test_cases_dir",
    "AGENT_INSTRUCTIONS",
]


# ─────────────────────────────────────────────────────────────
# Pydantic models — identical to the multi-agent project so eval results are
# directly comparable.
# ─────────────────────────────────────────────────────────────


class RiskFactorName(str, Enum):
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
    ThreatScenario: str = "AccountCompromise"
    PrimaryEntityType: str = "User"
    PrimaryEntityId: str
    IoC_IPs: list[str] = Field(default_factory=list)
    IoC_Locations: list[str] = Field(default_factory=list)
    IoC_Devices: list[str] = Field(default_factory=list)
    IoC_Applications: list[str] = Field(default_factory=list)
    IoC_Domains: list[str] = Field(default_factory=list)
    DetectionTime: str = ""
    Severity: str = "High"


class ContextEnrichment(BaseModel):
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
    RiskFactor: str
    Type: str = ""
    Value: str = ""
    Reason: str = ""
    EvidenceScore: int = Field(default=0, ge=0, le=100)


class ThreatDecisionRecord(BaseModel):
    Detection: NormalizedDetection
    Context: ContextEnrichment
    RiskEvidenceItems: list[RiskEvidence] = Field(default_factory=list)
    RiskFactors: dict[str, bool] = Field(default_factory=dict)


class ActionItem(BaseModel):
    action: str
    target: str = ""
    value: str = ""
    riskFactor: str = ""
    destructive: bool = False
    requiresApproval: bool = False


class InvestigationVerdict(BaseModel):
    verdict: str          # AccountCompromised | BenignAnomaly | Inconclusive
    confidence: str       # High | Medium | Low
    reasoning: str
    actionPlan: list[ActionItem] = Field(default_factory=list)
    narrative: str = ""


# ─────────────────────────────────────────────────────────────
# Agent assembly
# ─────────────────────────────────────────────────────────────


AGENT_INSTRUCTIONS = (
    "You are an SOC L2 analyst handling Microsoft Sentinel Impossible-Travel "
    "detections. The user message contains a JSON NormalizedDetection payload.\n\n"
    "When you receive such a payload, follow the `soc-impossible-travel` skill "
    "end-to-end: load it via `load_skill`, then work through its 5 phases (Parse, "
    "Enrich, Evaluate 10 risk factors, Score, PACO verdict). Use the registered "
    "tools for every data-source lookup and the skill scripts for distance / "
    "velocity calculations.\n\n"
    "Return exactly one InvestigationVerdict JSON object as your final response "
    "— no surrounding prose, no markdown code fence."
)


def _default_skills_dir() -> Path:
    return Path(__file__).resolve().parent / "skills"


def build_agent(
    client,
    *,
    skills_dir: str | Path | None = None,
    store: bool = False,
    extra_tools: list[Any] | None = None,
) -> Agent:
    """Construct the single skill-driven agent.

    Args:
        client: A configured ``FoundryChatClient`` (or any compatible chat client).
        skills_dir: Path to the directory containing ``soc-impossible-travel/SKILL.md``.
            Defaults to ``<this file>/skills``.
        store: Forwarded to ``Agent.default_options["store"]``. ``False`` for the
            hosted container, ``True`` if you want Foundry to persist threads
            locally for inspection.
        extra_tools: Optional additional tools to register alongside ``ALL_TOOLS``.

    Returns:
        A fully wired ``Agent`` with the file-based skills provider installed.
    """
    skills_path = Path(skills_dir) if skills_dir else _default_skills_dir()
    skills_provider = SkillsProvider.from_paths(
        skill_paths=str(skills_path),
        script_runner=subprocess_script_runner,
    )

    tools = list(ALL_TOOLS) + list(extra_tools or [])

    return Agent(
        client=client,
        name="SOCImpossibleTravelAgent",
        description=(
            "Single agent driven by the soc-impossible-travel file-based skill. "
            "Investigates Microsoft Sentinel Impossible-Travel detections end-to-end."
        ),
        instructions=AGENT_INSTRUCTIONS,
        tools=tools,
        context_providers=[skills_provider],
        default_options={"response_format": InvestigationVerdict, "store": store},
    )
