"""Impossible Travel Investigation — Hosted Agent entrypoint.

Thin wrapper around :mod:`investigation_workflow` (the shared workflow used by
``01-investigation.ipynb``). All the models, ``@tool`` functions, executors,
and the ``ImpossibleTravelInvestigation`` workflow live in that module so the
notebook and the hosted container stay in lock-step.

This entrypoint just:
  1. Reads platform-injected env vars (``FOUNDRY_PROJECT_ENDPOINT``,
     ``MODEL_DEPLOYMENT_NAME``, optional ``PACO_MODEL_DEPLOYMENT_NAME``).
  2. Bundles all ``test_cases/*.json`` shipped alongside this file into the
     in-memory data sources.
  3. Builds the workflow with two ``FoundryChatClient`` instances (one for the
     risk sub-agents, one for PACO — may be the same).
  4. Hosts the workflow as an OpenAI Responses-compatible HTTP server.
"""
from __future__ import annotations

import os
from pathlib import Path

from agent_framework.foundry import FoundryChatClient
from agent_framework_foundry_hosting import ResponsesHostServer
from azure.identity import DefaultAzureCredential

from investigation_workflow import build_workflow, load_test_cases_dir


def _configure_telemetry() -> None:
    """Disable OTEL sampling so every sub-agent span is exported.

    The Azure Monitor exporter defaults to fixed-rate sampling which drops a
    large fraction of dependency spans when 10+ sub-agents fire concurrently.
    Setting ``OTEL_TRACES_SAMPLER=always_on`` ensures all chat completion spans
    (and their token-usage attributes) reach App Insights.
    """
    os.environ.setdefault("OTEL_TRACES_SAMPLER", "always_on")
    # Also increase the batch export limits so nothing is dropped due to
    # queue pressure during the fan-out burst.
    os.environ.setdefault("OTEL_BSP_MAX_QUEUE_SIZE", "4096")
    os.environ.setdefault("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512")


def main() -> None:
    _configure_telemetry()

    project_endpoint = (
        os.environ.get("FOUNDRY_PROJECT_ENDPOINT")
        or os.environ["AZURE_AI_PROJECT_ENDPOINT"]
    )
    model_name = (
        os.environ.get("MODEL_DEPLOYMENT_NAME")
        or os.environ.get("AZURE_AI_MODEL_DEPLOYMENT_NAME", "gpt-4o")
    )
    paco_model_name = os.environ.get("PACO_MODEL_DEPLOYMENT_NAME", model_name)

    # When True, Foundry persists thread/session data so the portal surfaces
    # full session details, token counts, and traces. Override with
    # WORKFLOW_STORE=false to opt back out.
    store_threads = os.environ.get("WORKFLOW_STORE", "true").strip().lower() in (
        "1", "true", "yes", "on",
    )
    print(f"[startup] Workflow store={store_threads}")

    test_cases_dir = Path(__file__).parent / "test_cases"
    loaded = load_test_cases_dir(test_cases_dir)
    print(f"[startup] Loaded {loaded} test case(s) from {test_cases_dir}")

    credential = DefaultAzureCredential()
    risk_client = FoundryChatClient(
        project_endpoint=project_endpoint,
        model=model_name,
        credential=credential,
    )
    paco_client = (
        risk_client
        if paco_model_name == model_name
        else FoundryChatClient(
            project_endpoint=project_endpoint,
            model=paco_model_name,
            credential=credential,
        )
    )

    components = build_workflow(risk_client, paco_client=paco_client, store=store_threads)
    server = ResponsesHostServer(components.workflow.as_agent())
    server.run()


if __name__ == "__main__":
    main()
