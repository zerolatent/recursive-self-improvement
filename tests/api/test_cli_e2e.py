"""End-to-end test for the `evo` CLI golden path (FR-014, §3/§10.1).

Spins up the real FastAPI app under uvicorn on an ephemeral port, wired to
the test database, then drives a full campaign through the CLI's
golden-path commands — `evo init`, `agent register`, `eval baseline`,
`campaign plan|run|inspect`, `release nominate|qualify|canary|promote|
rollback` — exactly as a CI job would. The only step that bypasses the
CLI is registering the candidate proposal itself: candidates are produced
by the evolution plane's pipeline, not by a CLI command, so the test
posts it to the API directly (still over real HTTP).

The CLI runs in-process (`cli.main`) with a `--config` file written by
`evo init`, so the full HTTP path (client -> uvicorn -> app -> Postgres)
is exercised without subprocess overhead.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from sqlalchemy.orm import sessionmaker

from evoruntime.api.cli import main as cli_main
from evoruntime.server.app import create_app
from evoruntime.server.dependencies import get_session_factory
from evoruntime.server.settings import get_settings
from tests.support.factories import make_campaign_spec_mapping

PARENT_BYTES = b"prompt v1: answer carefully"
CANDIDATE_BYTES = b"prompt v2: answer carefully, step by step"


@pytest.fixture
def live_server(session_factory: sessionmaker[Any], monkeypatch: pytest.MonkeyPatch) -> Any:
    """The real app served by uvicorn on an ephemeral localhost port."""
    # Semantic diffs run through the E7 reference adapter, exactly as a
    # real deployment would configure it.
    monkeypatch.setenv("EVORUNTIME_ADAPTER_COMMAND", "python -m tests.plugins.reference_plugin")
    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("uvicorn did not start within 10s")
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def _run_evo(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, Any]:
    """Run one CLI command and return (exit_code, parsed JSON stdout)."""
    exit_code = cli_main(list(args))
    out = capsys.readouterr().out
    return exit_code, json.loads(out) if out.strip() else None


def _write_json(path: Path, payload: Any) -> str:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_cli_golden_path_drives_campaign_to_release(
    live_server: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    tenant_id: str,
) -> None:
    config = tmp_path / "evo-config.json"
    metrics = _write_json(tmp_path / "metrics.json", {"task_success_rate": 0.83})
    spec = _write_json(tmp_path / "spec.json", make_campaign_spec_mapping())
    adapter_versions = _write_json(tmp_path / "adapters.json", {"evo-prompt-strategist": "1.2.0"})
    model_routes = _write_json(tmp_path / "routes.json", {"default": "gpt-5-mini"})
    policies = _write_json(tmp_path / "policies.json", {"tier": "tier-2-standard"})

    # 1. init: write the connection profile every later command reads.
    code, body = _run_evo(
        capsys,
        "init",
        "--url",
        live_server,
        "--identity",
        "svc_evaluator_1",
        "--role",
        "evaluator",
        "--tenant",
        tenant_id,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["config_path"] == str(config)

    headers = {
        "x-evoruntime-identity": "svc_evaluator_1",
        "x-evoruntime-role": "evaluator",
        "x-evoruntime-tenant": tenant_id,
    }

    # 2. agent register.
    code, body = _run_evo(
        capsys,
        "agent",
        "register",
        "--plugin-id",
        "evo-prompt-strategist",
        "--kind",
        "strategy",
        "--pinned-image",
        "ghcr.io/evoruntime/strategist@sha256:" + "b" * 64,
        "--artifact-types",
        "prompt_bundle",
        "--config",
        str(config),
    )
    assert code == 0
    assert body["plugin_id"] == "evo-prompt-strategist"

    # 3. eval baseline: record the incumbent's signed outcome. The parent
    # artifact is registered first so the candidate can point at it.
    parent = httpx.post(
        f"{live_server}/v1/candidates",
        json={
            "artifact_type": "prompt_bundle",
            "canonical_bytes_b64": base64.b64encode(PARENT_BYTES).decode(),
            "strategy_id": "incumbent",
        },
        headers=headers,
    )
    assert parent.status_code == 201, parent.text
    baseline_digest = parent.json()["artifact_digest"]
    code, body = _run_evo(
        capsys,
        "eval",
        "baseline",
        "--artifact-digest",
        baseline_digest,
        "--outcome",
        "pass",
        "--metrics-file",
        metrics,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["outcome"] == "pass"
    assert body["attestation_id"]

    # 4. campaign plan: validate, pin, and sign the spec.
    code, body = _run_evo(
        capsys,
        "campaign",
        "plan",
        "--spec-file",
        spec,
        "--config",
        str(config),
    )
    assert code == 0
    campaign_id = body["campaign_id"]
    assert body["phase"] == "discover"

    # 5. campaign run: advance one lifecycle step.
    code, body = _run_evo(
        capsys,
        "campaign",
        "run",
        "--campaign-id",
        campaign_id,
        "--to-phase",
        "plan",
        "--reason",
        "golden path",
        "--config",
        str(config),
    )
    assert code == 0
    assert body["phase"] == "plan"

    # 6. campaign inspect: detail, then the Pareto comparison.
    code, body = _run_evo(
        capsys,
        "campaign",
        "inspect",
        "--campaign-id",
        campaign_id,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["campaign_id"] == campaign_id

    # Candidates come from the evolution plane's pipeline, not the CLI;
    # register one over real HTTP so the comparison has data.
    candidate_response = httpx.post(
        f"{live_server}/v1/candidates",
        json={
            "campaign_id": campaign_id,
            "artifact_type": "prompt_bundle",
            "canonical_bytes_b64": base64.b64encode(CANDIDATE_BYTES).decode(),
            "strategy_id": "evo-prompt-strategist",
            "parent_digest": baseline_digest,
        },
        headers=headers,
    )
    assert candidate_response.status_code == 201, candidate_response.text
    proposal_id = candidate_response.json()["proposal_id"]
    proposed_digest = candidate_response.json()["artifact_digest"]

    code, body = _run_evo(
        capsys,
        "campaign",
        "inspect",
        "--campaign-id",
        campaign_id,
        "--pareto",
        "--config",
        str(config),
    )
    assert code == 0
    assert body["entries"][0]["proposal_id"] == proposal_id

    # 7. candidate diff and evidence (evidence resolves the digest itself).
    code, body = _run_evo(
        capsys,
        "candidate",
        "diff",
        "--proposal-id",
        proposal_id,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["base_digest"] == baseline_digest
    assert body["candidate_digest"] == proposed_digest
    assert body["unified"]

    code, body = _run_evo(
        capsys,
        "candidate",
        "evidence",
        "--proposal-id",
        proposal_id,
        "--config",
        str(config),
    )
    assert code == 0
    assert body == []  # no bundles yet — the command still round-trips

    # 8. release nominate: record the approval decision.
    code, body = _run_evo(
        capsys,
        "release",
        "nominate",
        "--campaign-id",
        campaign_id,
        "--proposal-id",
        proposal_id,
        "--decision",
        "nominate",
        "--reason",
        "pareto-dominant",
        "--config",
        str(config),
    )
    assert code == 0
    assert body["kind"] == "nominate"

    # 9. release qualify: the candidate's signed qualification outcome.
    code, body = _run_evo(
        capsys,
        "release",
        "qualify",
        "--artifact-digest",
        proposed_digest,
        "--outcome",
        "pass",
        "--metrics-file",
        metrics,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["artifact_digest"] == proposed_digest

    # 10. release canary -> promote -> rollback -> status.
    code, body = _run_evo(
        capsys,
        "release",
        "canary",
        "--artifact-digest",
        proposed_digest,
        "--adapter-versions",
        adapter_versions,
        "--model-routes",
        model_routes,
        "--policies",
        policies,
        "--config",
        str(config),
    )
    assert code == 0
    manifest_digest = body["manifest_digest"]
    assert body["status"] == "canary"

    code, body = _run_evo(
        capsys,
        "release",
        "promote",
        "--manifest-digest",
        manifest_digest,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["status"] == "active"

    code, body = _run_evo(
        capsys,
        "release",
        "rollback",
        "--manifest-digest",
        manifest_digest,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["status"] == "rolled_back"

    code, body = _run_evo(
        capsys,
        "release",
        "status",
        "--manifest-digest",
        manifest_digest,
        "--config",
        str(config),
    )
    assert code == 0
    assert body["status"] == "rolled_back"


def test_cli_reports_api_errors_as_exit_code_1(
    live_server: str, capsys: pytest.CaptureFixture[str], tmp_path: Path, tenant_id: str
) -> None:
    """A failing API call surfaces as a nonzero exit, never a silent 0."""
    config = tmp_path / "evo-config.json"
    _run_evo(
        capsys,
        "init",
        "--url",
        live_server,
        "--identity",
        "svc_evaluator_1",
        "--role",
        "evaluator",
        "--tenant",
        tenant_id,
        "--config",
        str(config),
    )
    capsys.readouterr()

    exit_code = cli_main(
        ["campaign", "inspect", "--campaign-id", "camp_missing", "--config", str(config)]
    )

    assert exit_code == 1
    assert "camp_missing" in capsys.readouterr().err
