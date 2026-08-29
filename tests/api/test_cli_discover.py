"""CLI contract test for `evo campaign discover` (deliverable H3, §17.1 step 3).

§17.1 step 3 must be operable without Python: the operator runs `evo
campaign discover`, and the signed discovery report comes back as JSON.
This test spins up the real FastAPI app under uvicorn on an ephemeral port
wired to the test database, ingests failing traces over real HTTP, then
drives discovery through the CLI exactly as a CI job would — the same
pattern as `tests/api/test_cli_e2e.py`, scoped to the discover subcommand.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
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
from tests.support.factories import make_raw_event


@pytest.fixture
def live_server(session_factory: sessionmaker[Any], monkeypatch: pytest.MonkeyPatch) -> Any:
    """The real app served by uvicorn on an ephemeral localhost port."""
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


def _headers(tenant_id: str) -> dict[str, str]:
    return {
        "x-evoruntime-identity": "svc_evaluator_1",
        "x-evoruntime-role": "evaluator",
        "x-evoruntime-tenant": tenant_id,
    }


def _ingest_failed_trace(base_url: str, tenant_id: str) -> None:
    """One failed trace over real HTTP: failing shell call + not-ok end."""
    headers = _headers(tenant_id)
    tool = httpx.post(
        f"{base_url}/v1/payloads",
        params={"classification": "internal"},
        content=json.dumps({"name": "shell", "ok": False}).encode(),
        headers=headers,
    )
    assert tool.status_code == 201, tool.text
    end = httpx.post(
        f"{base_url}/v1/payloads",
        params={"classification": "internal"},
        content=json.dumps({"ok": False}).encode(),
        headers=headers,
    )
    assert end.status_code == 201, end.text

    trace_id = f"trc_{uuid.uuid4().hex[:12]}"
    events = [
        make_raw_event(0, tenant_id=tenant_id, trace_id=trace_id, event_type="tool.completed"),
        make_raw_event(1, tenant_id=tenant_id, trace_id=trace_id, event_type="trace.ended"),
    ]
    events[0]["payload_digest"] = tool.json()["payload_digest"]
    events[1]["payload_digest"] = end.json()["payload_digest"]
    ingested = httpx.post(f"{base_url}/v1/events:ingest", json={"events": events}, headers=headers)
    assert ingested.status_code == 200, ingested.text


def _init_config(
    capsys: pytest.CaptureFixture[str], live_server: str, tmp_path: Path, tenant_id: str
) -> Path:
    """`evo init` against the live server; returns the config path."""
    config = tmp_path / "evo-config.json"
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
    return config


def test_cli_campaign_discover_emits_a_signed_report(
    live_server: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    tenant_id: str,
) -> None:
    config = _init_config(capsys, live_server, tmp_path, tenant_id)

    # Seed one failed trace through the real write paths.
    _ingest_failed_trace(live_server, tenant_id)

    # The contract under test: discovery operable without Python.
    code, report = _run_evo(capsys, "campaign", "discover", "--config", str(config))
    assert code == 0
    assert report["traces_scanned"] == 1
    assert report["failure_count"] == 1
    assert report["categories_hit"] == ["dependency_misuse"]
    assert report["report_digest"].startswith("sha256:")
    assert report["signature_b64"]
    assert report["signer_public_key_b64"]

    # A second run over unchanged traces re-signs the same digest and
    # serves the already-signed report (idempotent persistence).
    code, rerun = _run_evo(capsys, "campaign", "discover", "--config", str(config))
    assert code == 0
    assert rerun["report_digest"] == report["report_digest"]
    assert rerun["report_id"] == report["report_id"]


def test_cli_campaign_discover_scopes_by_agent(
    live_server: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    tenant_id: str,
) -> None:
    config = _init_config(capsys, live_server, tmp_path, tenant_id)

    _ingest_failed_trace(live_server, tenant_id)

    code, report = _run_evo(
        capsys, "campaign", "discover", "--agent-id", "agt_test", "--config", str(config)
    )
    assert code == 0
    assert report["agent_id"] == "agt_test"
    assert report["traces_scanned"] == 1

    code, scoped = _run_evo(
        capsys, "campaign", "discover", "--agent-id", "agt_absent", "--config", str(config)
    )
    assert code == 0
    assert scoped["traces_scanned"] == 0
    assert scoped["clusters"] == []
