"""The `evo` CLI — thin wrappers over the FR-014 control-plane API.

This is the CI/CD concept doc's (§3, §10.1) authoritative early
interface, and it stays thin by construction: every command parses
arguments, resolves connection config, makes exactly one (or, for
`candidate evidence`, two) client calls, and prints the JSON response.
No business logic lives here — lifecycle rules, signing, and tenant
scoping are all server-side, so the CLI can never do more than the API
allows.

`evo init` writes the connection profile (URL + workload identity) that
every other command reads; environment variables override it so CI jobs
never need a config file checked in.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from evoruntime.api.client import EvoApiClient, EvoApiError

DEFAULT_CONFIG_PATH = Path.home() / ".evo" / "config.json"

_ENV_OVERRIDES = {
    "url": "EVO_URL",
    "identity": "EVO_IDENTITY",
    "role": "EVO_ROLE",
    "tenant": "EVO_TENANT",
}


def load_config(config_path: str | None) -> dict[str, str]:
    """Resolve the connection profile: config file, then env overrides.

    Environment wins over the file — a CI job points `EVO_URL` at its own
    plane without touching any checked-in state.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    config: dict[str, str] = {}
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            config = {str(k): str(v) for k, v in raw.items() if k in _ENV_OVERRIDES}
    for key, env_name in _ENV_OVERRIDES.items():
        value = os.environ.get(env_name)
        if value:
            config[key] = value
    missing = sorted(set(_ENV_OVERRIDES) - set(config))
    if missing:
        raise SystemExit(
            f"evo is not configured: missing {', '.join(missing)}. "
            "Run `evo init` or set the EVO_* environment variables."
        )
    return config


def build_client(config_path: str | None) -> EvoApiClient:
    """Build the API client from the resolved connection profile."""
    config = load_config(config_path)
    return EvoApiClient(
        config["url"],
        identity=config["identity"],
        role=config["role"],
        tenant=config["tenant"],
    )


def _read_json_file(path: str) -> dict[str, Any]:
    """Load a JSON document from disk (spec and metrics files)."""
    return dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _print(payload: Any) -> None:
    """Print a JSON result — the CLI's only output format."""
    print(json.dumps(payload, indent=2, sort_keys=True))


# ----------------------------------------------------------------------
# command handlers — each is one client call (or two for `evidence`)
# ----------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Write the connection profile used by every other command."""
    config = {
        "url": args.url,
        "identity": args.identity,
        "role": args.role,
        "tenant": args.tenant,
    }
    path = Path(args.config) if args.config else DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
    _print({"config_path": str(path), **config})
    return 0


def cmd_agent_register(args: argparse.Namespace) -> int:
    """Register an agent plugin."""
    with build_client(args.config) as client:
        result = client.register_agent(
            plugin_id=args.plugin_id,
            kind=args.kind,
            pinned_image=args.pinned_image,
            artifact_types=args.artifact_types.split(",") if args.artifact_types else [],
            agent_id=args.agent_id,
        )
    _print(result)
    return 0


def cmd_eval_baseline(args: argparse.Namespace) -> int:
    """Record the baseline (or any) evaluation outcome for an artifact."""
    metrics = _read_json_file(args.metrics_file)
    with build_client(args.config) as client:
        result = client.record_evaluation(
            artifact_digest=args.artifact_digest,
            outcome=args.outcome,
            metrics=metrics,
        )
    _print(result)
    return 0


def cmd_campaign_plan(args: argparse.Namespace) -> int:
    """Plan a campaign: validate, pin, and sign its spec."""
    spec = _read_json_file(args.spec_file)
    with build_client(args.config) as client:
        result = client.create_campaign(spec)
    _print(result)
    return 0


def cmd_campaign_run(args: argparse.Namespace) -> int:
    """Run a campaign one lifecycle step (pause/cancel/resume included)."""
    with build_client(args.config) as client:
        result = client.transition_campaign(args.campaign_id, args.to_phase, reason=args.reason)
    _print(result)
    return 0


def cmd_campaign_inspect(args: argparse.Namespace) -> int:
    """Inspect a campaign — detail, or its Pareto comparison."""
    with build_client(args.config) as client:
        if args.pareto:
            result = client.campaign_pareto(args.campaign_id)
        else:
            result = client.get_campaign(args.campaign_id)
    _print(result)
    return 0


def cmd_release_nominate(args: argparse.Namespace) -> int:
    """Record the approval decision that nominates a candidate."""
    with build_client(args.config) as client:
        result = client.record_approval(
            campaign_id=args.campaign_id,
            proposal_id=args.proposal_id,
            decision=args.decision,
            reason=args.reason,
        )
    _print(result)
    return 0


def cmd_release_qualify(args: argparse.Namespace) -> int:
    """Qualify a candidate: record its signed evaluation outcome."""
    metrics = _read_json_file(args.metrics_file)
    with build_client(args.config) as client:
        result = client.record_evaluation(
            artifact_digest=args.artifact_digest,
            outcome=args.outcome,
            metrics=metrics,
        )
    _print(result)
    return 0


def cmd_release_canary(args: argparse.Namespace) -> int:
    """Create a canary release from approved artifacts."""
    with build_client(args.config) as client:
        result = client.create_release(
            artifact_digests=args.artifact_digest.split(","),
            adapter_versions=_read_json_file(args.adapter_versions),
            model_routes=_read_json_file(args.model_routes),
            policies=_read_json_file(args.policies),
            prior_release_digest=args.prior_release_digest,
            status="canary",
        )
    _print(result)
    return 0


def cmd_release_promote(args: argparse.Namespace) -> int:
    """Promote a canary release to active."""
    with build_client(args.config) as client:
        result = client.promote_release(args.manifest_digest)
    _print(result)
    return 0


def cmd_release_rollback(args: argparse.Namespace) -> int:
    """Roll a release back to its prior release."""
    with build_client(args.config) as client:
        result = client.rollback_release(args.manifest_digest)
    _print(result)
    return 0


def cmd_release_status(args: argparse.Namespace) -> int:
    """Show a release's rollback status."""
    with build_client(args.config) as client:
        result = client.rollback_status(args.manifest_digest)
    _print(result)
    return 0


def cmd_approval_request(args: argparse.Namespace) -> int:
    """Open a review-board request (tier-3 promotion or privileged admission)."""
    with build_client(args.config) as client:
        result = client.create_approval_request(
            kind=args.kind,
            justification=args.justification,
            campaign_id=args.campaign_id,
            proposal_id=args.proposal_id,
            plugin_id=args.plugin_id,
            content_digest=args.content_digest,
            privileged_role=args.privileged_role,
        )
    _print(result)
    return 0


def cmd_approval_decide(args: argparse.Namespace) -> int:
    """Record one review-board decision as the verified caller."""
    with build_client(args.config) as client:
        result = client.decide_approval_request(
            args.request_id, decision=args.decision, note=args.note
        )
    _print(result)
    return 0


def cmd_approval_status(args: argparse.Namespace) -> int:
    """Show a review-board request with its recorded decisions."""
    with build_client(args.config) as client:
        result = client.get_approval_request(args.request_id)
    _print(result)
    return 0


def cmd_campaign_discover(args: argparse.Namespace) -> int:
    """Cluster trace failures into a signed discovery report (H3)."""
    with build_client(args.config) as client:
        result = client.run_discovery(
            campaign_id=args.campaign_id,
            agent_id=args.agent_id,
            release_id=args.release_id,
        )
    _print(result)
    return 0


def cmd_candidate_diff(args: argparse.Namespace) -> int:
    """Show a candidate's semantic diff against its parent."""
    with build_client(args.config) as client:
        result = client.candidate_diff(args.proposal_id)
    _print(result)
    return 0


def cmd_candidate_evidence(args: argparse.Namespace) -> int:
    """List evidence bundles attached to a candidate's artifact."""
    with build_client(args.config) as client:
        candidate = client.get_candidate(args.proposal_id)
        result = client.list_evidence(artifact_digest=candidate["artifact_digest"])
    _print(result)
    return 0


# ----------------------------------------------------------------------
# parser wiring
# ----------------------------------------------------------------------


def _add_config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="path to the evo config file (default ~/.evo/config.json)")


def build_parser() -> argparse.ArgumentParser:
    """Build the full `evo` argument parser."""
    parser = argparse.ArgumentParser(
        prog="evo", description="EvoRuntime control-plane CLI (thin API wrappers)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="write the connection profile")
    init.add_argument("--url", required=True, help="evaluation-plane base URL")
    init.add_argument("--identity", required=True, help="workload identity subject")
    init.add_argument("--role", required=True, help="workload role")
    init.add_argument("--tenant", required=True, help="tenant id")
    init.set_defaults(func=cmd_init)
    _add_config_arg(init)

    agent = sub.add_parser("agent", help="agent registration")
    agent_sub = agent.add_subparsers(required=True)
    agent_register = agent_sub.add_parser("register", help="register an agent plugin")
    agent_register.add_argument("--plugin-id", required=True)
    agent_register.add_argument("--kind", required=True, choices=["strategy", "adapter"])
    agent_register.add_argument("--pinned-image", required=True)
    agent_register.add_argument("--artifact-types", required=True, help="comma-separated")
    agent_register.add_argument("--agent-id", default=None)
    agent_register.set_defaults(func=cmd_agent_register)
    _add_config_arg(agent_register)

    eval_cmd = sub.add_parser("eval", help="evaluation outcomes")
    eval_sub = eval_cmd.add_subparsers(required=True)
    baseline = eval_sub.add_parser("baseline", help="record a signed evaluation outcome")
    baseline.add_argument("--artifact-digest", required=True)
    baseline.add_argument("--outcome", required=True, choices=["pass", "fail"])
    baseline.add_argument("--metrics-file", required=True, help="JSON file of metrics")
    baseline.set_defaults(func=cmd_eval_baseline)
    _add_config_arg(baseline)

    campaign = sub.add_parser("campaign", help="campaign lifecycle")
    campaign_sub = campaign.add_subparsers(required=True)
    plan = campaign_sub.add_parser("plan", help="validate, pin, and sign a campaign spec")
    plan.add_argument("--spec-file", required=True, help="JSON file with the campaign spec")
    plan.set_defaults(func=cmd_campaign_plan)
    _add_config_arg(plan)

    run = campaign_sub.add_parser("run", help="move a campaign one lifecycle step")
    run.add_argument("--campaign-id", required=True)
    run.add_argument("--to-phase", required=True)
    run.add_argument("--reason", default="")
    run.set_defaults(func=cmd_campaign_run)
    _add_config_arg(run)

    inspect = campaign_sub.add_parser("inspect", help="inspect a campaign")
    inspect.add_argument("--campaign-id", required=True)
    inspect.add_argument("--pareto", action="store_true", help="show the Pareto comparison")
    inspect.set_defaults(func=cmd_campaign_inspect)
    _add_config_arg(inspect)

    discover = campaign_sub.add_parser(
        "discover", help="cluster trace failures into a signed discovery report (H3)"
    )
    discover.add_argument("--campaign-id", help="scope clustering to one campaign")
    discover.add_argument("--agent-id", help="scope clustering to one agent")
    discover.add_argument("--release-id", help="scope clustering to one release")
    discover.set_defaults(func=cmd_campaign_discover)
    _add_config_arg(discover)

    release = sub.add_parser("release", help="release lifecycle")
    release_sub = release.add_subparsers(required=True)

    nominate = release_sub.add_parser("nominate", help="record an approval decision")
    nominate.add_argument("--campaign-id", required=True)
    nominate.add_argument("--proposal-id", required=True)
    nominate.add_argument(
        "--decision", default="nominate", choices=["nominate", "reject", "quarantine", "revoke"]
    )
    nominate.add_argument("--reason", default=None)
    nominate.set_defaults(func=cmd_release_nominate)
    _add_config_arg(nominate)

    qualify = release_sub.add_parser("qualify", help="record the signed qualification outcome")
    qualify.add_argument("--artifact-digest", required=True)
    qualify.add_argument("--outcome", default="pass", choices=["pass", "fail"])
    qualify.add_argument("--metrics-file", required=True, help="JSON file of metrics")
    qualify.set_defaults(func=cmd_release_qualify)
    _add_config_arg(qualify)

    canary = release_sub.add_parser("canary", help="create a canary release")
    canary.add_argument("--artifact-digest", required=True, help="comma-separated digests")
    canary.add_argument("--adapter-versions", required=True, help="JSON file")
    canary.add_argument("--model-routes", required=True, help="JSON file")
    canary.add_argument("--policies", required=True, help="JSON file")
    canary.add_argument("--prior-release-digest", default=None)
    canary.set_defaults(func=cmd_release_canary)
    _add_config_arg(canary)

    promote = release_sub.add_parser("promote", help="promote a canary release to active")
    promote.add_argument("--manifest-digest", required=True)
    promote.set_defaults(func=cmd_release_promote)
    _add_config_arg(promote)

    rollback = release_sub.add_parser("rollback", help="roll a release back")
    rollback.add_argument("--manifest-digest", required=True)
    rollback.set_defaults(func=cmd_release_rollback)
    _add_config_arg(rollback)

    status = release_sub.add_parser("status", help="show a release's rollback status")
    status.add_argument("--manifest-digest", required=True)
    status.set_defaults(func=cmd_release_status)
    _add_config_arg(status)

    approval = sub.add_parser("approval", help="review-board approval workflow (F10)")
    approval_sub = approval.add_subparsers(required=True)

    approval_request = approval_sub.add_parser("request", help="open a review-board request")
    approval_request.add_argument(
        "--kind", required=True, choices=["tier3_promotion", "privileged_admission"]
    )
    approval_request.add_argument(
        "--justification", required=True, help="why review-board approval is needed"
    )
    approval_request.add_argument("--campaign-id", default=None)
    approval_request.add_argument("--proposal-id", default=None)
    approval_request.add_argument("--plugin-id", default=None)
    approval_request.add_argument("--content-digest", default=None)
    approval_request.add_argument("--privileged-role", default=None)
    approval_request.set_defaults(func=cmd_approval_request)
    _add_config_arg(approval_request)

    approval_decide = approval_sub.add_parser(
        "decide", help="record one decision as the verified caller"
    )
    approval_decide.add_argument("--request-id", required=True)
    approval_decide.add_argument("--decision", required=True, choices=["approve", "reject"])
    approval_decide.add_argument("--note", default="")
    approval_decide.set_defaults(func=cmd_approval_decide)
    _add_config_arg(approval_decide)

    approval_status = approval_sub.add_parser(
        "status", help="show a request with its recorded decisions"
    )
    approval_status.add_argument("--request-id", required=True)
    approval_status.set_defaults(func=cmd_approval_status)
    _add_config_arg(approval_status)

    candidate = sub.add_parser("candidate", help="candidate inspection")
    candidate_sub = candidate.add_subparsers(required=True)
    diff = candidate_sub.add_parser("diff", help="semantic diff against the parent")
    diff.add_argument("--proposal-id", required=True)
    diff.set_defaults(func=cmd_candidate_diff)
    _add_config_arg(diff)

    evidence = candidate_sub.add_parser("evidence", help="evidence for a candidate's artifact")
    evidence.add_argument("--proposal-id", required=True)
    evidence.set_defaults(func=cmd_candidate_evidence)
    _add_config_arg(evidence)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse, dispatch, print JSON, and map errors to exits."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (EvoApiError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"evo: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
