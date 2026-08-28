"""A reference plugin implementing both §10.2 contracts over stdio JSON-RPC.

Run as a subprocess by the FR-004 conformance suite. Behavior is selected
with ``EVORUNTIME_PLUGIN_MODE``:

* ``conform`` — a well-behaved strategy + adapter.
* ``exact`` — proposes exactly the number of proposals the budget allows.
* ``over_budget`` — proposes one more proposal than the budget allows.
* ``hang`` — never answers (wall-clock enforcement test).
* ``bad_json`` — emits a non-JSON line (protocol violation test).
* ``die`` — exits immediately (process-death test).
* ``env_probe`` — echoes back the *names* of the environment variables it
  can see, so the clean-environment test asserts scrubbing end to end
  without ever printing a secret value.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
import time

from evoruntime.plugins.protocol import serve

MODE = os.environ.get("EVORUNTIME_PLUGIN_MODE", "conform")


class ConformingPlugin:
    """Minimal correct implementation of both contracts."""

    def initialize(self, context):
        return {"data": {"initialized": True, "artifact_type": context["artifact_type"]}}

    def propose(self, state, parents, evidence, budget):
        count = 1
        if MODE == "exact":
            count = int(budget["proposals_remaining"])
        elif MODE == "over_budget":
            count = int(budget["proposals_remaining"]) + 1
        return {
            "proposals": [
                {
                    "proposal_id": f"p{i}",
                    "artifact_type": "prompt_bundle",
                    "patch": {"op": "replace", "path": "prompt_bundle/system.md"},
                    "rationale": "reference proposal",
                }
                for i in range(count)
            ]
        }

    def observe(self, state, result):
        return {"data": {**state["data"], "observed": result["result_id"]}}

    def checkpoint(self, state):
        # Deliberately NOT valid JSON in any schema the runtime knows — the
        # runtime must store these bytes opaquely, never deserialize them.
        payload = b"\x00\x01plugin-native-checkpoint\x00\xff"
        return {
            "data_b64": base64.b64encode(payload).decode(),
            "schema_id": "reference-plugin/v1",
        }

    def validate(self, candidate):
        return {"accepted": True, "violations": []}

    def render(self, base, patch):
        content = base64.b64decode(base["data_b64"]) + b"\n# rendered\n"
        return {
            "data_b64": base64.b64encode(content).decode(),
            "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
            "media_type": "text/plain",
        }

    def semantic_diff(self, base, candidate):
        return {"unified": "--- base\n+++ candidate\n"}

    def fingerprint(self, candidate):
        raw = base64.b64decode(candidate["data_b64"])
        return {"value": f"sha256:{hashlib.sha256(raw).hexdigest()}"}


class EnvProbePlugin:
    def initialize(self, context):
        return {"data": {"env_var_names": sorted(os.environ)}}


def main() -> int:
    if MODE == "die":
        return 1
    if MODE == "bad_json":
        sys.stdout.write("this is not json\n")
        sys.stdout.flush()
        return 0
    if MODE == "hang":
        time.sleep(60)
        return 0
    handler = EnvProbePlugin() if MODE == "env_probe" else ConformingPlugin()
    serve(handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
