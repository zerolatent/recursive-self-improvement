"""H7: transfer suite execution against the second harness and second model family.

The TransferSuite framework (F7) needed zero code changes; what it lacked
was fixture data: a second harness to point a CROSS_HARNESS family at and
a second model family behind `ChatCompletionClient` for CROSS_MODEL. Both
live in `tests/eval/h7_support.py`; the task set is the coding fixture
corpus with its H7 slice annotations, loaded through `fixtures.lib.slices`.
"""

from __future__ import annotations

from fixtures.lib.slices import coding_fixtures_to_eval_tasks

from evoruntime.eval import (
    InMemoryTaskSource,
    ScriptedAgent,
    SuiteFamily,
    TransferFamilyKind,
    TransferSuite,
    evaluated_transfer_scopes,
    run_transfer_suite,
)
from evoruntime.eval.backends import OpenAICompatibleBackend
from tests.eval.conftest import scripted_outcomes, three_arm_experiment
from tests.eval.h7_support import (
    DeterministicHarness,
    StaticSecretsProvider,
    StubChatCompletionClient,
)

BOOTSTRAP_ITERATIONS = 2_000
MODEL_API_KEY_SECRET = "EVORUNTIME_MODEL_API_KEY"


def _family(
    name: str, kind: TransferFamilyKind, *, harness_id: str, backend_id: str
) -> SuiteFamily:
    experiment = three_arm_experiment(
        name=f"exp-h7-{name}",
        dataset="ds_seed_coding_dev_v1",
        bootstrap_iterations=BOOTSTRAP_ITERATIONS,
    )
    return SuiteFamily(
        name=name,
        kind=kind,
        experiment=experiment,
        harness_id=harness_id,
        backend_id=backend_id,
    )


def _secrets() -> StaticSecretsProvider:
    return StaticSecretsProvider({MODEL_API_KEY_SECRET: "stub-key"})


def test_cross_harness_and_cross_model_families_evaluate() -> None:
    """Both H7 families run end-to-end over the annotated fixture corpus."""
    tasks = coding_fixtures_to_eval_tasks()
    assert len(tasks) >= 20

    suite = TransferSuite(
        name="h7-transfer",
        families=[
            _family(
                "xharness",
                TransferFamilyKind.CROSS_HARNESS,
                harness_id="alt-harness-v1",
                backend_id="scripted-harness-v1",
            ),
            _family(
                "xmodel",
                TransferFamilyKind.CROSS_MODEL,
                harness_id="fixture-agent-v1",
                backend_id="stub-model-family-b",
            ),
        ],
    )

    backends = {
        # CROSS_HARNESS: harness #1 (ScriptedAgent) vs harness #2
        # (DeterministicHarness) under the same arm structure.
        "xharness": {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, successes=len(tasks))),
            "retry": DeterministicHarness(solved_difficulties=("easy", "medium")),
            "one-shot": ScriptedAgent(scripted_outcomes(tasks, successes=len(tasks) // 2)),
        },
        # CROSS_MODEL: two model families behind ChatCompletionClient —
        # family-a completes every prompt, family-b has a shorter effective
        # context and fails on the longer issues.
        "xmodel": {
            "incumbent": OpenAICompatibleBackend(
                model="stub-family-a",
                client=StubChatCompletionClient(family="a"),
                secrets=_secrets(),
            ),
            "retry": OpenAICompatibleBackend(
                model="stub-family-b",
                client=StubChatCompletionClient(family="b", succeeds_up_to_chars=400),
                secrets=_secrets(),
            ),
            "one-shot": OpenAICompatibleBackend(
                model="stub-family-a",
                client=StubChatCompletionClient(family="a"),
                secrets=_secrets(),
            ),
        },
    }
    sources = {name: InMemoryTaskSource(tasks) for name in ("xharness", "xmodel")}

    result = run_transfer_suite(suite, backends=backends, task_sources=sources)

    assert not result.failed_families, [
        f"{outcome.family.name}: {outcome.error}" for outcome in result.failed_families
    ]
    assert evaluated_transfer_scopes(result) == ("xharness", "xmodel")
    for outcome in result.evaluated_families:
        assert outcome.result is not None
        assert outcome.result.task_ids, f"{outcome.family.name}: no task runs recorded"


def test_second_harness_differs_from_the_first() -> None:
    """The CROSS_HARNESS family's arms are two different harness implementations."""
    tasks = coding_fixtures_to_eval_tasks()
    scripted = ScriptedAgent(scripted_outcomes(tasks, successes=len(tasks)))
    alt = DeterministicHarness(solved_difficulties=("easy",))
    # Distinct implementations with distinct competence profiles: the scripted
    # harness succeeds everywhere, the alt harness only on easy tasks — and the
    # corpus has non-easy tasks, so the profiles genuinely differ.
    assert type(scripted) is not type(alt)
    assert any(task.metadata.get("difficulty") != "easy" for task in tasks)
