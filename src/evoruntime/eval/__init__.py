"""The evaluation harness (D6).

Runs preregistered experiment arms — incumbent, retry-self-consistency,
one-shot-control — under matched resource budgets on a dev partition, and
reports multi-seed variance plus paired-bootstrap intervals against the
incumbent. Nothing here reads sealed holdout content: a sealed partition
is refused at experiment construction and again at the task source.

The spec's contract is the package's front door::

    from evoruntime.eval import Arm, Experiment, run_experiment

    exp = Experiment(
        name="python-repair-baseline-2026-08",
        dataset="ds_repo_repair_dev_v1",
        task_budget_profile="task-budget-v1",
        arms=[
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.retry("retry"),
            Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL),
        ],
        seeds=3,
    )
    result = run_experiment(exp, backends=backends, task_source=source)
    result.primary   # per-arm success rate, cost, latency, seed variance
    result.delta     # paired bootstrap CI, multiplicity-adjusted

Module layout: `budgets` (the envelope and its meter), `tasks` (task and
run records), `experiment` (preregistration), `sources` (where tasks come
from, and the sealed-partition refusal), `backends` (what attempts a
task), `runner` (execution), `statistics` (bootstrap and multiplicity),
`results` (aggregation), `errors` (the failure taxonomy).
"""

from evoruntime.eval.backends import (
    CHARS_PER_TOKEN_ESTIMATE,
    DEFAULT_MODEL_API_KEY_SECRET,
    AgentBackend,
    AgentRequest,
    AgentResponse,
    AttemptCost,
    BernoulliScriptedAgent,
    ChatCompletionClient,
    ChatRequest,
    ChatResponse,
    EnvSecretsProvider,
    HttpChatCompletionClient,
    OpenAICompatibleBackend,
    ScriptedAgent,
    ScriptedStep,
    SecretsProvider,
    estimate_input_tokens,
    parse_chat_response,
    resolve_credential,
)
from evoruntime.eval.budgets import (
    BUDGET_PROFILES,
    TASK_BUDGET_V1,
    BudgetDimension,
    BudgetMeter,
    BudgetUsage,
    Clock,
    FrozenClock,
    MonotonicClock,
    TaskBudget,
    resolve_budget_profile,
)
from evoruntime.eval.errors import (
    BackendCredentialError,
    BackendRequestError,
    BudgetExceededError,
    EvalError,
    ExperimentDefinitionError,
    ScriptedAgentError,
    SealedPartitionError,
    StatisticsError,
    TaskSourceError,
    UnknownBudgetProfileError,
)
from evoruntime.eval.experiment import Arm, ArmKind, Experiment, derive_seed
from evoruntime.eval.results import (
    ArmComparison,
    ArmSummary,
    ExperimentResult,
    VarianceReport,
    summarize_experiment,
)
from evoruntime.eval.runner import ArmStrategy, run_arm, run_experiment, run_task, strategy_for
from evoruntime.eval.sources import (
    InMemoryTaskSource,
    PartitionTaskSource,
    TaskSource,
    load_jsonl_tasks,
)
from evoruntime.eval.statistics import (
    MIN_BOOTSTRAP_ITERATIONS,
    MultiplicityMethod,
    PairedBootstrapResult,
    Verdict,
    holm_adjusted_p_values,
    paired_bootstrap,
    per_comparison_alpha,
)
from evoruntime.eval.tasks import (
    AttemptRecord,
    ClaimedOutcomeVerifier,
    EvalTask,
    MajorityVoteVerifier,
    OutcomeVerifier,
    StopReason,
    TaskRun,
)

__all__ = [
    "BUDGET_PROFILES",
    "TASK_BUDGET_V1",
    "AgentBackend",
    "AgentRequest",
    "AgentResponse",
    "Arm",
    "ArmComparison",
    "ArmKind",
    "ArmStrategy",
    "ArmSummary",
    "AttemptCost",
    "AttemptRecord",
    "BackendCredentialError",
    "BackendRequestError",
    "BernoulliScriptedAgent",
    "BudgetDimension",
    "BudgetExceededError",
    "BudgetMeter",
    "BudgetUsage",
    "CHARS_PER_TOKEN_ESTIMATE",
    "ChatCompletionClient",
    "ChatRequest",
    "ChatResponse",
    "ClaimedOutcomeVerifier",
    "Clock",
    "DEFAULT_MODEL_API_KEY_SECRET",
    "EnvSecretsProvider",
    "EvalError",
    "EvalTask",
    "Experiment",
    "ExperimentDefinitionError",
    "ExperimentResult",
    "FrozenClock",
    "HttpChatCompletionClient",
    "InMemoryTaskSource",
    "MIN_BOOTSTRAP_ITERATIONS",
    "MajorityVoteVerifier",
    "MonotonicClock",
    "MultiplicityMethod",
    "OpenAICompatibleBackend",
    "OutcomeVerifier",
    "PairedBootstrapResult",
    "PartitionTaskSource",
    "ScriptedAgent",
    "ScriptedAgentError",
    "ScriptedStep",
    "SealedPartitionError",
    "SecretsProvider",
    "StatisticsError",
    "StopReason",
    "TaskBudget",
    "TaskRun",
    "TaskSource",
    "TaskSourceError",
    "UnknownBudgetProfileError",
    "VarianceReport",
    "Verdict",
    "derive_seed",
    "estimate_input_tokens",
    "holm_adjusted_p_values",
    "load_jsonl_tasks",
    "paired_bootstrap",
    "parse_chat_response",
    "per_comparison_alpha",
    "resolve_budget_profile",
    "resolve_credential",
    "run_arm",
    "run_experiment",
    "run_task",
    "strategy_for",
    "summarize_experiment",
]
