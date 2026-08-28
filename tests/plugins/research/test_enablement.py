"""The §16.5 enablement invariant: both research plugins are disabled on
artifact classes without external correctness checks.

The gate is exercised over real subprocesses — a disabled plugin answers
with a structured JSON-RPC error and keeps serving, it never crashes.
"""

from __future__ import annotations

import pytest

from evoruntime.plugins.protocol import PluginMethodError
from tests.plugins.research.support import (
    RESEARCH_MODULE_NAMES,
    RESEARCH_PLUGIN_PARAMS,
    plugin_context,
    strategy_client,
)

#: Phase 1 text classes — correctness judged by models/humans, never by
#: sandboxed execution. Exactly the classes the plugins must refuse.
NON_EXECUTABLE_CLASSES = (
    "memory_entry",
    "prompt_bundle",
    "demonstration_set",
    "compiled_prompt_program",
    "skill_package",
)

#: Executable classes the plugins are enabled on (their own declared
#: class is exercised by the conformance suite; these prove the gate is
#: class-level, not plugin-hardcoded).
OTHER_EXECUTABLE_CLASSES = ("tool_spec", "skill_script", "harness_patch")


class TestDisabledOnNonExecutableCorrectness:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    @pytest.mark.parametrize("artifact_type", NON_EXECUTABLE_CLASSES)
    def test_initialize_refuses_with_a_structured_error(
        self, module_name: str, artifact_type: str
    ) -> None:
        client, _ = strategy_client(module_name)
        try:
            with pytest.raises(PluginMethodError, match="disabled for artifact class"):
                client.initialize(plugin_context(artifact_type, ("x/",)))
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    @pytest.mark.parametrize("artifact_type", NON_EXECUTABLE_CLASSES)
    def test_the_process_survives_refusal_and_still_serves(
        self, module_name: str, artifact_type: str
    ) -> None:
        client, _ = strategy_client(module_name)
        try:
            with pytest.raises(PluginMethodError):
                client.initialize(plugin_context(artifact_type, ("x/",)))
            # The same process still answers a well-formed initialize —
            # the refusal is a contract error, not a crash.
            declared = next(t for name, t, _ in RESEARCH_PLUGIN_PARAMS if name == module_name)
            state = client.initialize(plugin_context(declared, ("x/",)))
            assert state.data["artifact_type"] == declared
        finally:
            client.close()


class TestEnabledOnlyOnExecutableClasses:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_initialize_on_the_declared_executable_class_succeeds(self, module_name: str) -> None:
        artifact_type = next(t for name, t, _ in RESEARCH_PLUGIN_PARAMS if name == module_name)
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(plugin_context(artifact_type, ("x/",)))
            assert state.data["artifact_type"] == artifact_type
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    @pytest.mark.parametrize("artifact_type", OTHER_EXECUTABLE_CLASSES)
    def test_an_executable_but_undeclared_class_is_refused_on_type_grounds(
        self, module_name: str, artifact_type: str
    ) -> None:
        """Externally executable, but not what the plugin declares: the
        refusal names the type mismatch, not the enablement gate."""
        declared = next(t for name, t, _ in RESEARCH_PLUGIN_PARAMS if name == module_name)
        client, _ = strategy_client(module_name)
        try:
            with pytest.raises(PluginMethodError, match="declares"):
                client.initialize(plugin_context(artifact_type, ("x/",)))
            assert declared
        finally:
            client.close()


class TestGateUnit:
    def test_unknown_classes_fail_closed(self) -> None:
        from evoruntime.plugins.research.enablement import is_externally_executable

        assert is_externally_executable("not_a_real_class") is False
        assert is_externally_executable("") is False

    def test_every_executable_class_passes_the_gate(self) -> None:
        from evoruntime.plugins.manifest import EXECUTABLE_ARTIFACT_TYPES
        from evoruntime.plugins.research.enablement import is_externally_executable

        for artifact_type in EXECUTABLE_ARTIFACT_TYPES:
            assert is_externally_executable(artifact_type.value) is True

    def test_missing_artifact_type_is_a_contract_error(self) -> None:
        import pytest

        from evoruntime.plugins.protocol import PluginHandlerError
        from evoruntime.plugins.research.enablement import require_external_correctness

        with pytest.raises(PluginHandlerError, match="lacks an artifact_type"):
            require_external_correctness("plugin", {})
