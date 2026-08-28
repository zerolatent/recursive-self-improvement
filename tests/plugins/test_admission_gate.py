"""FR-018 admission gate — unit behavior and purity."""

from __future__ import annotations

from evoruntime.plugins.admission import (
    ArchiveInfo,
    OutputEntry,
    OutputKind,
    ViolationCode,
    admit_output,
)


def entries(*items: OutputEntry) -> list[OutputEntry]:
    return list(items)


class TestHappyPath:
    def test_empty_bundle_admits(self) -> None:
        assert admit_output([]).admitted is True

    def test_clean_files_admit(self) -> None:
        decision = admit_output(
            entries(
                OutputEntry(path="prompt_bundle/system.md", size_bytes=2048),
                OutputEntry(path="tools/render.sh", size_bytes=128, executable=True),
            ),
            declared_executables=frozenset({"tools/render.sh"}),
        )
        assert decision.admitted is True
        assert decision.violations == ()


class TestPathShape:
    def test_parent_traversal_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="../../etc/passwd")))
        assert decision.admitted is False
        assert decision.violations[0].code is ViolationCode.PATH_TRAVERSAL

    def test_nested_traversal_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="docs/../../../etc/cron.d/evil")))
        assert decision.violations[0].code is ViolationCode.PATH_TRAVERSAL

    def test_absolute_path_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="/etc/cron.d/evil")))
        assert decision.violations[0].code is ViolationCode.ABSOLUTE_PATH

    def test_symlink_rejected(self) -> None:
        decision = admit_output(
            entries(OutputEntry(path="shadow_link", kind=OutputKind.SYMLINK, target="/etc/shadow"))
        )
        assert decision.violations[0].code is ViolationCode.SYMLINK

    def test_device_node_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="zero", kind=OutputKind.DEVICE)))
        assert decision.violations[0].code is ViolationCode.DEVICE_NODE


class TestResourceLimits:
    def test_archive_bomb_rejected(self) -> None:
        decision = admit_output(
            entries(
                OutputEntry(
                    path="bundle.zip",
                    size_bytes=40960,
                    archive=ArchiveInfo(uncompressed_total_bytes=4 * 1024**3),
                )
            )
        )
        assert decision.violations[0].code is ViolationCode.ARCHIVE_BOMB

    def test_oversized_file_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="huge.md", size_bytes=999_999_999)))
        assert decision.violations[0].code is ViolationCode.OVERSIZED_FILE

    def test_sparse_file_rejected(self) -> None:
        decision = admit_output(
            entries(OutputEntry(path="sparse.md", size_bytes=8 * 1024**3, sparse=True))
        )
        assert decision.violations[0].code is ViolationCode.SPARSE_FILE

    def test_bundle_total_cap(self) -> None:
        decision = admit_output(
            entries(
                OutputEntry(path="a.bin", size_bytes=6 * 1024**2),
                OutputEntry(path="b.bin", size_bytes=6 * 1024**2),
            ),
            max_total_bytes=10 * 1024**2,
        )
        assert decision.admitted is False
        assert any(v.path == "<bundle>" for v in decision.violations)


class TestExecutablesAndConfusables:
    def test_undeclared_executable_rejected(self) -> None:
        decision = admit_output(
            entries(OutputEntry(path="tools/helper", size_bytes=256, executable=True)),
            declared_executables=frozenset({"tools/render.sh"}),
        )
        assert decision.violations[0].code is ViolationCode.UNDECLARED_EXECUTABLE

    def test_cyrillic_homoglyph_of_protected_path_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="\u0455r\u0441/evil.txt")))
        assert decision.violations[0].code is ViolationCode.CONFUSABLE_PATH

    def test_zero_width_joiner_in_protected_path_rejected(self) -> None:
        decision = admit_output(entries(OutputEntry(path="tests\u200b/hidden.py")))
        assert decision.violations[0].code is ViolationCode.CONFUSABLE_PATH


class TestPurity:
    def test_same_input_same_verdict(self) -> None:
        batch = entries(
            OutputEntry(path="prompt_bundle/system.md", size_bytes=1024),
            OutputEntry(path="../escape", size_bytes=10),
        )
        first = admit_output(batch)
        second = admit_output(batch)
        assert first == second
        assert first.admitted is False

    def test_one_poisoned_entry_rejects_the_bundle(self) -> None:
        decision = admit_output(
            entries(
                OutputEntry(path="clean.md", size_bytes=10),
                OutputEntry(path="/absolute", size_bytes=10),
            )
        )
        assert decision.admitted is False
        assert len(decision.violations) == 1
