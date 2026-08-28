"""Spawn-time resource-limit enforcement.

``ResourceLimits`` in the manifest was validated-but-inert in Phase 1; this
module is where ``cpu`` and ``memory_gib`` become physical. The limits are
applied with ``setrlimit`` in the child's pre-exec setup — before ``execve``
— so the candidate process is born inside its ceilings and cannot grow out
of them.

Mapping notes (documented, not hidden):

- ``memory_gib`` maps to ``RLIMIT_AS`` (address-space ceiling) — the
  classic resource-bomb stopper.
- ``cpu`` is declared in cores, but ``RLIMIT_CPU`` counts CPU-seconds. The
  physical ceiling a candidate cannot exceed is cores × wall-clock budget,
  so that product becomes the CPU-second limit.
- ``wall_clock_minutes`` is enforced by the executor's wait timeout (kill on
  expiry), not by an rlimit.
- ``model_tokens``/``proposals`` are evaluation-plane budgets, not spawn
  properties of a process; they stay with the harness (F6), not here.
"""

from __future__ import annotations

import math
import resource

from evoruntime.plugins.manifest import ResourceLimits

_GIBIBYTE = 1024**3
# A candidate has no business writing huge files or dumping cores.
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_OPEN_FILES = 256


def rlimit_configuration(limits: ResourceLimits) -> tuple[tuple[int, int, int], ...]:
    """Map manifest limits to ``(resource, soft, hard)`` triples.

    Pure: same limits in, same configuration out — which is what makes it
    unit-testable without spawning anything.
    """
    cpu_seconds = max(1, math.ceil(limits.cpu * limits.wall_clock_minutes * 60))
    address_space = int(limits.memory_gib * _GIBIBYTE)
    return (
        (resource.RLIMIT_AS, address_space, address_space),
        (resource.RLIMIT_CPU, cpu_seconds, cpu_seconds),
        (resource.RLIMIT_CORE, 0, 0),
        (resource.RLIMIT_FSIZE, _MAX_FILE_BYTES, _MAX_FILE_BYTES),
        (resource.RLIMIT_NOFILE, _MAX_OPEN_FILES, _MAX_OPEN_FILES),
    )


def apply_rlimits(limits: ResourceLimits) -> None:
    """Apply the configuration in the current process (the child, at spawn).

    Raises ``OSError`` (never silently continues) when the kernel refuses a
    limit — a limit that cannot be applied must abort the run, not degrade.
    """
    for res_id, soft, hard in rlimit_configuration(limits):
        resource.setrlimit(res_id, (soft, hard))
