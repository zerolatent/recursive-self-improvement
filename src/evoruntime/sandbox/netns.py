"""Network-namespace isolation, applied where the host allows it.

The spec's locked decision: "a reference backend using subprocess + rlimits
+ network namespaces where the host allows". Creating a network namespace
needs ``CAP_SYS_ADMIN`` — directly, or indirectly via an unprivileged user
namespace (``CLONE_NEWUSER | CLONE_NEWNET`` in one ``unshare`` call). This
module probes for that capability and, when present, applies it in the
child's pre-exec setup as defense-in-depth on top of the seccomp filter.

Where the host does not allow namespaces (CI containers, hardened hosts),
the backend proceeds without the namespace — the seccomp socket filter is
the physical enforcement there — and the attestation records
``network_namespace: false`` so the degradation is visible, not silent.
"""

from __future__ import annotations

import os

_CLONE_NEWNET = 0x40000000
_CLONE_NEWUSER = 0x10000000

_probe_result: bool | None = None


def _try_unshare(flags: int) -> None:
    os.unshare(flags)


def _write_own_id_map() -> None:
    """Map the child's own uid/gid into the new user namespace.

    Without this the process runs as the overflow uid (65534) and loses
    access to the staged workspace it owns. Mapping only the process's own
    id is the unprivileged-allowed form; ``setgroups`` must be denied first.
    """
    with open("/proc/self/setgroups", "w", encoding="ascii") as setgroups:
        setgroups.write("deny")
    with open("/proc/self/uid_map", "w", encoding="ascii") as uid_map:
        uid_map.write(f"{os.getuid()} {os.getuid()} 1")
    with open("/proc/self/gid_map", "w", encoding="ascii") as gid_map:
        gid_map.write(f"{os.getgid()} {os.getgid()} 1")


def _probe() -> bool:
    """Fork a child that attempts the namespace dance; report success."""
    pid = os.fork()
    if pid == 0:
        try:
            try:
                _try_unshare(_CLONE_NEWUSER | _CLONE_NEWNET)
                _write_own_id_map()
            except OSError:
                # Root (or a privileged container) can unshare the netns
                # directly without a user namespace.
                _try_unshare(_CLONE_NEWNET)
        except OSError:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def netns_available() -> bool:
    """Whether this host allows creating an isolated network namespace."""
    global _probe_result
    if _probe_result is None:
        _probe_result = _probe()
    return _probe_result


def isolate_network_namespace() -> bool:
    """Move the current process into a fresh network namespace.

    Called from the child's pre-exec setup. Returns ``True`` when the
    namespace was created, ``False`` when the host forbids it (the caller
    records the degradation in the attestation). Unexpected errors other
    than the host refusing namespace creation propagate.
    """
    try:
        try:
            _try_unshare(_CLONE_NEWUSER | _CLONE_NEWNET)
            _write_own_id_map()
        except OSError:
            _try_unshare(_CLONE_NEWNET)
        return True
    except OSError:
        return False
