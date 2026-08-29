"""Kernel-level network syscall filter (seccomp-BPF), applied at spawn.

This is the physical half of egress enforcement for tiers that run with no
network: the filter is installed in the child before ``execve`` and survives
it, so a candidate that dials a non-Unix socket gets ``EPERM`` from the
kernel — not an advisory warning from the runtime.

The filter is deliberately narrow: it gates ``socket()`` by address family.
Everything else is allowed, because the address family is the chokepoint —
once ``socket(AF_INET, ...)`` is impossible, no connect/sendto path to the
network exists (the child inherits no network file descriptors).
"""

from __future__ import annotations

import ctypes
import os
import platform
from collections.abc import Sequence

# prctl(2) and seccomp(2) constants (Linux).
_PR_SET_NO_NEW_PRIVS = 38
_SECCOMP_SET_MODE_FILTER = 1
# SYS_seccomp differs per architecture.
_SYS_SECCOMP = {"x86_64": 317, "aarch64": 277}
# AUDIT_ARCH_* values carried in seccomp_data.arch.
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7
# __NR_socket per architecture.
_NR_SOCKET = {"x86_64": 41, "aarch64": 198}

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1

# seccomp_data field offsets: { int nr; u32 arch; u64 ip; u64 args[6]; }
_OFF_NR = 0
_OFF_ARCH = 4
_OFF_ARGS0 = 16

# Classic-BPF instruction classes used below.
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06


class _BpfInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(_BpfInsn))]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _machine() -> str:
    return platform.machine()


def _arch_token() -> int:
    machine = _machine()
    if machine == "x86_64":
        return _AUDIT_ARCH_X86_64
    if machine == "aarch64":
        return _AUDIT_ARCH_AARCH64
    raise RuntimeError(f"unsupported architecture for seccomp: {machine}")


def _socket_syscall_nr() -> int:
    machine = _machine()
    if machine not in _NR_SOCKET:
        raise RuntimeError(f"unsupported architecture for seccomp: {machine}")
    return _NR_SOCKET[machine]


def _build_socket_domain_filter(allowed_domains: frozenset[int]) -> list[_BpfInsn]:
    """Compile the BPF program: allow ``socket()`` only for listed domains.

    Layout (indices matter — the jumps are computed against them):
        0        ld   [arch]
        1        jeq  AUDIT_ARCH     -> continue, else ALLOW
        2        ld   [nr]
        3        jeq  __NR_socket    -> continue, else ALLOW
        4        ld   [args[0]]      (the requested address family)
        5..4+A   jeq  domain_i       -> ALLOW, else next (last: ERRNO)
        5+A      ret  ERRNO(EPERM)
        6+A      ret  ALLOW
    """
    arch = _arch_token()
    nr_socket = _socket_syscall_nr()
    a = len(allowed_domains)
    domains = sorted(allowed_domains)
    allow_idx = 6 + a

    program: list[_BpfInsn] = []
    program.append(_BpfInsn(_BPF_LD_W_ABS, 0, 0, _OFF_ARCH))
    # arch mismatch: the syscall table below cannot be trusted — allow (the
    # attestation records which filter was applied; an unknown arch means
    # this host is outside the reference backend's contract).
    program.append(_BpfInsn(_BPF_JMP_JEQ_K, 0, allow_idx - 2, arch))
    program.append(_BpfInsn(_BPF_LD_W_ABS, 0, 0, _OFF_NR))
    program.append(_BpfInsn(_BPF_JMP_JEQ_K, 0, allow_idx - 4, nr_socket))
    program.append(_BpfInsn(_BPF_LD_W_ABS, 0, 0, _OFF_ARGS0))
    for i, domain in enumerate(domains):
        # jt is relative to the *next* instruction (index 5+i → next is
        # 6+i); ALLOW sits at 6+a, so jt = a - i. jf = 0 falls through to
        # the next domain check, or (last) to the ERRNO return below.
        program.append(_BpfInsn(_BPF_JMP_JEQ_K, a - i, 0, domain))
    program.append(_BpfInsn(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    program.append(_BpfInsn(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    return program


def _install_filter(program: list[_BpfInsn]) -> None:
    libc = _libc()
    array = (_BpfInsn * len(program))(*program)
    fprog = _SockFprog(len(program), array)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
    libc.syscall.argtypes = [
        ctypes.c_long,
        ctypes.c_long,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    libc.syscall.restype = ctypes.c_long
    machine = _machine()
    if machine not in _SYS_SECCOMP:
        raise RuntimeError(f"unsupported architecture for seccomp: {machine}")
    rc = libc.syscall(_SYS_SECCOMP[machine], _SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog))
    if rc != 0:
        raise OSError(ctypes.get_errno(), "seccomp(SECCOMP_SET_MODE_FILTER) failed")


# Escalation-primitive syscalls denied on the HIGHEST tier (G5): the
# primitives a candidate would need to escape containment, escalate
# privilege, or tamper with the host kernel — ptrace (process injection),
# mount/pivot_root/umount2 (filesystem reconfiguration), the keyring and
# module-loading families, BPF, kexec, handle-based open (bypasses mount
# namespacing), and namespace re-entry (unshare/setns). Numbers verified
# against the kernel UAPI tables per architecture (x86_64:
# arch/x86/entry/syscalls/syscall_64.tbl; arm64: the asm-generic table).
_NR_DENIED_SYSCALLS: dict[str, dict[str, int]] = {
    "x86_64": {
        "ptrace": 101,
        "pivot_root": 155,
        "_sysctl": 156,
        "mount": 165,
        "umount2": 166,
        "swapon": 167,
        "swapoff": 168,
        "iopl": 172,
        "ioperm": 173,
        "create_module": 174,
        "init_module": 175,
        "delete_module": 176,
        "get_kernel_syms": 177,
        "query_module": 178,
        "nfsservctl": 180,
        "lookup_dcookie": 212,
        "kexec_load": 246,
        "add_key": 248,
        "request_key": 249,
        "keyctl": 250,
        "unshare": 272,
        "perf_event_open": 298,
        "name_to_handle_at": 303,
        "open_by_handle_at": 304,
        "setns": 308,
        "finit_module": 313,
        "kexec_file_load": 320,
        "bpf": 321,
    },
    "aarch64": {
        "umount2": 39,
        "mount": 40,
        "pivot_root": 41,
        "unshare": 97,
        "kexec_load": 104,
        "init_module": 105,
        "delete_module": 106,
        "ptrace": 117,
        "perf_event_open": 241,
        "add_key": 217,
        "request_key": 218,
        "keyctl": 219,
        "bpf": 280,
        "name_to_handle_at": 264,
        "open_by_handle_at": 265,
        "setns": 268,
        "finit_module": 273,
        "kexec_file_load": 294,
    },
}

# Canonical denylist, ordered for stable attestations. Names present on
# every supported architecture only — the legacy x86-only calls
# (create_module, iopl, …) are enforced per-arch but not listed here.
HIGHEST_DENIED_SYSCALLS: tuple[str, ...] = (
    "ptrace",
    "mount",
    "umount2",
    "pivot_root",
    "swapon",
    "swapoff",
    "keyctl",
    "add_key",
    "request_key",
    "bpf",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "open_by_handle_at",
    "name_to_handle_at",
    "unshare",
    "setns",
    "perf_event_open",
)


def syscall_denylist_supported() -> bool:
    """Whether this architecture has a verified denylist table.

    HIGHEST demands the denylist; an unlisted architecture must refuse the
    tier rather than run it without the filter (fail closed).
    """
    return _machine() in _NR_DENIED_SYSCALLS


def _denylist_numbers(names: Sequence[str]) -> list[int]:
    """Resolve denylist names to the current architecture's syscall numbers.

    Pure lookup: an unknown name or unsupported architecture raises instead
    of silently narrowing the denylist.
    """
    machine = _machine()
    table = _NR_DENIED_SYSCALLS.get(machine)
    if table is None:
        raise RuntimeError(f"unsupported architecture for seccomp: {machine}")
    missing = [name for name in names if name not in table]
    if missing:
        raise RuntimeError(f"no syscall number for {missing} on {machine}")
    return sorted(table[name] for name in names)


def build_syscall_denylist_filter(names: Sequence[str]) -> list[_BpfInsn]:
    """Compile the BPF program: return EPERM for every listed syscall.

    Layout (indices matter — the jumps are computed against them):
        0        ld   [arch]
        1        jeq  AUDIT_ARCH     -> continue, else ALLOW
        2        ld   [nr]
        3..2+N   jeq  nr_i           -> ERRNO, else next (last: fall through)
        3+N      ret  ERRNO(EPERM)
        4+N      ret  ALLOW
    """
    arch = _arch_token()
    numbers = _denylist_numbers(names)
    n = len(numbers)

    program: list[_BpfInsn] = []
    program.append(_BpfInsn(_BPF_LD_W_ABS, 0, 0, _OFF_ARCH))
    # arch mismatch: the syscall table below cannot be trusted — allow (the
    # attestation records which filter was applied; an unknown arch means
    # this host is outside the reference backend's contract).
    program.append(_BpfInsn(_BPF_JMP_JEQ_K, 0, 2 + n, arch))
    program.append(_BpfInsn(_BPF_LD_W_ABS, 0, 0, _OFF_NR))
    for i, nr in enumerate(numbers):
        # jt is relative to the *next* instruction (index 3+i → next is
        # 4+i); ERRNO sits at 3+n, so jt = n - i - 1. jf = 0 falls through
        # to the next check — except the last, whose no-match must skip the
        # ERRNO return and land on ALLOW (4+n), so jf = 1 there.
        program.append(_BpfInsn(_BPF_JMP_JEQ_K, n - i - 1, 1 if i == n - 1 else 0, nr))
    program.append(_BpfInsn(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    program.append(_BpfInsn(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    return program


def apply_syscall_denylist(names: Sequence[str]) -> None:
    """Install the syscall denylist filter in the *current* process.

    Called from the child's pre-exec setup; the filter survives ``execve``
    because ``PR_SET_NO_NEW_PRIVS`` is set first. Stacks with any filter
    installed earlier — the kernel enforces the most restrictive return
    across all attached filters. Raises ``OSError`` (never silently
    continues) when the kernel refuses the filter.
    """
    _install_filter(build_syscall_denylist_filter(names))


def apply_network_socket_filter(allowed_domains: frozenset[int]) -> None:
    """Install the socket-domain filter in the *current* process.

    Called from the child's pre-exec setup; the filter survives ``execve``
    because ``PR_SET_NO_NEW_PRIVS`` is set first. Raises ``OSError`` (never
    silently continues) when the kernel refuses the filter.
    """
    _install_filter(_build_socket_domain_filter(allowed_domains))


def seccomp_available() -> bool:
    """Probe whether this platform can install a seccomp filter.

    The probe runs in a forked child so the pytest/runtime process never
    carries a lingering filter of its own.
    """
    machine = _machine()
    if machine not in _SYS_SECCOMP or machine not in _NR_SOCKET:
        return False
    pid = os.fork()
    if pid == 0:
        try:
            _install_filter([_BpfInsn(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW)])
        except Exception:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0
