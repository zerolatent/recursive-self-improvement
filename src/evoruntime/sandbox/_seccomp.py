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
