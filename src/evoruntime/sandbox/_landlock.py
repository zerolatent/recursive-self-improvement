"""Kernel-level filesystem containment (Landlock), applied at spawn.

Landlock (Linux 5.13+) is the unprivileged way to physically contain a
process's writes: the child installs a ruleset that handles the write-family
access rights and grants them only beneath the staged workspace root. After
``landlock_restrict_self`` — which survives ``execve`` — a write anywhere
else on the filesystem returns ``EACCES`` from the kernel. Reads and
execution are deliberately *not* handled, so the interpreter and its
standard library stay loadable while every write path is contained.

This is what makes the filesystem-escape escape-attempt a physical denial
rather than a convention the candidate is asked to honor.
"""

from __future__ import annotations

import ctypes
import os
import platform
from collections.abc import Sequence

# Landlock syscalls (Linux).
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

# Filesystem access rights (linux/landlock.h).
_LL_FS_EXECUTE = 1 << 0
_LL_FS_WRITE_FILE = 1 << 1
_LL_FS_READ_FILE = 1 << 2
_LL_FS_READ_DIR = 1 << 3
_LL_FS_REMOVE_DIR = 1 << 4
_LL_FS_REMOVE_FILE = 1 << 5
_LL_FS_MAKE_CHAR = 1 << 6
_LL_FS_MAKE_DIR = 1 << 7
_LL_FS_MAKE_REG = 1 << 8
_LL_FS_MAKE_SOCK = 1 << 9
_LL_FS_MAKE_FIFO = 1 << 10
_LL_FS_MAKE_BLOCK = 1 << 11
_LL_FS_MAKE_SYM = 1 << 12
_LL_FS_REFER = 1 << 13  # ABI 2
_LL_FS_TRUNCATE = 1 << 14  # ABI 3
_LL_FS_IOCTL_DEV = 1 << 15  # ABI 5

# Rights handled per ABI version — write-family bits ONLY (bits 1 and
# 4..12). EXECUTE, READ_FILE and READ_DIR are deliberately never handled so
# the interpreter and its standard library stay loadable from anywhere.
# ABI 2 added REFER (file reparenting is a write effect), ABI 3 added
# TRUNCATE, ABI 5 added IOCTL_DEV. ABI 4 added network handling, which we
# deliberately do not touch — egress is seccomp/proxy territory.
_ABI_RIGHTS: dict[int, int] = {
    1: 0x1FF2,  # WRITE_FILE + REMOVE_*/MAKE_* (bits 1, 4..12)
    2: 0x3FF2,  # + REFER
    3: 0x7FF2,  # + TRUNCATE
    4: 0x7FF2,
    5: 0xFFF2,  # + IOCTL_DEV
    6: 0xFFF2,
}


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def landlock_abi_version() -> int:
    """Return the kernel's Landlock ABI version, or 0 when unavailable."""
    if platform.system() != "Linux":
        return 0
    libc = _libc()
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_ulong, ctypes.c_uint]
    libc.syscall.restype = ctypes.c_long
    version = libc.syscall(_SYS_LANDLOCK_CREATE_RULESET, 0, 0, 1)  # VERSION flag
    if version < 1:
        return 0
    return int(version)


def landlock_available() -> bool:
    return landlock_abi_version() >= 1


def restrict_writes_to(writable_roots: Sequence[str | os.PathLike[str]]) -> None:
    """Contain the current process's writes to the given directory roots.

    Called from the child's pre-exec setup. The handled rights are the
    write-family bits the kernel supports; they are granted only beneath
    ``writable_roots`` and denied everywhere else. Reads and execution are
    left unhandled (unrestricted) so the interpreter keeps working.

    Raises ``OSError`` (never silently continues) when the kernel refuses
    any step — a containment that cannot be installed must abort the run.
    """
    abi = landlock_abi_version()
    if abi < 1:
        raise OSError("Landlock is not available on this kernel")
    handled = _ABI_RIGHTS.get(abi, _ABI_RIGHTS[max(_ABI_RIGHTS)])

    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int

    # landlock_create_ruleset(attr, size, flags)
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint]
    ruleset_attr = _LandlockRulesetAttr(handled)
    ruleset_fd = libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    try:
        # landlock_add_rule(ruleset_fd, rule_type, attr, flags)
        libc.syscall.argtypes = [
            ctypes.c_long,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint,
        ]
        for root in writable_roots:
            parent_fd = os.open(root, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = _LandlockPathBeneathAttr(handled, parent_fd)
                rc = libc.syscall(
                    _SYS_LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    _LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    0,
                )
                if rc != 0:
                    raise OSError(ctypes.get_errno(), f"landlock_add_rule failed for {root}")
            finally:
                os.close(parent_fd)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")
        # landlock_restrict_self(ruleset_fd, flags)
        libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_uint]
        if libc.syscall(_SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(ruleset_fd)
