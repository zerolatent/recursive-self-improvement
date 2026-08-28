"""Errors raised by the artifact registry's service boundary.

Each FR-003 rejection path has its own error type so callers (and tests)
can assert on the *reason* an activation or registration was refused, not
just that something went wrong.
"""

from __future__ import annotations


class RegistryError(Exception):
    """Base class for artifact-registry errors."""


class ArtifactNotFoundError(RegistryError):
    """Raised when a digest does not resolve to a registered artifact."""


class DigestMismatchError(RegistryError):
    """Raised when recomputed bytes do not match a claimed digest — either at
    registration (the caller claimed a digest the body doesn't hash to) or at
    read time (stored bytes no longer hash to the recorded digest, i.e.
    tampering or corruption)."""


class UnsignedActivationError(RegistryError):
    """Raised when a release manifest cannot be activated because its
    signature is missing or does not verify over its canonical bytes."""


class CircularMetadataError(RegistryError):
    """Raised when metadata would reference itself: an artifact listing its
    own digest among dependencies, a proposal parenting itself, or a release
    manifest naming itself as its own prior release."""


class MixedReleaseActivationError(RegistryError):
    """Raised when an activation request names artifacts that the target
    release manifest does not resolve — i.e. the activated set mixes
    digests from outside this release (FR-003)."""


class InvalidStatusEventError(RegistryError):
    """Raised for a status event with an unknown kind or an actor/identity
    shape that does not parse."""


class InvalidProposalError(RegistryError):
    """Raised for a proposal whose metadata does not parse — e.g. a missing
    or empty strategy_id, which would break lineage attribution."""
