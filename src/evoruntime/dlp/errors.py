"""Typed DLP errors.

Collected in one module, like `evoruntime.datasets.errors` and
`evoruntime.eval.errors`, so the failure set a caller must handle is
auditable in one place.

`UnredactedContentError` is the trust boundary refusing to be crossed: it
means sensitive content reached (or almost reached) a plugin surface, which
is always a bug in the caller, never a recoverable condition (FR-015).
"""

from __future__ import annotations


class DlpError(Exception):
    """Base class for DLP failures."""


class CorpusIntegrityError(DlpError):
    """The labeled corpus failed an integrity or shape check.

    Raised when a declared content digest does not match the actual
    content, an example id is duplicated, or a positive/negative example
    is shaped inconsistently. A corpus that cannot prove its own
    integrity cannot back a recall measurement.
    """


class UnredactedContentError(DlpError):
    """Detectors still fire on content that claims to be redacted.

    Raised by `assert_fully_redacted` and the evidence-bundle gate. This
    is the "no plugin ever sees unredacted trace content" invariant
    (§17.3 DLP row) refusing to be violated silently.
    """
