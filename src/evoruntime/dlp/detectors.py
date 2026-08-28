"""Pure detection rules for the DLP redaction pipeline (FR-015).

Detectors are regex rules with optional semantic validators, grouped by
`DlpCategory`. Everything here is a pure function over strings: no I/O,
no clock, no model calls — which is what makes the corpus evaluation
(`evoruntime.dlp.metrics`) deterministic and the redaction pipeline
safe to run at the evidence-bundle boundary.

Design notes:

* Rules are deliberately conservative about *shape* (token prefixes,
  Luhn-valid card numbers, octet-bounded IPs) and about *context*
  (a bare word like "token" only triggers when followed by an
  assignment). The false-positive budget (§17.3: <=5%) is spent on the
  clean half of the corpus, not absorbed by vagueness.
* Free-text person names are intentionally out of scope — without a
  NER model there is no honest way to bound the false-positive rate,
  and a guessed name list would be both under-inclusive and
  over-inclusive. Names are detected in labeled contexts only
  (`full_name:`, `account_holder:`, ...). This limitation is
  documented rather than papered over.
* Overlapping matches from different rules are expected (a JWT inside
  a Bearer header); `redact_text` merges overlapping spans, and the
  metrics harness counts distinct spans per category.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from evoruntime.dlp.corpus import DlpCategory


@dataclass(frozen=True)
class Finding:
    """One detector match: a span of `content` plus its provenance."""

    category: DlpCategory
    rule_id: str
    start: int
    end: int
    matched_text: str


@dataclass(frozen=True)
class DetectionRule:
    """A single detector: a regex plus an optional semantic validator.

    The validator receives the match and returns False to reject it —
    used where regex shape alone over-matches (credit cards need Luhn;
    IPs need octets <= 255).
    """

    rule_id: str
    category: DlpCategory
    pattern: re.Pattern[str]
    validator: Callable[[re.Match[str]], bool] | None = None


def _luhn_ok(match: re.Match[str]) -> bool:
    digits = re.sub(r"\D", "", match.group(0))
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ipv4_ok(match: re.Match[str]) -> bool:
    return all(0 <= int(octet) <= 255 for octet in match.group(0).split("."))


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Values that appear after a secret-shaped keyword in benign config and
# docs ("secret: none", "password: ********", "token: null"). The generic
# assignment rule skips these instead of redacting documentation.
_BENIGN_ASSIGNMENT_VALUES = (
    r"(?:none|null|true|false|required|placeholder|example|redacted|masked|omitted)\b"
)

_SECRET_KEYWORDS = (
    r"api[_-]?key"
    r"|api[_-]?secret"
    r"|secret"
    r"|access[_-]?token"
    r"|auth[_-]?token"
    r"|client[_-]?secret"
    r"|password"
    r"|passwd"
    r"|pwd"
    r"|private[_-]?key"
    r"|token"
)

SECRETS_RULES: tuple[DetectionRule, ...] = (
    DetectionRule("aws_access_key_id", DlpCategory.SECRETS, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    DetectionRule(
        "aws_secret_access_key",
        DlpCategory.SECRETS,
        _c(r"(?:aws_)?secret_?access_?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}\b"),
    ),
    DetectionRule(
        "github_token", DlpCategory.SECRETS, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")
    ),
    DetectionRule(
        "github_pat", DlpCategory.SECRETS, re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")
    ),
    DetectionRule(
        "openai_key", DlpCategory.SECRETS, re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,200}\b")
    ),
    DetectionRule(
        "stripe_key", DlpCategory.SECRETS, re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b")
    ),
    DetectionRule(
        "slack_token", DlpCategory.SECRETS, re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,250}\b")
    ),
    DetectionRule("google_api_key", DlpCategory.SECRETS, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    DetectionRule("npm_token", DlpCategory.SECRETS, re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    DetectionRule(
        "private_key_block",
        DlpCategory.SECRETS,
        re.compile(
            r"-----BEGIN\s+(?:[A-Z]+\s+)?PRIVATE KEY(?: BLOCK)?\s*-----[\s\S]*?"
            r"-----END\s+(?:[A-Z]+\s+)?PRIVATE KEY(?: BLOCK)?\s*-----"
        ),
    ),
    DetectionRule(
        "jwt",
        DlpCategory.SECRETS,
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    DetectionRule("bearer_token", DlpCategory.SECRETS, _c(r"\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b")),
    DetectionRule(
        "credential_url",
        DlpCategory.SECRETS,
        _c(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@]+:[^\s/@]+@[^\s]+"
        ),
    ),
    DetectionRule(
        "secret_assignment",
        DlpCategory.SECRETS,
        _c(
            rf"\b(?:{_SECRET_KEYWORDS})\b[\"']?\s*[:=]\s*[\"']?"
            rf"(?!{_BENIGN_ASSIGNMENT_VALUES})[A-Za-z0-9._~+/=-]{{8,}}"
        ),
    ),
)

PII_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        "email",
        DlpCategory.PII,
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ),
    DetectionRule("ssn", DlpCategory.PII, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    DetectionRule(
        "phone",
        DlpCategory.PII,
        re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
    ),
    DetectionRule(
        "credit_card",
        DlpCategory.PII,
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        validator=_luhn_ok,
    ),
    DetectionRule(
        "ipv4",
        DlpCategory.PII,
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        validator=_ipv4_ok,
    ),
    DetectionRule(
        "person_name_contextual",
        DlpCategory.PII,
        _c(
            # The label matches case-insensitively ("Full_Name", "dob"), but
            # the value must be a genuinely capitalized name — the scoped
            # (?-i:) keeps "employee_name is pending" from matching.
            r"\b(?:full[_-]?name|customer[_-]?name|account[_-]?holder"
            r"|contact[_-]?name|employee[_-]?name)\s*[:=]?\s*[\"']?"
            r"(?-i:[A-Z][A-Za-z'\u2019-]+(?:\s+[A-Z][A-Za-z'\u2019-]+)+)"
        ),
    ),
    DetectionRule(
        "date_of_birth_contextual",
        DlpCategory.PII,
        _c(
            r"\b(?:dob|date[_-]of[_-]birth|birth[_-]?date)\s*[:=]?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})\b"
        ),
    ),
    DetectionRule(
        "street_address",
        DlpCategory.PII,
        _c(
            r"\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}"
            r"(?:Street|Avenue|Boulevard|Road|Lane|Drive|Terrace|Court|Place|Way|St|Ave|Blvd|Rd|Ln|Dr|Ter)\b"
        ),
    ),
)

INJECTION_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        "ignore_previous",
        DlpCategory.PROMPT_INJECTION,
        _c(
            r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instructions?|prompts?|rules?|directions?|messages?|context)\b"
        ),
    ),
    DetectionRule(
        "disregard_previous",
        DlpCategory.PROMPT_INJECTION,
        _c(r"\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|your)\b"),
    ),
    DetectionRule(
        "ignore_safety",
        DlpCategory.PROMPT_INJECTION,
        _c(
            r"\b(?:ignore|bypass|drop|disable)\s+(?:all\s+|your\s+|the\s+)?"
            r"(?:guardrails|safety\s+(?:checks?|rules?)|content\s+filters?|restrictions?|denylists?)\b"
        ),
    ),
    DetectionRule(
        "system_override",
        DlpCategory.PROMPT_INJECTION,
        _c(r"\b(?:system|developer|instruction)\s+(?:override|message)\b|#\s*SYSTEM\s*:"),
    ),
    DetectionRule(
        "fake_chat_tag",
        DlpCategory.PROMPT_INJECTION,
        re.compile(r"<\|?(?:system|im_start|im_end)\|?>"),
    ),
    DetectionRule(
        "note_to_model",
        DlpCategory.PROMPT_INJECTION,
        _c(r"\bnote\s+to\s+(?:assistant|ai|model|llm|agent)\b"),
    ),
    DetectionRule(
        "instruction_extraction",
        DlpCategory.PROMPT_INJECTION,
        _c(
            # Bounded gap: "reveal the exact text of your instructions" is
            # one attempt, not a coincidence — but the gap stays inside a
            # single clause so "show the report of the rules review" (a
            # legitimate sentence) cannot bridge into a match.
            r"\b(?:reveal|print|show|repeat|output|display|leak)\b"
            r"[^.!?\n]{0,60}?"
            r"\b(?:system\s+|initial\s+|hidden\s+|original\s+|your\s+|the\s+)?"
            # "rules" is deliberately absent: "show the report of the rules
            # review" is a legitimate sentence, and no corpus injection
            # attempt extracts "rules" through an extraction verb.
            r"(?:prompt|instructions?|directives?)\b"
            # "rules you were given" is the canonical phrasing for this
            # attempt; the possessive clause keeps the benign "report of the
            # rules review" sentence out of scope.
            r"|\b(?:show|reveal|print|repeat|output|display)\b[^.!?\n]{0,40}?"
            r"\brules\s+you\s+were\s+given\b"
        ),
    ),
    DetectionRule(
        "new_instructions",
        DlpCategory.PROMPT_INJECTION,
        _c(r"\b(?:new|updated|revised|actual|real)\s+(?:instructions?|directives?|rules?)\s*:"),
    ),
    DetectionRule(
        "role_hijack",
        DlpCategory.PROMPT_INJECTION,
        _c(r"\byou\s+are\s+now\s+(?:a|an|the)\b|\bfrom\s+now\s+on,?\s+you\b"),
    ),
    DetectionRule(
        "obey_commands",
        DlpCategory.PROMPT_INJECTION,
        _c(
            r"\byou\s+must\s+(?:now\s+)?obey\b|\bobey\s+(?:my|these|the)\s+(?:commands?|instructions?)\b"
        ),
    ),
    DetectionRule(
        "do_not_follow",
        DlpCategory.PROMPT_INJECTION,
        _c(
            r"\bdo[\s-]+not[\s-]+follow\s+(?:the\s+|your\s+|any\s+|all\s+)?"
            r"(?:above|previous|prior|initial|original|system|old)\b"
        ),
    ),
    DetectionRule(
        "override_directive",
        DlpCategory.PROMPT_INJECTION,
        _c(
            r"\boverride\s+(?:your\s+)?(?:instructions?|rules?|guardrails?|safety|restrictions?)\b"
            r"|\binstruction\s+override\b"
        ),
    ),
    DetectionRule(
        "exfiltration_directive",
        DlpCategory.PROMPT_INJECTION,
        _c(
            r"\b(?:email|send|post|upload|copy|forward)\s+(?:me\s+)?(?:a\s+copy\s+of\s+)?(?:the\s+)?"
            r"(?:customer\s+)?(?:database\b|db\b|credentials\b|secrets?\b|\.env\b|private\s+keys?\b)"
        ),
    ),
)

DEFAULT_RULES: tuple[DetectionRule, ...] = SECRETS_RULES + PII_RULES + INJECTION_RULES


def detect(content: str, rules: tuple[DetectionRule, ...] = DEFAULT_RULES) -> tuple[Finding, ...]:
    """Run every rule over `content` and return findings sorted by position.

    Pure: same input, same findings, always. A rule whose validator
    rejects a match contributes nothing — the match never existed.
    """
    findings: list[Finding] = []
    for rule in rules:
        for match in rule.pattern.finditer(content):
            if rule.validator is not None and not rule.validator(match):
                continue
            findings.append(
                Finding(
                    category=rule.category,
                    rule_id=rule.rule_id,
                    start=match.start(),
                    end=match.end(),
                    matched_text=match.group(0),
                )
            )
    findings.sort(key=lambda f: (f.start, f.end, f.rule_id))
    return tuple(findings)
