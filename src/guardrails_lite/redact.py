"""Redaction: masks, stable pseudonyms and full replacement.

Three strategies, chosen per finding by the policy action:

* mask       - preserve the shape of the value (j***@example.com, **** **** **** 1111)
* pseudonym  - HMAC-SHA256(salt, value) truncated, so the same email becomes the
  same token in every document and every process. This is the default for PII.
* remove     - drop the span entirely.

When reversible=True the mapping token -> original value is returned so the
caller can restore the text, but the map is never written to disk by this
library.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field

from .model import Finding, Verdict

MASKABLE = {"email", "phone", "credit_card", "iban", "ipv4", "ipv6", "cn_id_card",
            "mac_address", "ipv4_network"}


def token_for(value: str, *, salt: str, detector_id: str, length: int = 8) -> str:
    """Deterministic HMAC token for value, namespaced by detector id."""
    key = ("guardrails-lite|" + salt).encode("utf-8")
    msg = (detector_id + "\x1f" + value).encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return digest[:length]


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "*" * len(value)
    head = local[0] if local else ""
    return f"{head}{'*' * max(1, len(local) - 1)}@{domain}"


def _mask_digits(value: str, *, keep: int = 4) -> str:
    digits = [i for i, ch in enumerate(value) if ch.isdigit()]
    hide = set(digits[: max(0, len(digits) - keep)])
    out = []
    for i, ch in enumerate(value):
        if i in hide:
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_ip(value: str) -> str:
    sep = "." if "." in value else ":"
    parts = value.split(sep)
    if len(parts) == 1:
        return "*" * len(value)
    return sep.join([parts[0]] + ["***"] * (len(parts) - 1))


def mask_value(finding: Finding) -> str:
    """Shape-preserving mask for the common PII detectors."""
    value = finding.text
    if finding.detector_id == "email":
        return _mask_email(value)
    if finding.detector_id in ("credit_card", "phone", "iban", "cn_id_card"):
        return _mask_digits(value)
    if finding.detector_id in ("ipv4", "ipv6", "ipv4_network"):
        return _mask_ip(value)
    if finding.detector_id == "mac_address":
        return ":".join(["**"] * 6)
    return "*" * max(4, len(value))


def replacement_for(finding: Finding, policy_salt: str, strategy: str) -> str:
    """Build the replacement text for one finding."""
    if strategy == "mask":
        return mask_value(finding)
    if strategy == "remove":
        return ""
    token = token_for(finding.text, salt=policy_salt, detector_id=finding.detector_id)
    return f"[[{finding.detector_id.upper()}:{token}]]"


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Redacted text plus the reversible map (empty unless explicitly enabled)."""

    text: str
    findings: tuple[Finding, ...] = ()
    tokens: dict[str, str] = field(default_factory=dict)
    removed: int = 0

    def __bool__(self) -> bool:
        return bool(self.findings)

    @property
    def token_count(self) -> int:
        return len(set(self.tokens))


@dataclass(frozen=True, slots=True)
class ReversibleMap:
    """Maps pseudonym tokens back to their originals for a single call site."""

    forward: dict[str, str]
    salt: str = ""

    def restore(self, text: str) -> str:
        """Replace every token in text with its original value."""
        out = text
        for token, original in sorted(self.forward.items(), key=lambda kv: -len(kv[0])):
            out = out.replace(token, original)
        return out

    def __len__(self) -> int:
        return len(self.forward)


_TOKEN_RE = re.compile(r"\[\[[A-Z0-9_]+:[0-9a-f]{6,}\]\]")


def redact(
    text: str,
    findings: tuple[Finding, ...] | list[Finding],
    *,
    salt: str = "guardrails-lite",
    strategies: dict[str, str] | None = None,
    reversible: bool = False,
    drop_redacted: bool = False,
) -> RedactionResult:
    """Replace non-overlapping findings in text.

    strategies maps a detector id (or '*') to 'pseudonym', 'mask' or 'remove'.
    The default is pseudonym for everything.
    """
    strategies = strategies or {}
    default = strategies.get("*", "pseudonym")
    tokens: dict[str, str] = {}
    pieces: list[str] = []
    cursor = 0
    removed = 0
    kept: list[Finding] = []
    for finding in sorted(findings, key=lambda f: (f.start, f.end)):
        if finding.start < cursor:
            continue
        strategy = strategies.get(finding.detector_id, default)
        replacement = replacement_for(finding, salt, strategy)
        if strategy == "remove":
            removed += 1
        if not drop_redacted:
            pieces.append(text[cursor : finding.start])
            pieces.append(replacement)
        cursor = finding.end
        kept.append(finding)
        if replacement.startswith("[[") and replacement.endswith("]]"):
            tokens[replacement] = finding.text
    if not drop_redacted:
        pieces.append(text[cursor:])
    out = "".join(pieces) if not drop_redacted else ""

    if reversible:
        return RedactionResult(out, tuple(kept), tokens, removed)
    return RedactionResult(out, tuple(kept), {}, removed)


def redact_verdict(
    verdict: Verdict,
    text: str,
    *,
    salt: str = "guardrails-lite",
    strategies: dict[str, str] | None = None,
) -> RedactionResult:
    """Convenience wrapper: redact using the findings already stored in a verdict."""
    return redact(text, verdict.findings, salt=salt, strategies=strategies)


def rehydrate(text: str, forward: dict[str, str]) -> str:
    """Restore pseudonym tokens produced by redact()."""
    return ReversibleMap(dict(forward)).restore(text)
