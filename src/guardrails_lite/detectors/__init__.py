"""Registry of every detector, plus cheap prefilters.

Prefilters are the difference between "correct" and "usable": the default
policy runs 29 detectors over every document, and on ordinary prose most of
them cannot possibly match. Each prefilter below is a necessary condition for
its detector (a superset test), so a skipped detector can never change a
result - it only avoids the regex work. The correctness invariant is covered by
tests/test_prefilter.py, which asserts that prefixed scanning finds exactly the
same spans as unfiltered scanning on the whole benchmark corpus.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from .base import CATEGORIES, Detector, Span
from .injection import INJECTION_DETECTORS, repetition_prefilter
from .pii import PII_DETECTORS

#: Lowercase literal hints. A detector with hints is skipped when none appear.
#: Every tuple is a necessary condition for its detector's pattern.
_NEEDS: dict[str, tuple[str, ...]] = {
    "email": ("@",),
    "phone": ("+", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    "credit_card": ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    "iban": (" ", "-", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    "ipv4": (".",),
    "ipv4_network": ("/",),
    "ipv6": (":",),
    "jwt": ("eyj",),
    "aws_access_key": ("akia", "asia", "agpa", "aida", "aroa", "anpa"),
    "github_token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "openai_key": ("sk-",),
    "slack_token": ("xox",),
    "private_key": ("-----begin",),
    "cn_id_card": ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"),
    "generic_secret": ("key", "secret", "token", "password", "passwd"),
    "bearer_token": ("bearer",),
    "mac_address": (":",),
    "instruction_override": (
        "ignore", "disregard", "forget", "discard", "override", "bypass",
    ),
    "role_hijack": ("you are", "act as", "pretend", "roleplay", "from now on", "no restrictions"),
    "system_prompt_exfil": ("prompt", "instruction", "repeat everything", "rules", "message"),
    "delimiter_smuggling": ("<|", "[[", "===", "---", "##", "<<", "im_start"),
    "tool_call_injection": ("tool", "function", "<tool", "</tool", "invoke", "execute", "run "),
    "markdown_exfil": ("![", "](", "http"),
    "credential_harvest": (
        "key", "secret", "password", "credential", "token", ".env", "environment"
    ),
    "safety_bypass": (
        "bypass", "silently", "quietly", "jailbreak", "without", "do not tell", "no "
    ),
    "encoded_payload": (),
    "invisible_unicode": (),
    "bidi_override": (),
    "repeated_content": (),
}


#: Extra cheap prefilters that are not simple substring tests.
_PREFILTERS: dict[str, Callable[[str], bool]] = {
    "repeated_content": repetition_prefilter,
}


#: Context-signal detectors: their spans describe a region of the document
#: (a token flood, a block of cloaked text) instead of claiming characters, so
#: they are reported alongside ordinary findings that fall inside them.
_CONTEXT_DETECTORS = frozenset(
    {
        "repeated_content",
        "repeated_phrase",
        "invisible_unicode",
        "bidi_override",
        "instruction_override",
        "system_prompt_exfil",
        "credential_harvest",
        "safety_bypass",
        "role_hijack",
        "delimiter_smuggling",
        "tool_call_injection",
        "markdown_exfil",
        "repeated_word_run",
    }
)


def _with_prefilters(det: Detector) -> Detector:
    return replace(
        det,
        needs=_NEEDS.get(det.id, ()),
        prefilter=_PREFILTERS.get(det.id),
        exclusive=det.id not in _CONTEXT_DETECTORS,
    )


ALL_DETECTORS: tuple[Detector, ...] = tuple(
    _with_prefilters(d) for d in sorted(PII_DETECTORS + INJECTION_DETECTORS, key=lambda d: d.id)
)

DETECTORS: dict[str, Detector] = {d.id: d for d in ALL_DETECTORS}


def all_detectors() -> tuple[Detector, ...]:
    """Return every detector, sorted by id."""
    return ALL_DETECTORS


def get_detector(detector_id: str) -> Detector:
    """Return one detector by id; raises KeyError with a helpful message."""
    try:
        return DETECTORS[detector_id]
    except KeyError:
        known = ", ".join(sorted(DETECTORS))
        raise KeyError(f"unknown detector {detector_id!r}; known detectors: {known}") from None


__all__ = [
    "ALL_DETECTORS",
    "CATEGORIES",
    "DETECTORS",
    "Detector",
    "Span",
    "all_detectors",
    "get_detector",
]
