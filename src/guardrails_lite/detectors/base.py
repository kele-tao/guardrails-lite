"""Detector primitives: spans, detector metadata, regex helpers.

A detector is a small immutable object with an id, a severity, a human
description and an honest note about false positives. Detectors return spans
(character offsets) and know nothing about policies or redaction.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from re import Pattern

from ..model import Finding, Severity

#: Categories used by the policy engine and the CLI summary.
CATEGORIES = ("pii", "secret", "encoding", "injection")


@dataclass(frozen=True, slots=True)
class Span:
    """A raw match produced by a detector, before policy is applied."""

    start: int
    end: int
    score: float = 1.0
    note: str = ""
    metadata: tuple[tuple[str, str], ...] = ()


ScanFn = Callable[[str], Iterable[Span]]


@dataclass(frozen=True, slots=True)
class Detector:
    """Metadata plus a scanning function for one class of risk.

    prefilter is an optional cheap regex. When it does not match, the (usually
    much more expensive) main pattern is skipped entirely. This keeps the
    29-detector default policy linear on plain prose.
    """

    id: str
    name: str
    category: str
    severity: Severity
    description: str
    false_positives: str
    scan: ScanFn
    action: str = "flag"
    prefilter: Pattern[str] | Callable[[str], bool] | None = None
    needs: tuple[str, ...] = ()
    #: When False, this detector's span is a context signal (a flood, a block of
    #: cloaked text) rather than a claim on characters, so overlapping findings
    #: from other detectors are still reported.
    exclusive: bool = True

    def find(self, text: str, lower: str | None = None) -> list[Finding]:
        """Run the detector and return Findings sorted by offset.

        lower may be a pre-lowered copy of text to avoid re-lowercasing for
        every detector in a scan.
        """
        if self.needs:
            haystack = lower if lower is not None else text.lower()
            if not any(hint in haystack for hint in self.needs):
                return []
        prefilter = self.prefilter
        if prefilter is not None:
            if hasattr(prefilter, "search"):
                if prefilter.search(text) is None:
                    return []
            elif not prefilter(text):
                return []
        out: list[Finding] = []
        for span in self.scan(text):
            if span.start < 0 or span.end > len(text) or span.end <= span.start:
                continue
            out.append(
                Finding(
                    detector_id=self.id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    start=span.start,
                    end=span.end,
                    text=text[span.start : span.end],
                    score=max(0.0, min(1.0, span.score)),
                    note=span.note,
                    metadata=span.metadata,
                )
            )
        out.sort(key=lambda f: (f.start, f.end, f.detector_id))
        return out

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "action": self.action,
            "description": self.description,
            "false_positives": self.false_positives,
        }


def regex_spans(
    pattern: Pattern[str],
    validate: Callable[[re.Match[str]], bool] | None = None,
    score: float = 1.0,
    note: str = "",
    group: int = 0,
) -> ScanFn:
    """Build a scanning function from a compiled pattern.

    *validate* receives the match and can reject candidates (Luhn checks,
    mod-97 IBAN checks, private-key structure and so on).
    """

    def scan(text: str) -> Iterable[Span]:
        for m in pattern.finditer(text):
            if validate is not None and not validate(m):
                continue
            start, end = m.span(group)
            if end <= start:
                continue
            meta = tuple((k, v) for k, v in m.groupdict().items() if v is not None)
            yield Span(start, end, score=score, note=note, metadata=meta)

    return scan


def dedupe(spans: Sequence[Span]) -> list[Span]:
    """Drop exact duplicates and nested spans, keeping the widest match."""
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    out: list[Span] = []
    for span in ordered:
        if out and span.start >= out[-1].start and span.end <= out[-1].end:
            continue
        out.append(span)
    return out


def keyword_spans(
    text: str,
    pattern: Pattern[str],
    *,
    score: float,
    note: str,
    severity_hint: str = "",
) -> Iterable[Span]:
    """Yield a span per keyword-pattern hit, with an optional severity hint."""
    for m in pattern.finditer(text):
        meta = (("hint", severity_hint),) if severity_hint else ()
        yield Span(m.start(), m.end(), score=score, note=note, metadata=meta)
