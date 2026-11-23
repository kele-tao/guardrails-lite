"""Core value objects: findings, verdicts, severities.

The model is deliberately small and immutable so a verdict can be serialised
straight to JSON and compared byte for byte between runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

Action = Literal["allow", "flag", "redact", "block"]

#: Ordered from least to most severe. The index doubles as the numeric rank.
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
Severity = Literal["info", "low", "medium", "high", "critical"]

#: Strongest last. Used when several findings disagree about the action.
ACTION_RANK: dict[str, int] = {"allow": 0, "flag": 1, "redact": 2, "block": 3}


def severity_rank(sev: str) -> int:
    """Return 0..4 for a severity string; unknown severities raise ValueError."""
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError as exc:
        raise ValueError(f"unknown severity {sev!r}") from exc


def strongest(actions: list[str]) -> Action:
    """Return the most severe action in actions, or 'allow' for an empty list."""
    best = "allow"
    for act in actions:
        if ACTION_RANK[act] > ACTION_RANK[best]:
            best = act
    return best  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected span.

    Offsets are character offsets into the scanned text (Python str indices,
    so CJK and emoji count as one character each).
    """

    detector_id: str
    name: str
    category: str
    severity: Severity
    start: int
    end: int
    text: str
    score: float = 1.0
    note: str = ""
    metadata: tuple[tuple[str, str], ...] = ()

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self, *, include_text: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "detector": self.detector_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "score": round(self.score, 4),
            "note": self.note,
        }
        if include_text:
            data["text"] = self.text
        if self.metadata:
            data["metadata"] = dict(self.metadata)
        return data

    def overlaps(self, other: Finding) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True, slots=True)
class Verdict:
    """The result of scanning one document with one policy."""

    action: Action
    findings: tuple[Finding, ...] = ()
    redacted: str | None = None
    suppressed: int = 0
    text_length: int = 0
    policy_name: str = "default"
    elapsed_us: float = 0.0

    @property
    def flagged(self) -> bool:
        return self.action in ("flag", "redact", "block")

    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return dict(sorted(counts.items()))

    def to_dict(
        self, *, include_text: bool = False, include_timing: bool = False
    ) -> dict[str, Any]:
        """Serialise the verdict.

        Timing is excluded by default so two runs over the same input serialise
        to byte-identical JSON; pass include_timing=True for profiling output.
        """
        data: dict[str, Any] = {
            "policy": self.policy_name,
            "action": self.action,
            "text_length": self.text_length,
            "suppressed": self.suppressed,
            "counts": self.by_category(),
            "findings": [f.to_dict(include_text=include_text) for f in self.findings],
            "redacted": self.redacted,
        }
        if include_timing:
            data["elapsed_us"] = round(self.elapsed_us, 1)
        return data

    def to_json(
        self,
        *,
        include_text: bool = False,
        include_timing: bool = False,
        indent: int | None = 2,
    ) -> str:
        return json.dumps(
            self.to_dict(include_text=include_text, include_timing=include_timing),
            indent=indent,
        )


@dataclass
class ScanStats:
    """Mutable counters used by the CLI and the benchmark harness."""

    chunks: int = 0
    chars_scanned: int = 0
    per_detector: dict[str, int] = field(default_factory=dict)
