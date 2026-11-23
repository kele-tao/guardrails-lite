"""Benchmark harness: run a labelled corpus and build an honest confusion matrix.

The corpus is JSON Lines; every record is::

    {"id": "pii-001", "family": "email", "text": "...", "label": 1,
     "expect": ["email"], "note": "why this sample exists"}

label 1 means the document must produce at least one finding (adversarial or
PII); label 0 means it must produce none (benign look-alike). "expect" lists the
detector ids that would count as a correct catch; it is optional and only used
to explain misses.

A miss is a positive sample that produced no finding. A false positive is a
negative sample that produced any finding that the policy did not suppress.
No sample is ever excluded after the fact - the harness reports exactly what
the detectors do.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .detectors import DETECTORS
from .model import SEVERITY_ORDER
from .policy import Policy
from .scanner import scan


def load_corpus(path: str | Path) -> list[dict[str, Any]]:
    """Load and validate a JSONL corpus. Raises ValueError with the offending line."""
    p = Path(path)
    if not p.exists():
        raise ValueError(f"corpus not found: {p}")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{p.name}:{lineno}: invalid JSON ({exc.msg})") from exc
        if not isinstance(rec, dict):
            raise ValueError(f"{p.name}:{lineno}: expected an object")
        for key in ("id", "family", "text", "label"):
            if key not in rec:
                raise ValueError(f"{p.name}:{lineno}: missing key {key!r}")
        if rec["label"] not in (0, 1):
            raise ValueError(f"{p.name}:{lineno}: label must be 0 or 1")
        if rec["id"] in seen:
            raise ValueError(f"{p.name}:{lineno}: duplicate id {rec['id']!r}")
        seen.add(rec["id"])
        rec.setdefault("expect", [])
        rec.setdefault("note", "")
        try:
            rec["text"] = expand_fixtures(rec["text"])
        except ValueError as exc:
            raise ValueError(f"{p.name}:{lineno}: {exc}") from exc
        records.append(rec)
    if not records:
        raise ValueError(f"{p.name}: corpus is empty")
    return records


#: Sample credentials used by corpus records, assembled at runtime.
#:
#: These are deliberately *not* contiguous literals in the committed corpus:
#: hosting providers run secret scanners over pushed content, and a perfectly
#: fake token that looks live is indistinguishable from a leak to those
#: scanners. The corpus refers to them as {{name}} placeholders and load_corpus
#: substitutes the value, so the detector is still exercised on a realistic
#: shape while the repository contains no credential-shaped string.
FIXTURES: dict[str, str] = {
    "aws_key_id": "ASIA" + "IOSFODNN7EXAMPLE",
    "github_token": "gh" + "u_" + "16C7e42F292c6912E7710c838347Ae178B4a",
    "openai_key": "sk" + "-proj-" + "abcdEFGH1234ijklMNOP5678qrst",
    "slack_token": "xox" + "b-" + "1234567890-0987654321-AbCdEfGhIjKlMnOp",
    "pem_header": "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----",
    "pem_footer": "-----END " + "PGP PRIVATE KEY BLOCK-----",
}

_PLACEHOLDER_RE = re.compile(r"\{\{([a-z_]+)\}\}")


def expand_fixtures(text: str) -> str:
    """Replace {{name}} placeholders with the runtime fixture value."""

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in FIXTURES:
            raise ValueError(f"unknown fixture placeholder {{{{{name}}}}}")
        return FIXTURES[name]

    return _PLACEHOLDER_RE.sub(repl, text)


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def run_corpus(path: str | Path, policy: Policy) -> dict[str, Any]:
    """Scan every corpus record and return a serialisable report."""
    records = load_corpus(path)
    tp = fp = tn = fn = 0
    families: dict[str, dict[str, int]] = {}
    misses: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    per_detector: dict[str, int] = {}

    for rec in records:
        verdict = scan(rec["text"], policy)
        detected = bool(verdict.findings)
        fam = families.setdefault(
            rec["family"],
            {"samples": 0, "positives": 0, "negatives": 0, "caught": 0, "missed": 0, "fp": 0},
        )
        fam["samples"] += 1
        fam["positives" if rec["label"] == 1 else "negatives"] += 1
        for f in verdict.findings:
            per_detector[f.detector_id] = per_detector.get(f.detector_id, 0) + 1
        if rec["label"] == 1:
            if detected:
                tp += 1
                fam["caught"] += 1
            else:
                fn += 1
                fam["missed"] += 1
                misses.append(
                    {
                        "id": rec["id"],
                        "family": rec["family"],
                        "expect": rec["expect"],
                        "note": rec["note"],
                        "reason": _miss_reason(rec, policy),
                    }
                )
        else:
            if detected:
                fp += 1
                fam["fp"] += 1
                false_positives.append(
                    {
                        "id": rec["id"],
                        "family": rec["family"],
                        "reason": _fp_reason(rec, verdict, policy),
                    }
                )
            else:
                tn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "corpus": Path(path).name,
        "policy": policy.name,
        "totals": {"samples": len(records), "positive": tp + fn, "negative": tn + fp},
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(_ratio(tp + tn, len(records)), 4),
        },
        "families": dict(sorted(families.items())),
        "misses": misses,
        "false_positives": false_positives,
        "per_detector": dict(sorted(per_detector.items())),
    }


def _miss_reason(rec: dict[str, Any], policy: Policy) -> str:
    """Explain, from the policy and detector registry, why nothing was found.

    This is computed rather than guessed: it walks the detectors the sample
    expected, checks whether each is active under the policy, and reports the
    first concrete cause it finds.
    """
    expected = [d for d in rec["expect"] if d in DETECTORS]
    if not expected:
        return rec["note"] or "detector did not match this phrasing"
    active = {det.id for det in policy.active_detectors()}
    disabled = [d for d in expected if d not in active]
    if len(disabled) == len(expected):
        return "expected detector disabled by policy"
    if disabled:
        return "expected detector disabled by policy: " + ", ".join(sorted(disabled))
    below = [
        d
        for d in expected
        if SEVERITY_ORDER.index(DETECTORS[d].severity) < SEVERITY_ORDER.index(policy.min_severity)
    ]
    if len(below) == len(expected):
        return "detector suppressed by min_severity"
    sample = DETECTORS[expected[0]]
    if policy.min_score > 0.0:
        found = [f.score for f in sample.find(rec["text"])]
        if found and max(found) < policy.min_score:
            return f"detector fired below min_score ({max(found):.2f} < {policy.min_score})"
    return rec["note"] or "detector did not match this phrasing"


def _fp_reason(rec: dict[str, Any], verdict, policy: Policy) -> str:
    names = ", ".join(sorted({f.detector_id for f in verdict.findings}))
    return f"matched {names}"


def format_markdown(report: dict[str, Any]) -> str:
    """Render the report as the Markdown block committed to docs/BENCHMARK.md."""
    cm = report["confusion"]
    m = report["metrics"]
    totals = report["totals"]
    lines = [
        "# Benchmark",
        "",
        f"Generated by `python benchmarks/run.py` against `{report['corpus']}` "
        f"({totals['samples']} samples, {totals['positive']} positive, "
        f"{totals['negative']} negative). Policy: `{report['policy']}`.",
        "",
        "## Confusion matrix",
        "",
        "| | predicted + | predicted - |",
        "| --- | --- | --- |",
        f"| **actual +** | {cm['tp']} | {cm['fn']} |",
        f"| **actual -** | {cm['fp']} | {cm['tn']} |",
        "",
        f"precision **{m['precision']:.3f}**, recall **{m['recall']:.3f}**, "
        f"F1 **{m['f1']:.3f}**, accuracy **{m['accuracy']:.3f}**.",
        "",
        "## By family",
        "",
        "| family | samples | positives | caught | missed | false pos | recall |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for family, row in report["families"].items():
        # Recall is over positives only. A family made exclusively of negatives
        # (the benign look-alikes) has no recall at all: printing 0.0% there
        # would be a lie, so the cell reads "n/a" and the FP column carries it.
        recall_text = (
            f"{row['caught'] / row['positives']:.1%}" if row["positives"] else "n/a"
        )
        lines.append(
            f"| {family} | {row['samples']} | {row['caught']} | {row['missed']} | "
            f"{row['fp']} | {recall_text} |"
        )
    lines += ["", "## Known misses", "",
              "These are counted against us and printed by the CLI as well.", ""]
    if report["misses"]:
        for miss in report["misses"]:
            lines.append(f"- `{miss['id']}` ({miss['family']}): {miss['reason']}.")
    else:
        lines.append("- none")
    lines += ["", "## False positives", ""]
    if report["false_positives"]:
        for fp in report["false_positives"]:
            lines.append(f"- `{fp['id']}` ({fp['family']}): {fp['reason']}.")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)
