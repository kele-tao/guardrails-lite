"""The prefilter invariant, plus API surface tests for __init__ and __main__.

Prefilters are only safe if they never change a result. This module proves that
by re-scanning the whole benchmark corpus and the examples with prefilters
stripped from every detector and asserting the spans are identical.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import guardrails_lite
from guardrails_lite import scan, scan_stream
from guardrails_lite.detectors import all_detectors
from guardrails_lite.policy import Policy, parse_policy

ROOT = Path(__file__).resolve().parent.parent


def scan_with(
    text: str, policy: Policy, *, use_prefilters: bool
) -> list[tuple[str, int, int]]:
    """Scan through the real pipeline, with or without detector prefilters."""
    detectors = policy.active_detectors()
    if not use_prefilters:
        detectors = [replace(d, prefilter=None, needs=()) for d in detectors]
    verdict = scan(text, policy, detectors=detectors)
    return [(f.detector_id, f.start, f.end) for f in verdict.findings]


def test_prefilters_never_change_a_result():
    policy = parse_policy({"name": "prefilter-check"})
    corpus = [
        line
        for line in (ROOT / "benchmarks" / "corpus.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    import json

    records = [json.loads(line) for line in corpus]
    for rec in records:
        with_pf = scan_with(rec["text"], policy, use_prefilters=True)
        without_pf = scan_with(rec["text"], policy, use_prefilters=False)
        assert with_pf == without_pf, rec["id"]


def test_prefilters_do_not_hide_entities_in_examples():
    policy = parse_policy({"name": "prefilter-check"})
    for name in ("leaky_doc.md", "prompt_injection.txt", "benign.md"):
        text = (ROOT / "examples" / name).read_text(encoding="utf-8")
        assert scan_with(text, policy, use_prefilters=True) == scan_with(
            text, policy, use_prefilters=False
        ), name


def test_public_api_exports():
    for name in (
        "scan",
        "scan_stream",
        "redact",
        "rehydrate",
        "load_policy",
        "parse_policy",
        "Finding",
        "Verdict",
        "Policy",
        "all_detectors",
        "DETECTORS",
    ):
        assert hasattr(guardrails_lite, name), name
    assert guardrails_lite.__version__ == "1.0.0"


def test_module_entry_point_runs(capsys, monkeypatch):
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", ["guardrails-lite", "detectors"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("guardrails_lite", run_name="__main__")
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "detectors" in out.lower() or "email" in out


def test_scan_and_stream_agree_on_library_api():
    text = "contact jane@example.com or 13800138000"
    batch = scan(text)
    streamed = scan_stream([text[:10], text[10:20], text[20:]])
    assert [(f.start, f.end) for f in batch.findings] == [
        (f.start, f.end) for f in streamed.findings
    ]


def test_all_detectors_are_documented():
    for det in all_detectors():
        assert len(det.description) > 10
        assert len(det.false_positives) > 10
        assert det.severity in ("info", "low", "medium", "high", "critical")
        assert det.action in ("allow", "flag", "redact", "block")
