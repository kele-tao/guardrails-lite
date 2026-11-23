"""Benchmark harness tests: corpus validation, confusion matrix, honest misses."""

from __future__ import annotations

import json

import pytest

from guardrails_lite.bench import format_markdown, load_corpus, run_corpus
from guardrails_lite.policy import load_policy, parse_policy


def test_committed_corpus_is_valid(corpus_path):
    records = load_corpus(corpus_path)
    assert len(records) >= 80
    positives = [r for r in records if r["label"] == 1]
    assert len(positives) >= 40
    assert all(r["family"] for r in records)
    assert all(isinstance(r["text"], str) and r["text"] for r in records)


def test_corpus_rejects_bad_json(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text(
        '{"id": "a", "family": "x", "text": "t", "label": 1}\n{oops\n', encoding="utf-8"
    )
    with pytest.raises(ValueError) as exc:
        load_corpus(path)
    assert "invalid JSON" in str(exc.value)


def test_corpus_rejects_missing_keys(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text('{"id": "a", "family": "x"}\n', encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_corpus(path)
    assert "missing key" in str(exc.value)


def test_corpus_rejects_bad_label_and_duplicates(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text('{"id": "a", "family": "x", "text": "t", "label": 2}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_corpus(path)
    path.write_text(
        '{"id": "a", "family": "x", "text": "t", "label": 1}\n'
        '{"id": "a", "family": "x", "text": "t", "label": 1}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as exc:
        load_corpus(path)
    assert "duplicate id" in str(exc.value)


def test_corpus_rejects_empty_file(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text("\n\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        load_corpus(path)
    assert "empty" in str(exc.value)


def test_confusion_matrix_arithmetic_on_synthetic_corpus(tmp_path, default_policy):
    path = tmp_path / "c.jsonl"
    rows = [
        {"id": "p1", "family": "email", "text": "a@example.com", "label": 1, "expect": ["email"]},
        {"id": "p2", "family": "email", "text": "no contact here", "label": 1, "expect": ["email"]},
        {"id": "n1", "family": "benign", "text": "plain deployment notes", "label": 0},
        {"id": "n2", "family": "benign", "text": "call 13800138000", "label": 0},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    report = run_corpus(path, default_policy)
    cm = report["confusion"]
    assert (cm["tp"], cm["fn"], cm["fp"], cm["tn"]) == (1, 1, 1, 1)
    assert report["metrics"]["precision"] == pytest.approx(0.5)
    assert report["metrics"]["recall"] == pytest.approx(0.5)
    assert report["metrics"]["accuracy"] == pytest.approx(0.5)
    assert len(report["misses"]) == 1
    assert report["misses"][0]["id"] == "p2"
    assert len(report["false_positives"]) == 1


def test_report_has_stable_keys(corpus_path, default_policy):
    report = run_corpus(corpus_path, default_policy)
    assert set(report) == {
        "corpus",
        "policy",
        "totals",
        "confusion",
        "metrics",
        "families",
        "misses",
        "false_positives",
        "per_detector",
    }
    assert report["policy"] == "default"
    total = sum(row["samples"] for row in report["families"].values())
    assert total == report["totals"]["samples"]


def test_markdown_contains_matrix_and_misses(corpus_path, default_policy):
    report = run_corpus(corpus_path, default_policy)
    md = format_markdown(report)
    assert "## Confusion matrix" in md
    assert "| **actual +** |" in md
    assert "## Known misses" in md
    assert f"{report['confusion']['fn']}" in md


def test_disabling_detector_shows_up_as_a_miss(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text(
        json.dumps(
            {
                "id": "p1",
                "family": "email",
                "text": "a@example.com",
                "label": 1,
                "expect": ["email"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    policy = parse_policy({"detectors": {"disable": ["email"]}})
    report = run_corpus(path, policy)
    assert report["confusion"]["fn"] == 1
    assert "disabled by policy" in report["misses"][0]["reason"]


def test_benchmark_numbers_are_reproducible(corpus_path, default_policy):
    first = run_corpus(corpus_path, default_policy)
    second = run_corpus(corpus_path, default_policy)
    assert first["confusion"] == second["confusion"]
    assert first["metrics"] == second["metrics"]


def test_committed_results_match_a_fresh_run(corpus_path):
    """The JSON committed under benchmarks/ must equal a fresh run."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    committed = json.loads((root / "benchmarks" / "results.json").read_text(encoding="utf-8"))
    fresh = run_corpus(corpus_path, load_policy(root / "policies" / "default.json"))
    assert committed["confusion"] == fresh["confusion"]
    assert committed["metrics"] == fresh["metrics"]
