"""Scanner tests: verdicts, overlap resolution, and the streaming scanner.

The streaming tests are the important ones: an entity that straddles a chunk
boundary must be found exactly once, with offsets that match a single-shot scan
of the concatenated document.
"""

from __future__ import annotations

import itertools
import random

import pytest

from conftest import SAMPLE_AWS_KEY_ID, SAMPLE_PEM_HEADER
from guardrails_lite.policy import parse_policy
from guardrails_lite.scanner import (
    DEFAULT_OVERLAP,
    detector_catalogue,
    detector_ids,
    iter_chunks,
    scan,
    scan_stream,
)


def test_clean_text_is_allow():
    verdict = scan("Nothing sensitive here: just a sentence about deployment.")
    assert verdict.action == "allow"
    assert verdict.findings == ()
    assert verdict.redacted is None


def test_verdict_is_json_serialisable():
    import json

    verdict = scan("mail jane@example.com")
    payload = json.loads(verdict.to_json(include_text=True))
    assert payload["action"] == "redact"
    assert payload["counts"] == {"pii": 1}
    assert payload["findings"][0]["text"] == "jane@example.com"


def test_empty_input():
    verdict = scan("")
    assert verdict.action == "allow"
    assert verdict.text_length == 0


def test_unicode_offsets_are_character_based():
    text = "\u4f60\u597d\U0001f600 jane@example.com \u4e16\u754c"
    (finding,) = scan(text).findings
    assert text[finding.start : finding.end] == "jane@example.com"
    assert text[finding.start - 1] == " "


def test_scan_rejects_non_string():
    with pytest.raises(TypeError):
        scan(b"bytes")


def test_overlap_resolution_prefers_higher_score():
    # A Luhn-valid card must win over the phone/order-id candidates on the same
    # characters; no two findings may overlap in a verdict.
    text = "pay with 4539 1488 0343 6467 today"
    verdict = scan(text)
    assert len(verdict.findings) == 1
    assert verdict.findings[0].detector_id == "credit_card"
    spans = sorted((f.start, f.end) for f in verdict.findings)
    for earlier, later in itertools.pairwise(spans):
        assert earlier[1] <= later[0]


def test_deterministic_output():
    text = "jane@example.com 13800138000 " + SAMPLE_AWS_KEY_ID
    assert scan(text).to_json() == scan(text).to_json()


def test_action_escalates_with_severity():
    text = "normal text with an email jane@example.com"
    assert scan(text).action == "redact"
    text = "normal text with a key " + SAMPLE_AWS_KEY_ID
    assert scan(text).action == "block"


def test_detector_catalogue_and_ids():
    catalogue = detector_catalogue()
    assert len(catalogue) == len(detector_ids())
    assert all({"id", "severity", "action", "description"} <= set(row) for row in catalogue)


def test_iter_chunks_normalises_pieces():
    assert list(iter_chunks(["abcdef", "gh"], chunk_size=4)) == ["abcd", "efgh"]
    assert list(iter_chunks([], chunk_size=4)) == []
    with pytest.raises(ValueError):
        list(iter_chunks(["x"], chunk_size=0))
    with pytest.raises(TypeError):
        list(iter_chunks([b"x"], chunk_size=1))  # type: ignore[list-item]


def test_stream_matches_batch_on_clean_unicode_document():
    text = ("line about deployment and metrics\n" * 50) + "contact jane@example.com\n"
    batch = scan(text)
    streamed = scan_stream([text[i : i + 37] for i in range(0, len(text), 37)])
    assert [(f.detector_id, f.start, f.end) for f in batch.findings] == [
        (f.detector_id, f.start, f.end) for f in streamed.findings
    ]


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 13, 64, 997])
def test_stream_finds_entity_split_across_every_boundary(chunk_size):
    text = "prefix text " + "x" * 40 + " jane.doe@example.com suffix"
    batch = scan(text)
    chunks = [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]
    streamed = scan_stream(chunks, chunk_size=chunk_size, overlap=DEFAULT_OVERLAP)
    assert [(f.detector_id, f.start, f.end) for f in batch.findings] == [
        (f.detector_id, f.start, f.end) for f in streamed.findings
    ]
    assert streamed.text_length == len(text)


def test_stream_matches_batch_on_mixed_document():
    parts = [
        "intro line\n",
        "email one: alpha@example.com\n",
        "random filler " * 30 + "\n",
        "card 4539 1488 0343 6467\n",
        "key " + SAMPLE_AWS_KEY_ID + "\n",
        "id 11010519491231002X\n",
    ]
    text = "".join(parts)
    batch = scan(text)
    chunks = [text[i : i + 23] for i in range(0, len(text), 23)]
    streamed = scan_stream(chunks, chunk_size=23)
    batch_spans = [(f.detector_id, f.start, f.end) for f in batch.findings]
    stream_spans = [(f.detector_id, f.start, f.end) for f in streamed.findings]
    assert batch_spans == stream_spans


def test_stream_reports_each_entity_once():
    text = ("filler " * 200) + "jane@example.com" + (" filler" * 200)
    streamed = scan_stream([text[i : i + 100] for i in range(0, len(text), 100)])
    emails = [f for f in streamed.findings if f.detector_id == "email"]
    assert len(emails) == 1
    assert emails[0].start == text.index("jane@example.com")


def test_stream_never_splits_a_pem_header():
    text = "padding " * 300 + SAMPLE_PEM_HEADER + " trailing" * 50
    streamed = scan_stream([text[i : i + 61] for i in range(0, len(text), 61)])
    keys = [f for f in streamed.findings if f.detector_id == "private_key"]
    assert len(keys) == 1
    assert keys[0].text == SAMPLE_PEM_HEADER


def test_stream_is_deterministic():
    text = "mail a@example.com then b@example.com then " + "x " * 500
    chunks = [text[i : i + 17] for i in range(0, len(text), 17)]
    first = scan_stream(list(chunks))
    second = scan_stream(list(chunks))
    assert first.to_json() == second.to_json()


def test_stream_accepts_generator():
    def gen():
        for i in range(200):
            yield f"line {i} with filler text\n"

    verdict = scan_stream(gen())
    assert verdict.text_length > 1000
    assert verdict.action in ("allow", "flag", "redact", "block")


def test_stream_rejects_bad_input():
    with pytest.raises(TypeError):
        scan_stream([b"bytes"])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        scan_stream(["x"], overlap=-1)


def test_stream_respects_policy():
    policy = parse_policy({"detectors": {"disable": ["email"]}})
    streamed = scan_stream(["mail jane@example.com"], policy)
    assert streamed.findings == ()


def test_large_document_smoke():
    """One large input: 2 MB of prose with PII sprinkled through it."""
    rng = random.Random(1234)
    words = ["alpha", "beta", "gamma", "delta", "ops", "cloud", "report"]
    rows = []
    for i in range(24000):
        rows.append(" ".join(rng.choice(words) for _ in range(12)))
        if i % 400 == 0:
            rows[-1] += f" contact user{i}@example.com"
    text = "\n".join(rows)
    assert len(text) > 1_500_000
    verdict = scan(text)
    emails = [f for f in verdict.findings if f.detector_id == "email"]
    assert len(emails) == len(range(0, 24000, 400))


def test_stats_are_collected():
    from guardrails_lite.model import ScanStats

    stats = ScanStats()
    text = "mail a@example.com " + "filler " * 500
    scan_stream(
        [text[i : i + 64] for i in range(0, len(text), 64)], chunk_size=64, stats=stats
    )
    assert stats.chunks >= 8
    assert stats.chars_scanned == len(text)
    assert stats.per_detector.get("email") == 1
