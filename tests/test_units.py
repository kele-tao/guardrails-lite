"""Unit tests for the YAML subset parser, detector primitives and the model."""

from __future__ import annotations

import json
import re

import pytest

from guardrails_lite.detectors.base import Detector, Span, dedupe, keyword_spans, regex_spans
from guardrails_lite.model import (
    Finding,
    ScanStats,
    Verdict,
    severity_rank,
    strongest,
)
from guardrails_lite.yamlish import _strip_comment, load_yaml

# ---------------------------------------------------------------- YAML subset


def test_yaml_scalars_and_comments():
    doc = load_yaml(
        "plain: hello world\n"
        "number: 42\n"
        "negative: -7\n"
        "ratio: 0.25\n"
        "flag: true\n"
        "off: no\n"
        "nothing: null\n"
        "tilde: ~\n"
        "quoted: 'a: b'\n"
        'dq: "line\\nbreak"\n'
        "hash: value # trailing comment\n"
        "kept: 'has # inside'\n"
    )
    assert doc["plain"] == "hello world"
    assert doc["number"] == 42 and isinstance(doc["number"], int)
    assert doc["negative"] == -7
    assert doc["ratio"] == 0.25
    assert doc["flag"] is True
    assert doc["off"] is False
    assert doc["nothing"] is None
    assert doc["tilde"] is None
    assert doc["quoted"] == "a: b"
    assert doc["dq"] == "line\nbreak"
    assert doc["hash"] == "value"
    assert doc["kept"] == "has # inside"


def test_yaml_sequences_of_mappings_and_scalars():
    doc = load_yaml(
        "items:\n"
        "  - one\n"
        "  - two\n"
        "rules:\n"
        "  - id: a\n"
        "    severity: high\n"
        "  - id: b\n"
        "    nested:\n"
        "      deep: 1\n"
    )
    assert doc["items"] == ["one", "two"]
    assert doc["rules"][0] == {"id": "a", "severity": "high"}
    assert doc["rules"][1]["nested"]["deep"] == 1


def test_yaml_empty_document_and_doc_marker():
    assert load_yaml("") == {}
    assert load_yaml("\n\n# only a comment\n") == {}
    assert load_yaml("---\nname: x\n") == {"name": "x"}


def test_yaml_rejects_unsupported_constructs():
    with pytest.raises(ValueError):
        load_yaml("a: *alias\n")
    with pytest.raises(ValueError):
        load_yaml("a: &anchor value\n")
    with pytest.raises(ValueError):
        load_yaml("a:\n\tb: 1\n")


def test_yaml_rejects_inconsistent_indentation():
    with pytest.raises(ValueError):
        load_yaml("a:\n    b: 1\n  c: 2\n")
    with pytest.raises(ValueError):
        load_yaml("a: 1\n  b: 2\n")


def test_yaml_rejects_unexpected_content():
    with pytest.raises(ValueError):
        load_yaml("- a\nb: 1\n")
    with pytest.raises(ValueError):
        load_yaml("just some text\n")


def test_strip_comment_keeps_hash_inside_quotes():
    assert _strip_comment("key: 'a # b'  # real") == "key: 'a # b'"
    assert _strip_comment("# whole line") == ""
    assert _strip_comment("a: b#not-a-comment") == "a: b#not-a-comment"


# ------------------------------------------------------------ detector basics

def test_regex_spans_respects_validator_and_group():
    pattern = re.compile(r"(secret)=(\w+)")
    scan = regex_spans(pattern, validate=lambda m: len(m.group(2)) > 3, group=2)
    spans = list(scan("secret=abcd secret=xy"))
    assert len(spans) == 1
    assert (spans[0].start, spans[0].end) == (7, 11)
    assert spans[0].metadata == ()


def test_regex_spans_metadata_uses_named_groups():
    pattern = re.compile(r"(?P<scheme>https?)://(?P<host>[a-z.]+)")
    spans = list(regex_spans(pattern)("see https://example.com now"))
    assert spans[0].metadata == (("scheme", "https"), ("host", "example.com"))
    assert list(regex_spans(pattern)("bbb")) == []


def test_detector_find_rejects_out_of_range_spans():
    det = Detector(
        id="bad",
        name="Bad",
        category="pii",
        severity="low",
        description="d" * 12,
        false_positives="f" * 12,
        scan=lambda text: [Span(-5, 3), Span(0, len(text) + 5), Span(2, 2), Span(0, 1)],
    )
    findings = det.find("hello")
    assert [(f.start, f.end) for f in findings] == [(0, 1)]


def test_detector_uses_needs_and_prefilter():
    calls = []

    def scan(text):
        calls.append(text)
        return [Span(0, 1)]

    det = Detector(
        id="probe",
        name="Probe",
        category="pii",
        severity="low",
        description="d" * 12,
        false_positives="f" * 12,
        scan=scan,
        needs=("needle",),
        prefilter=re.compile(r"hay"),
    )
    assert det.find("nothing here") == []
    assert det.find("a needle but no straw") == []
    assert list(calls) == []
    assert det.find("a needle in the haystack")
    assert calls == ["a needle in the haystack"]


def test_detector_prefilter_can_be_a_callable():
    det = Detector(
        id="probe2",
        name="Probe 2",
        category="pii",
        severity="low",
        description="d" * 12,
        false_positives="f" * 12,
        scan=lambda text: [Span(0, 1)],
        prefilter=lambda text: "go" in text,
    )
    assert det.find("stop") == []
    assert det.find("go now")


def test_detector_to_dict_is_serialisable():
    det = Detector(
        id="x",
        name="X",
        category="pii",
        severity="high",
        description="desc",
        false_positives="fp",
        scan=lambda text: [],
        action="block",
    )
    data = json.loads(json.dumps(det.to_dict()))
    assert data == {
        "id": "x",
        "name": "X",
        "category": "pii",
        "severity": "high",
        "action": "block",
        "description": "desc",
        "false_positives": "fp",
    }


def test_dedupe_keeps_widest_and_drops_nested():
    spans = [Span(0, 10), Span(2, 5), Span(10, 12), Span(10, 12)]
    assert [(s.start, s.end) for s in dedupe(spans)] == [(0, 10), (10, 12)]


def test_keyword_spans_carries_hint_metadata():
    spans = list(
        keyword_spans(
            "ignore this", re.compile(r"ignore"), score=0.5, note="kw", severity_hint="high"
        )
    )
    assert spans[0].metadata == (("hint", "high"),)
    assert spans[0].score == 0.5
    assert spans[0].note == "kw"


# ------------------------------------------------------------------- model


def make_finding(**kwargs):
    base = {
        "detector_id": "email",
        "name": "Email",
        "category": "pii",
        "severity": "medium",
        "start": 3,
        "end": 9,
        "text": "a@b.co",
    }
    base.update(kwargs)
    return Finding(**base)  # type: ignore[arg-type]


def test_finding_properties_and_serialisation():
    f = make_finding()
    assert f.length == 6
    assert f.to_dict()["length"] == 6
    assert "text" not in f.to_dict()
    assert f.to_dict(include_text=True)["text"] == "a@b.co"


def test_finding_metadata_is_serialised():
    f = make_finding(metadata=(("decoded_len", "54"),))
    assert f.to_dict()["metadata"] == {"decoded_len": "54"}


def test_finding_overlap_semantics():
    a = make_finding(start=0, end=5)
    b = make_finding(start=4, end=9)
    c = make_finding(start=5, end=9)
    assert a.overlaps(b)
    assert not a.overlaps(c)
    assert b.overlaps(a)


def test_verdict_helpers_and_json_determinism():
    findings = (make_finding(), make_finding(detector_id="phone", category="pii", start=20, end=31))
    verdict = Verdict(action="redact", findings=findings, text_length=100)
    assert verdict.flagged is True
    assert verdict.by_category() == {"pii": 2}
    first = verdict.to_json()
    second = verdict.to_json()
    assert first == second
    assert "elapsed_us" not in first
    assert "elapsed_us" in verdict.to_json(include_timing=True)
    assert Verdict(action="allow").flagged is False


def test_verdict_redacted_field_round_trips():
    verdict = Verdict(action="redact", redacted="safe", text_length=4, policy_name="p")
    data = verdict.to_dict()
    assert data["redacted"] == "safe"
    assert data["policy"] == "p"
    assert data["counts"] == {}


def test_model_helpers():
    assert severity_rank("critical") == 4
    assert strongest(["flag", "allow"]) == "flag"
    stats = ScanStats()
    stats.chunks = 2
    stats.chars_scanned = 10
    stats.per_detector["email"] = 1
    assert stats.chunks == 2
