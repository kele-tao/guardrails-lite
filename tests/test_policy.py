"""Policy engine: JSON and YAML loading, validation, allowlists, custom rules."""

from __future__ import annotations

import json

import pytest

from conftest import SAMPLE_AWS_KEY_ID
from guardrails_lite.policy import (
    PolicyError,
    default_policy,
    load_policy,
    parse_policy,
    policy_summary,
)
from guardrails_lite.scanner import scan
from guardrails_lite.yamlish import load_yaml


def test_default_policy_is_usable():
    policy = default_policy()
    assert policy.name == "default"
    assert len(policy.active_detectors()) >= 25
    assert policy.effective_action([]) == "allow"


def test_minimal_policy_document():
    policy = parse_policy({"name": "min", "actions": {"email": "block"}})
    assert policy.name == "min"
    assert policy.detector_action("email") == "block"
    assert policy.detector_action("phone") == "redact"


def test_policy_rejects_unknown_keys_with_help():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"name": "x", "actons": {}})
    assert "unknown key" in str(exc.value)
    assert "actions" in str(exc.value)


def test_policy_rejects_unknown_detector_id():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"actions": {"emial": "block"}})
    assert "unknown detector" in str(exc.value)


@pytest.mark.parametrize("bad", ["deny", 3, None, "BLOCK"])
def test_policy_rejects_bad_actions(bad):
    with pytest.raises(PolicyError):
        parse_policy({"actions": {"email": bad}})


@pytest.mark.parametrize("bad", ["severe", 4, None])
def test_policy_rejects_bad_severity(bad):
    with pytest.raises(PolicyError):
        parse_policy({"min_severity": bad})


@pytest.mark.parametrize("score", [-0.1, 1.5, "high", True])
def test_policy_rejects_bad_min_score(score):
    with pytest.raises(PolicyError):
        parse_policy({"min_score": score})


def test_policy_enable_disable_validation():
    policy = parse_policy({"detectors": {"disable": ["phone", "mac_address"]}})
    active = {d.id for d in policy.active_detectors()}
    assert "phone" not in active
    assert "email" in active
    with pytest.raises(PolicyError):
        parse_policy({"detectors": {"disable": ["nope"]}})


def test_min_severity_filters_detectors():
    policy = parse_policy({"min_severity": "critical"})
    active = {d.id for d in policy.active_detectors()}
    assert "email" not in active
    assert "aws_access_key" in active


def test_allowlist_value_and_pattern():
    policy = parse_policy(
        {
            "allowlist": [
                {"detector": "email", "value": "noreply@example.com"},
                {"detector": "ipv4", "pattern": "^10\\."},
            ]
        }
    )
    verdict = scan("noreply@example.com and 10.1.2.3 and dev@example.com", policy)
    found = {f.detector_id for f in verdict.findings}
    assert "email" in found
    assert "ipv4" not in found
    assert verdict.suppressed >= 2


def test_allowlist_pattern_applies_to_every_detector():
    policy = parse_policy({"allowlist": [{"pattern": "^ASIA"}]})
    verdict = scan(SAMPLE_AWS_KEY_ID + " and 13800138000", policy)
    # The wildcard rule suppresses the AWS key but never the phone number.
    assert {f.detector_id for f in verdict.findings} == {"phone"}
    assert verdict.suppressed == 1


def test_allowlist_rejects_bad_regex():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"allowlist": [{"detector": "email", "pattern": "(["}]})
    assert "invalid regex" in str(exc.value)


def test_custom_regex_rules_are_findings():
    policy = parse_policy(
        {
            "custom": [
                {
                    "id": "ticket",
                    "pattern": "TICKET-\\d{4}",
                    "severity": "high",
                    "action": "block",
                    "name": "Support ticket",
                }
            ]
        }
    )
    verdict = scan("see TICKET-4821 for details", policy)
    assert verdict.action == "block"
    (finding,) = [f for f in verdict.findings if f.detector_id == "ticket"]
    assert finding.start == 4
    assert finding.name == "Support ticket"
    assert finding.category == "custom"


def test_custom_rules_reject_duplicates_and_bad_regex():
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "a", "pattern": "x"}, {"id": "a", "pattern": "y"}]})
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "a", "pattern": "("}]})
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"pattern": "x"}]})


def test_load_json_policy(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"name": "file-policy", "min_severity": "high"}), encoding="utf-8")
    policy = load_policy(path)
    assert policy.name == "file-policy"
    assert policy.min_severity == "high"


def test_load_yaml_policy(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(
        "name: yaml-policy\n"
        "min_severity: high\n"
        "actions:\n"
        "  email: block\n"
        "  phone: flag\n"
        "custom:\n"
        "  - id: order\n"
        "    pattern: 'ORD-\\d{6}'\n"
        "    severity: medium\n"
        "    action: redact\n"
        "allowlist:\n"
        "  - detector: ipv4\n"
        "    pattern: '^127\\.'\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.name == "yaml-policy"
    assert policy.detector_action("email") == "block"
    assert policy.custom_rules[0].id == "order"
    assert len(policy.allowlist) == 1


def test_load_policy_errors_are_friendly(tmp_path):
    with pytest.raises(PolicyError) as exc:
        load_policy(tmp_path / "missing.json")
    assert "not found" in str(exc.value)

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(bad_json)
    assert "invalid JSON" in str(exc.value)

    empty = tmp_path / "empty.json"
    empty.write_text("   ", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(empty)
    assert "empty" in str(exc.value)

    directory = tmp_path / "dir.json"
    directory.mkdir()
    with pytest.raises(PolicyError) as exc:
        load_policy(directory)
    assert "directory" in str(exc.value)


def test_policy_summary_counts():
    policy = load_policy_root()
    summary = policy_summary(policy)
    assert summary["name"] == "default"
    assert summary["detectors"] >= 25
    assert summary["salt_set"] is True
    assert isinstance(summary["actions"], dict)


def load_policy_root():
    from pathlib import Path

    return load_policy(Path(__file__).resolve().parent.parent / "policies" / "default.json")


def test_yaml_subset_parses_nested_structures():
    doc = load_yaml(
        "name: test\n"
        "list:\n"
        "  - a\n"
        "  - b: 1\n"
        "    c: true\n"
        "nested:\n"
        "  inner:\n"
        "    deep: 2.5\n"
        "quoted: 'has # hash'\n"
    )
    assert doc["name"] == "test"
    assert doc["list"] == ["a", {"b": 1, "c": True}]
    assert doc["nested"]["inner"]["deep"] == 2.5
    assert doc["quoted"] == "has # hash"


def test_yaml_subset_rejects_unsupported_features():
    with pytest.raises(ValueError):
        load_yaml("a: |\n  block\n")
    with pytest.raises(ValueError):
        load_yaml("a:\n    b: 1\n  c: 2\n")
