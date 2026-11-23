"""Validation edge cases for the policy engine.

These tests exist because a policy is the safety-critical configuration surface:
a silently accepted typo can disable a detector, so every rejection path must
produce a specific, actionable message rather than a traceback.
"""

from __future__ import annotations

import json

import pytest

from guardrails_lite.detectors import all_detectors
from guardrails_lite.model import Finding, severity_rank, strongest
from guardrails_lite.policy import (
    AllowRule,
    CustomRule,
    Policy,
    PolicyError,
    load_policy,
    parse_policy,
    policy_summary,
)


def finding(detector_id="email", severity="medium", score=0.9, text="a@b.co"):
    return Finding(
        detector_id=detector_id,
        name=detector_id,
        category="pii",
        severity=severity,  # type: ignore[arg-type]
        start=0,
        end=len(text),
        text=text,
        score=score,
    )


def test_policy_defaults_are_documented_behaviour():
    policy = parse_policy({})
    assert policy.name == "default"
    assert policy.min_severity == "info"
    assert policy.min_score == 0.0
    assert policy.salt == "guardrails-lite"
    assert policy.reversible is False
    assert policy.default_action == "flag"
    assert policy.enabled == frozenset()
    assert policy.disabled == frozenset()
    assert policy.allowlist == ()
    assert policy.custom_rules == ()


def test_unknown_detector_action_is_rejected_with_hint():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"actions": {"emial": "block"}})
    message = str(exc.value)
    assert "emial" in message
    assert "detectors" in message


def test_name_must_be_non_empty_string():
    for bad in ("", "   ", 3, None):
        with pytest.raises(PolicyError):
            parse_policy({"name": bad})


def test_description_must_be_string():
    with pytest.raises(PolicyError):
        parse_policy({"description": 7})


def test_salt_must_be_non_empty_string():
    with pytest.raises(PolicyError):
        parse_policy({"salt": ""})
    with pytest.raises(PolicyError):
        parse_policy({"salt": 42})


def test_reversible_must_be_boolean():
    with pytest.raises(PolicyError):
        parse_policy({"reversible": "yes"})


def test_detectors_section_shape_is_enforced():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"detectors": ["email"]})
    assert "mapping" in str(exc.value)
    with pytest.raises(PolicyError):
        parse_policy({"detectors": {"enable": "email"}})
    with pytest.raises(PolicyError):
        parse_policy({"detectors": {"disable": [1, 2]}})
    with pytest.raises(PolicyError) as exc:
        parse_policy({"detectors": {"ignore": ["email"]}})
    assert "unknown key" in str(exc.value)


def test_enable_list_restricts_detectors():
    policy = parse_policy({"detectors": {"enable": ["email", "phone"]}})
    assert [d.id for d in policy.active_detectors()] == ["email", "phone"]


def test_enable_and_disable_combine():
    policy = parse_policy({"detectors": {"enable": ["email", "phone"], "disable": ["phone"]}})
    assert [d.id for d in policy.active_detectors()] == ["email"]


def test_actions_must_be_known_words():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"actions": {"email": "quarantine"}})
    assert "action must be one of" in str(exc.value)


def test_wildcard_action_is_accepted_but_not_used_for_unknown_detectors():
    policy = parse_policy({"actions": {"*": "block"}})
    assert policy.actions == {"*": "block"}
    assert policy.detector_action("email") == "redact"


def test_allowlist_shape_is_enforced():
    with pytest.raises(PolicyError):
        parse_policy({"allowlist": {"detector": "email"}})
    with pytest.raises(PolicyError) as exc:
        parse_policy({"allowlist": [{"detector": "nope"}]})
    assert "unknown detector" in str(exc.value)
    with pytest.raises(PolicyError):
        parse_policy({"allowlist": [{"detector": "email", "value": 5}]})
    with pytest.raises(PolicyError):
        parse_policy({"allowlist": [{"detector": "email", "pattern": 5}]})


def test_allowlist_without_value_or_pattern_drops_every_finding_of_that_detector():
    rule = AllowRule(detector="email")
    assert rule.drops(finding("email")) is True
    assert rule.drops(finding("phone")) is False


def test_allowlist_value_is_exact_match_only():
    rule = AllowRule(detector="email", value="a@b.co")
    assert rule.drops(finding(text="a@b.co"))
    assert not rule.drops(finding(text="a@b.com"))


def test_allowlist_pattern_matches_substring():
    import re

    rule = AllowRule(detector="ipv4", pattern=re.compile(r"^10\."))
    assert rule.drops(finding("ipv4", text="10.1.2.3"))
    assert not rule.drops(finding("ipv4", text="11.1.2.3"))


def test_custom_rule_validates_severity_and_action():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"custom": [{"id": "x", "pattern": "y", "severity": "urgent"}]})
    assert "severity must be one of" in str(exc.value)
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "x", "pattern": "y", "action": "nope"}]})


def test_custom_rule_requires_pattern_text():
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "x"}]})
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "x", "pattern": ""}]})


def test_custom_rule_rejects_long_pattern():
    with pytest.raises(PolicyError) as exc:
        parse_policy({"custom": [{"id": "x", "pattern": "a" * 2001}]})
    assert "2000" in str(exc.value)


def test_custom_rule_requires_id_string():
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"pattern": "x"}]})
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "", "pattern": "x"}]})


def test_custom_rule_fields_have_types():
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "x", "pattern": "y", "name": 5}]})
    with pytest.raises(PolicyError):
        parse_policy({"custom": [{"id": "x", "pattern": "y", "description": 5}]})


def test_custom_rule_to_dict_round_trips():
    policy = parse_policy({"custom": [{"id": "ticket", "pattern": "T-\\d+", "action": "block"}]})
    entry = policy.custom_rules[0].to_dict()
    assert entry["id"] == "ticket"
    assert entry["pattern"] == "T-\\d+"
    assert entry["action"] == "block"
    assert json.loads(json.dumps(entry))["id"] == "ticket"


def test_policy_to_dict_is_json_serialisable():
    policy = parse_policy(
        {
            "name": "serial",
            "actions": {"email": "block"},
            "allowlist": [{"detector": "ipv4", "pattern": "^10\\."}],
            "custom": [{"id": "t", "pattern": "x"}],
        }
    )
    data = json.loads(json.dumps(policy.to_dict()))
    assert data["name"] == "serial"
    assert data["actions"] == {"email": "block"}
    assert data["allowlist"][0]["pattern"] == "^10\\."
    assert data["custom_rules"][0]["id"] == "t"


def test_detector_action_falls_back_through_custom_rules_then_default():
    policy = parse_policy(
        {
            "default_action": "flag",
            "custom": [{"id": "ticket", "pattern": "T-1", "action": "block"}],
        }
    )
    assert policy.detector_action("ticket") == "block"
    assert policy.detector_action("unknown-id") == "flag"


def test_severity_rank_and_strongest_helpers():
    assert [severity_rank(s) for s in ("info", "low", "medium", "high", "critical")] == [
        0, 1, 2, 3, 4
    ]
    with pytest.raises(ValueError):
        severity_rank("nope")
    assert strongest([]) == "allow"
    assert strongest(["allow", "flag"]) == "flag"
    assert strongest(["redact", "block", "flag"]) == "block"
    assert strongest(["redact", "flag"]) == "redact"


def test_keep_applies_score_and_severity_in_order():
    policy = Policy(min_severity="high", min_score=0.8)
    assert not policy.keep(finding(severity="medium", score=0.99))
    assert not policy.keep(finding(severity="high", score=0.5))
    assert policy.keep(finding(severity="high", score=0.9))


def test_effective_action_uses_strongest_detector_action():
    policy = parse_policy({"actions": {"email": "flag", "credit_card": "block"}})
    assert policy.effective_action([]) == "allow"
    assert policy.effective_action([finding("email")]) == "flag"
    assert policy.effective_action([finding("email"), finding("credit_card")]) == "block"


def test_custom_rule_dataclass_is_frozen():
    import dataclasses

    rule = CustomRule(id="x", pattern=__import__("re").compile("y"))
    assert rule.id == "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.id = "z"  # type: ignore[misc]


def test_load_policy_reads_yaml_from_yml_extension(tmp_path):
    path = tmp_path / "p.yml"
    path.write_text("name: from-yml\nactions:\n  email: block\n", encoding="utf-8")
    policy = load_policy(path)
    assert policy.name == "from-yml"
    assert policy.detector_action("email") == "block"


def test_load_policy_detects_json_in_a_txt_extension(tmp_path):
    path = tmp_path / "p.txt"
    path.write_text(json.dumps({"name": "txt-json"}), encoding="utf-8")
    assert load_policy(path).name == "txt-json"
    path.write_text("name: txt-yaml\n", encoding="utf-8")
    assert load_policy(path).name == "txt-yaml"


def test_load_policy_yaml_error_is_reported_with_path(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("a: |\n  block\n", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(path)
    assert "invalid YAML" in str(exc.value)


def test_load_policy_invalid_utf8(tmp_path):
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe{")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_policy_summary_reports_only_overrides():
    policy = parse_policy({"name": "s", "actions": {"email": "block"}})
    summary = policy_summary(policy)
    assert summary["actions"] == {"email": "block"}
    assert summary["detectors"] == len(policy.active_detectors())
    assert summary["salt_set"] is True


def test_every_detector_id_is_a_valid_policy_target():
    """A policy must be able to name any detector the registry exposes."""
    policy = parse_policy({"detectors": {"enable": [d.id for d in all_detectors()]}})
    assert len(policy.active_detectors()) == len(all_detectors())
