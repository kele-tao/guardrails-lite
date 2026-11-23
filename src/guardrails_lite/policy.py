"""Policy engine: per-detector actions, thresholds, allowlists, custom regex.

Policies are plain dicts (JSON or the YAML subset in :mod:`guardrails_lite.yamlish`).
A policy never changes what a detector *finds*; it changes what happens to a
finding: it can be dropped by an allowlist, softened, escalated, or handed to a
custom regex rule.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detectors import DETECTORS, all_detectors
from .model import ACTION_RANK, SEVERITY_ORDER, Action, Finding, Severity, strongest

VALID_ACTIONS = frozenset(ACTION_RANK)
VALID_CATEGORIES = frozenset(("pii", "secret", "injection", "encoding"))


class PolicyError(ValueError):
    """Raised when a policy document is not usable. Message is user-facing."""


@dataclass(frozen=True, slots=True)
class CustomRule:
    """A user-supplied regex rule evaluated alongside the built-in detectors."""

    id: str
    pattern: re.Pattern[str]
    severity: Severity = "medium"
    action: Action = "flag"
    name: str = ""
    description: str = "Custom regex rule."

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pattern": self.pattern.pattern,
            "severity": self.severity,
            "action": self.action,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class AllowRule:
    """Drops findings that match. Matching is on the finding text or its span."""

    detector: str
    pattern: re.Pattern[str] | None = None
    value: str | None = None

    def drops(self, finding: Finding) -> bool:
        if self.detector not in ("*", finding.detector_id):
            return False
        if self.value is not None:
            return finding.text == self.value
        if self.pattern is not None:
            return bool(self.pattern.search(finding.text))
        return True


@dataclass(frozen=True, slots=True)
class Policy:
    """A validated, immutable policy."""

    name: str = "default"
    description: str = ""
    actions: dict[str, str] = field(default_factory=dict)
    min_severity: str = "info"
    min_score: float = 0.0
    enabled: frozenset[str] = frozenset()
    disabled: frozenset[str] = frozenset()
    allowlist: tuple[AllowRule, ...] = ()
    custom_rules: tuple[CustomRule, ...] = ()
    block_action: str = "block"
    default_action: str = "flag"
    salt: str = "guardrails-lite"
    reversible: bool = False

    # -- construction ------------------------------------------------------

    def detector_action(self, detector_id: str) -> str:
        """Action for a detector id, falling back to the detector default.

        Custom regex rules carry their own action and take precedence over the
        generic default; an explicit entry in the policy's actions map always
        wins so a deployment can override a rule without editing it.
        """
        if detector_id in self.actions:
            return self.actions[detector_id]
        det = DETECTORS.get(detector_id)
        if det is not None:
            return det.action
        for rule in self.custom_rules:
            if rule.id == detector_id:
                return rule.action
        return self.default_action

    def active_detectors(self) -> list[Any]:
        """Detectors enabled by this policy, sorted by id."""
        chosen = []
        for det in all_detectors():
            if det.id in self.disabled:
                continue
            if self.enabled and det.id not in self.enabled:
                continue
            if SEVERITY_ORDER.index(det.severity) < SEVERITY_ORDER.index(self.min_severity):
                continue
            chosen.append(det)
        return chosen

    def keep(self, finding: Finding) -> bool:
        """True when the finding survives allowlists, score and severity gates."""
        if SEVERITY_ORDER.index(finding.severity) < SEVERITY_ORDER.index(self.min_severity):
            return False
        if finding.score < self.min_score:
            return False
        return not any(rule.drops(finding) for rule in self.allowlist)

    def effective_action(self, findings: list[Finding]) -> Action:
        """Overall verdict action for a set of findings."""
        if not findings:
            return "allow"
        return strongest([self.detector_action(f.detector_id) for f in findings])

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "min_severity": self.min_severity,
            "min_score": self.min_score,
            "enabled": sorted(self.enabled),
            "disabled": sorted(self.disabled),
            "actions": dict(sorted(self.actions.items())),
            "allowlist": [
                {"detector": r.detector, "value": r.value,
                 "pattern": r.pattern.pattern if r.pattern else None}
                for r in self.allowlist
            ],
            "custom_rules": [r.to_dict() for r in self.custom_rules],
            "salt": self.salt,
            "reversible": self.reversible,
        }


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def _require_mapping(doc: Any, where: str) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise PolicyError(f"{where}: expected a mapping, got {type(doc).__name__}")
    return doc


def _as_action(value: Any, where: str) -> str:
    if not isinstance(value, str) or value not in VALID_ACTIONS:
        raise PolicyError(
            f"{where}: action must be one of {sorted(VALID_ACTIONS)}, got {value!r}"
        )
    return value


def _as_severity(value: Any, where: str) -> str:
    if not isinstance(value, str) or value not in SEVERITY_ORDER:
        raise PolicyError(
            f"{where}: severity must be one of {list(SEVERITY_ORDER)}, got {value!r}"
        )
    return value


def _parse_allowlist(raw: Any) -> tuple[AllowRule, ...]:
    rules: list[AllowRule] = []
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError("allowlist: expected a list of rules")
    for i, item in enumerate(raw):
        where = f"allowlist[{i}]"
        entry = _require_mapping(item, where)
        detector = entry.get("detector", "*")
        if not isinstance(detector, str):
            raise PolicyError(f"{where}.detector: expected a string")
        if detector != "*" and detector not in DETECTORS:
            raise PolicyError(f"{where}.detector: unknown detector {detector!r}")
        value = entry.get("value")
        pattern_raw = entry.get("pattern")
        if value is not None and not isinstance(value, str):
            raise PolicyError(f"{where}.value: expected a string")
        if pattern_raw is not None and not isinstance(pattern_raw, str):
            raise PolicyError(f"{where}.pattern: expected a string")
        if value is None and pattern_raw is None:
            rules.append(AllowRule(detector=detector))
            continue
        pattern = None
        if pattern_raw is not None:
            try:
                pattern = re.compile(pattern_raw)
            except re.error as exc:
                raise PolicyError(f"{where}.pattern: invalid regex ({exc})") from exc
        rules.append(AllowRule(detector=detector, pattern=pattern, value=value))
    return tuple(rules)


def _parse_custom_rules(raw: Any) -> tuple[CustomRule, ...]:
    rules: list[CustomRule] = []
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyError("custom: expected a list of rules")
    seen: set[str] = set()
    for i, item in enumerate(raw):
        where = f"custom[{i}]"
        entry = _require_mapping(item, where)
        rule_id = entry.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"{where}.id: expected a non-empty string")
        if rule_id in seen:
            raise PolicyError(f"{where}.id: duplicate custom rule id {rule_id!r}")
        seen.add(rule_id)
        pattern_raw = entry.get("pattern")
        if not isinstance(pattern_raw, str) or not pattern_raw:
            raise PolicyError(f"{where}.pattern: expected a non-empty string")
        if len(pattern_raw) > 2000:
            raise PolicyError(f"{where}.pattern: longer than 2000 characters")
        try:
            pattern = re.compile(pattern_raw)
        except re.error as exc:
            raise PolicyError(f"{where}.pattern: invalid regex ({exc})") from exc
        severity = _as_severity(entry.get("severity", "medium"), f"{where}.severity")
        action = _as_action(entry.get("action", "flag"), f"{where}.action")
        name = entry.get("name", rule_id)
        if not isinstance(name, str):
            raise PolicyError(f"{where}.name: expected a string")
        description = entry.get("description", "Custom regex rule.")
        if not isinstance(description, str):
            raise PolicyError(f"{where}.description: expected a string")
        rules.append(
            CustomRule(
                id=rule_id,
                pattern=pattern,
                severity=severity,  # type: ignore[arg-type]
                action=action,  # type: ignore[arg-type]
                name=name,
                description=description,
            )
        )
    return tuple(rules)


def parse_policy(doc: Any) -> Policy:
    """Validate a mapping and return a Policy. Raises PolicyError when invalid."""
    root = _require_mapping(doc, "policy")
    known = {
        "name", "description", "version", "actions", "detectors", "min_severity",
        "min_score", "allowlist", "custom", "salt", "reversible", "default_action",
    }
    unknown = sorted(set(root) - known)
    if unknown:
        raise PolicyError(
            "policy: unknown key(s) "
            + ", ".join(unknown)
            + "; known keys: "
            + ", ".join(sorted(known))
        )

    name = root.get("name", "default")
    if not isinstance(name, str) or not name.strip():
        raise PolicyError("name: expected a non-empty string")
    description = root.get("description", "")
    if not isinstance(description, str):
        raise PolicyError("description: expected a string")

    actions: dict[str, str] = {}
    raw_actions = root.get("actions")
    if raw_actions is not None:
        mapping = _require_mapping(raw_actions, "actions")
        for key, value in mapping.items():
            if key != "*" and key not in DETECTORS:
                raise PolicyError(
                    f"actions: unknown detector {key!r}; "
                    "run 'guardrails-lite detectors' to list ids"
                )
            actions[key] = _as_action(value, f"actions.{key}")

    enabled: frozenset[str] = frozenset()
    disabled: frozenset[str] = frozenset()
    detectors_raw = root.get("detectors")
    if detectors_raw is not None:
        mapping = _require_mapping(detectors_raw, "detectors")
        enable = mapping.get("enable")
        disable = mapping.get("disable")
        if enable is not None:
            if not isinstance(enable, list) or not all(isinstance(x, str) for x in enable):
                raise PolicyError("detectors.enable: expected a list of detector ids")
            bad = [x for x in enable if x not in DETECTORS]
            if bad:
                raise PolicyError("detectors.enable: unknown detector(s) " + ", ".join(bad))
            enabled = frozenset(enable)
        if disable is not None:
            if not isinstance(disable, list) or not all(isinstance(x, str) for x in disable):
                raise PolicyError("detectors.disable: expected a list of detector ids")
            bad = [x for x in disable if x not in DETECTORS]
            if bad:
                raise PolicyError("detectors.disable: unknown detector(s) " + ", ".join(bad))
            disabled = frozenset(disable)
        unknown_det = sorted(set(mapping) - {"enable", "disable"})
        if unknown_det:
            raise PolicyError("detectors: unknown key(s) " + ", ".join(unknown_det))

    min_severity = _as_severity(root.get("min_severity", "info"), "min_severity")
    min_score_raw = root.get("min_score", 0.0)
    if not isinstance(min_score_raw, (int, float)) or isinstance(min_score_raw, bool):
        raise PolicyError("min_score: expected a number between 0 and 1")
    min_score = float(min_score_raw)
    if not 0.0 <= min_score <= 1.0:
        raise PolicyError("min_score: expected a number between 0 and 1")

    salt = root.get("salt", "guardrails-lite")
    if not isinstance(salt, str) or not salt:
        raise PolicyError("salt: expected a non-empty string")
    reversible = root.get("reversible", False)
    if not isinstance(reversible, bool):
        raise PolicyError("reversible: expected true or false")
    default_action = _as_action(root.get("default_action", "flag"), "default_action")

    policy = Policy(
        name=name.strip(),
        description=description,
        actions=actions,
        min_severity=min_severity,
        min_score=min_score,
        enabled=enabled,
        disabled=disabled,
        allowlist=_parse_allowlist(root.get("allowlist")),
        custom_rules=_parse_custom_rules(root.get("custom")),
        default_action=default_action,
        salt=salt,
        reversible=reversible,
    )
    _ = policy.active_detectors()  # validates the enable/disable/severity combination
    return policy


def load_policy(path: str | Path) -> Policy:
    """Load a JSON or YAML policy file. Raises PolicyError with a friendly message."""
    p = Path(path)
    if not p.exists():
        raise PolicyError(f"policy file not found: {path}")
    if p.is_dir():
        raise PolicyError(f"policy path is a directory: {path}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyError(f"policy file is not valid UTF-8: {path}") from exc
    if not text.strip():
        raise PolicyError(f"policy file is empty: {path}")
    suffix = p.suffix.lower()
    if suffix == ".json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyError(
                f"{path}:{exc.lineno}:{exc.colno}: invalid JSON ({exc.msg})"
            ) from exc
    elif suffix in (".yaml", ".yml"):
        from .yamlish import load_yaml

        try:
            doc = load_yaml(text)
        except ValueError as exc:
            raise PolicyError(f"{path}: invalid YAML ({exc})") from exc
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            from .yamlish import load_yaml

            try:
                doc = load_yaml(text)
            except ValueError as exc:
                raise PolicyError(
                    f"{path}: not valid JSON ({exc}); YAML is only auto-detected for "
                    ".yaml/.yml files"
                ) from exc
    return parse_policy(doc)


DEFAULT_POLICY = Policy(name="default", description="Built-in default policy.")


def default_policy() -> Policy:
    """The policy used when none is supplied."""
    return DEFAULT_POLICY


def policy_summary(policy: Policy) -> dict[str, Any]:
    """Small dict used by the 'policy check' CLI command."""
    dets = policy.active_detectors()
    return {
        "name": policy.name,
        "description": policy.description,
        "detectors": len(dets),
        "custom_rules": len(policy.custom_rules),
        "allowlist_rules": len(policy.allowlist),
        "min_severity": policy.min_severity,
        "min_score": policy.min_score,
        "salt_set": bool(policy.salt),
        "reversible": policy.reversible,
        # Only explicit overrides are interesting here; the detector defaults are
        # already visible in 'guardrails-lite detectors'.
        "actions": dict(sorted(policy.actions.items())),
    }


def now_us() -> float:
    """Monotonic microsecond clock used for timing without wall-clock drift."""
    return time.perf_counter() * 1_000_000
