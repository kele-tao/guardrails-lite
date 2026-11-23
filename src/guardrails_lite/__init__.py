"""guardrails-lite: a dependency-free prompt-injection and PII firewall.

Single-call surface::

    from guardrails_lite import scan
    verdict = scan("email me at jane@example.com")
    verdict.action        # 'redact'
    verdict.redacted      # 'email me at [[EMAIL:9f2c...]]'

Everything is deterministic: the same input, policy and salt produce
byte-identical output, including pseudonymisation tokens.
"""

from .detectors import DETECTORS, Detector, all_detectors, get_detector
from .model import Finding, Severity, Verdict
from .policy import Policy, PolicyError, load_policy, parse_policy
from .redact import RedactionResult, ReversibleMap, redact, rehydrate
from .scanner import scan, scan_stream

__version__ = "1.0.0"

__all__ = [
    "DETECTORS",
    "Detector",
    "Finding",
    "Policy",
    "PolicyError",
    "RedactionResult",
    "ReversibleMap",
    "Severity",
    "Verdict",
    "all_detectors",
    "get_detector",
    "load_policy",
    "parse_policy",
    "redact",
    "rehydrate",
    "scan",
    "scan_stream",
]
