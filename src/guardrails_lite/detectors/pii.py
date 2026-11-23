"""PII and credential detectors (17 detectors).

Every detector returns character spans into the original text. Validators are
real: Luhn for payment cards, ISO 7064 mod-97 for IBANs, GB 11643 checksum for
Chinese resident IDs, structural checks for JWTs and private keys.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Severity
from .base import Detector, Span, regex_spans

# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------


def luhn(number: str) -> bool:
    """Return True when *number* passes the Luhn checksum."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(candidate: str) -> bool:
    """ISO 13616 / ISO 7064 mod-97-10 check for an IBAN candidate."""
    compact = re.sub(r"[\s\-]", "", candidate).upper()
    if not (15 <= len(compact) <= 34):
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) if ch.isalpha() else ch for ch in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:  # pragma: no cover - regex already guarantees digits
        return False


_CN_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_ID_CHECK = "10X98765432"


def cn_id_ok(candidate: str) -> bool:
    """GB 11643-1999 checksum plus a plausible birth date for an 18-char CN ID."""
    cid = candidate.strip().upper()
    if len(cid) != 18 or not cid[:17].isdigit():
        return False
    total = sum(int(cid[i]) * _CN_ID_WEIGHTS[i] for i in range(17))
    if _CN_ID_CHECK[total % 11] != cid[17]:
        return False
    year, month, day = cid[6:10], cid[10:12], cid[12:14]
    return year.startswith(("19", "20")) and 1 <= int(month) <= 12 and 1 <= int(day) <= 31


def jwt_ok(candidate: str) -> bool:
    """Structural check: three base64url segments, JSON-ish header, sane length."""
    parts = candidate.split(".")
    if len(parts) != 3:
        return False
    header = parts[0]
    return len(header) >= 10 and header.startswith("eyJ") and len(candidate) <= 4096


def _digits_only(m: re.Match[str]) -> bool:
    return any(c.isdigit() for c in m.group(0))


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+"
)

#: TLDs that appear as build metadata rather than in an address (user@2.0.1-nightly).
_VERSION_TLDS = frozenset(
    {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "jar", "war", "zip", "gz",
     "tar", "whl", "egg", "exe", "dmg", "msi", "pyc", "tmp", "log", "json", "lock"}
)


def _email_ok(m: re.Match[str]) -> bool:
    """Reject version-shaped matches such as commit user@2.0.1-nightly."""
    local, _, domain = m.group(0).partition("@")
    if not local or local[0] in ".-_" or local[-1] in ".-_" or ".." in local:
        return False
    labels = domain.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False
    tld = labels[-1].lower()
    if tld in _VERSION_TLDS:
        return False
    # TLDs are alphabetic (or punycode); "user@2.0.1-nightly" is build metadata.
    return tld.startswith("xn--") or (tld.isalpha() and len(tld) >= 2)

#: One pass for every phone shape. Exact shape is decided in _phone_spans, so
#: three separate full-document scans (and their three regex passes) disappear.
PHONE_RE = re.compile(
    r"(?<![\w+])(?:"
    r"(?:\+?86[\s\-]?)?1[3-9]\d{9}"  # CN mobile, optional country code
    r"|\+[1-9]\d{0,2}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?)?\d{3,4}[\s.\-]?\d{3,4}"  # intl
    r"|\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}"  # NANP local
    r")(?![\w])"
)

#: 13-19 digit run, optionally grouped by spaces/dashes; Luhn-validated in code.
CARD_RE = re.compile(r"(?<!\d)\d[\d \-]{11,17}\d(?!\d)")
IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Z]{2}\d{2}[\s\-]?)(?:[A-Z"
    r"0-9]{4}[\s\-]?){2,7}[A-Z0-9]{1,4}(?![A-Za-z0-9])"
)
#: Dotted-quad shape only; octet range is validated in _ipv4_spans, which is
#: twice as fast as spelling 0-255 out four times inside the regex.
IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|"
    r":(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:)"
    r")(?![0-9A-Fa-f:])"
)
JWT_RE = re.compile(
    r"(?<![\w.-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-"
    r"z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w.-])"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)
IPV4_NET_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(?:3[0-2]|[12]?\d)(?![\d.])"
)
CN_ID_RE = re.compile(
    r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0"
    r"-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
)
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:])")

# Credentials -------------------------------------------------------------

AWS_KEY_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}(?![A-Z0-9])")
GITHUB_TOKEN_RE = re.compile(
    r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,})(?![\w])"
)
OPENAI_KEY_RE = re.compile(r"(?<![\w-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}(?![\w-])")
SLACK_TOKEN_RE = re.compile(r"(?<![\w-])xox[abposr]-[A-Za-z0-9-]{10,}(?![\w-])")
GENERIC_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{16,})[\"']?"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-]{16,})")

# --------------------------------------------------------------------------
# Detector factory
# --------------------------------------------------------------------------


def _overlaps_sorted(seen: list[tuple[int, int]], start: int, end: int) -> bool:
    """True when [start, end) intersects any interval in *seen* (sorted by start).

    Binary search keeps the phone scan O(n log n) on documents with thousands of
    candidates; the naive any() loop was O(n^2).
    """
    lo, hi = 0, len(seen)
    while lo < hi:
        mid = (lo + hi) // 2
        if seen[mid][0] < start:
            lo = mid + 1
        else:
            hi = mid
    for idx in (lo - 1, lo):
        if 0 <= idx < len(seen) and seen[idx][1] > start and seen[idx][0] < end:
            return True
    return False


def _phone_spans(text: str) -> Iterable[Span]:
    """Classify phone-shaped matches from the single combined pattern.

    Confidence depends on the shape: a CN mobile (with or without country code)
    is unambiguous, a leading + makes an international number very likely, and a
    bare NANP-style triple-triple-quad is weakest because it collides with order
    ids and timestamps.
    """
    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        if not any(ch.isdigit() for ch in raw):
            continue
        digits = sum(ch.isdigit() for ch in raw)
        if digits < 10 or digits > 15:
            continue
        stripped = raw.lstrip()
        if stripped.startswith("+"):
            score, note = 0.75, "intl-prefix"
        elif re.match(r"^(?:\+?86[\s\-]?)?1[3-9]\d{9}$", raw):
            score, note = 0.95, "cn-mobile"
        else:
            score, note = 0.55, "local-format"
        yield Span(m.start(), m.end(), score=score, note=note)


_VERSION_BEFORE_RE = re.compile(
    r"(?i)(?:\b(?:v|version|ver\.|release|build|issue|fix|bug|patch|upgrade|downgrade)\s*#?\s*|"
    r"\b(?:python|node|npm|pip|llama|gpt|claude|v?\d+\.\d+)\s*)$"
)


def _ipv4_spans(text: str) -> Iterable[Span]:
    for m in IPV4_RE.finditer(text):
        raw = m.group(0)
        octets = [int(p) for p in raw.split(".")]
        if any(o > 255 for o in octets):
            continue
        probe = max(0, m.start() - 18)
        before = text[probe : m.start()]
        after = text[m.end() : m.end() + 4]
        # A dotted quad right after "version 1.2.3.4" or inside "1.2.3.4.5" is a
        # version string / truncated match, not an address: score it below the
        # default 0.5 threshold so it is suppressed unless a policy lowers it.
        versionish = (
            bool(_VERSION_BEFORE_RE.search(before))
            or after.startswith(".")
            or octets[0] in (0, 1, 2)
        )
        # 0.0.0.0 and 127.0.0.1 are common in config docs and logs.
        private = octets[0] in (10, 127) or (octets[0] == 192 and octets[1] == 168) or (
            octets[0] == 172 and 16 <= octets[1] <= 31
        )
        if versionish:
            yield Span(m.start(), m.end(), score=0.3, note="version-string")
            continue
        yield Span(
            m.start(),
            m.end(),
            score=0.55 if private else 0.85,
            note="private-range" if private else "public-range",
        )


def _card_spans(text: str) -> Iterable[Span]:
    for m in CARD_RE.finditer(text):
        raw = m.group(0)
        if luhn(raw):
            digits = re.sub(r"\D", "", raw)
            yield Span(m.start(), m.end(), score=0.98, note=f"luhn-ok:{digits[:4]}")


def _iban_spans(text: str) -> Iterable[Span]:
    for m in IBAN_RE.finditer(text):
        if iban_ok(m.group(0)):
            yield Span(m.start(), m.end(), score=0.97, note="mod97-ok")


def _cn_id_spans(text: str) -> Iterable[Span]:
    for m in CN_ID_RE.finditer(text):
        if cn_id_ok(m.group(0)):
            yield Span(m.start(), m.end(), score=0.98, note="gb11643-ok")


def _jwt_spans(text: str) -> Iterable[Span]:
    for m in JWT_RE.finditer(text):
        if jwt_ok(m.group(0)):
            yield Span(m.start(), m.end(), score=0.9, note="jwt-structure")


def _generic_secret_spans(text: str) -> Iterable[Span]:
    for m in GENERIC_SECRET_RE.finditer(text):
        value = m.group(1)
        low = value.lower()
        # Skip values that are obviously placeholders or that we already treat
        # as a high-confidence credential elsewhere.
        if low in {"your_api_key_here", "changeme", "placeholder"}:
            continue
        if value.startswith(("ghp_", "gho_", "github_pat_", "sk-", "xox")):
            continue
        yield Span(m.start(1), m.end(1), score=0.7, note="key=value")


def _bearer_spans(text: str) -> Iterable[Span]:
    for m in BEARER_RE.finditer(text):
        yield Span(m.start(1), m.end(1), score=0.8, note="bearer-token")


def _mac_spans(text: str) -> Iterable[Span]:
    for m in MAC_RE.finditer(text):
        yield Span(m.start(), m.end(), score=0.5, note="hardware-address")


PII_DETECTORS: list[Detector] = [
    Detector(
        id="email",
        name="Email address",
        category="pii",
        severity="medium",
        description="RFC-5322-ish email address (local part up to 64 chars).",
        false_positives=(
            "Matches version strings such as user@2.0.1 only if a TLD-like label follows."
        ),
        scan=regex_spans(EMAIL_RE, validate=_email_ok, score=0.9),
        action="redact",
    ),
    Detector(
        id="phone",
        name="Phone number",
        category="pii",
        severity="medium",
        description="E.164 international numbers, CN mainland mobiles and NANP local numbers.",
        false_positives="Looks like an order id. Short digit runs are scored low (0.55).",
        scan=_phone_spans,
        action="redact",
    ),
    Detector(
        id="credit_card",
        name="Payment card number",
        category="pii",
        severity="critical",
        description="13-19 digit card number that passes the Luhn checksum.",
        false_positives=(
            "Random 16-digit identifiers pass Luhn 1 time in 10; the span is reported anyway."
        ),
        scan=_card_spans,
        action="block",
    ),
    Detector(
        id="iban",
        name="IBAN bank account",
        category="pii",
        severity="high",
        description="International bank account number validated with ISO 7064 mod-97.",
        false_positives="A candidate must pass mod-97, so false positives are near zero.",
        scan=_iban_spans,
        action="redact",
    ),
    Detector(
        id="ipv4",
        name="IPv4 address",
        category="pii",
        severity="low",
        description="Dotted-quad IPv4 address, public or private.",
        false_positives="Version strings (1.2.3.4) and telemetry IPs are common in logs.",
        scan=_ipv4_spans,
        action="redact",
    ),
    Detector(
        id="ipv6",
        name="IPv6 address",
        category="pii",
        severity="low",
        description="Full or compressed IPv6 address.",
        false_positives="Unix timestamps written with colons are not matched.",
        scan=regex_spans(IPV6_RE, score=0.8),
        action="redact",
    ),
    Detector(
        id="jwt",
        name="JSON Web Token",
        category="secret",
        severity="high",
        description="Three-segment base64url JWT with an eyJ-prefixed header.",
        false_positives="A base64 blob of the same shape without a JWT habit is very unlikely.",
        scan=_jwt_spans,
        action="redact",
    ),
    Detector(
        id="aws_access_key",
        name="AWS access key id",
        category="secret",
        severity="critical",
        description="AWS key id (AKIA/ASIA/AGPA/AIDA/AROA/ANPA + 16 chars).",
        false_positives="Requires the exact prefix and length; near-zero false positives.",
        scan=regex_spans(AWS_KEY_RE, score=0.99),
        action="block",
    ),
    Detector(
        id="github_token",
        name="GitHub token",
        category="secret",
        severity="critical",
        description="ghp_/gho_/ghu_/ghs_/ghr_ or github_pat_ token.",
        false_positives="Exact prefix required; near-zero false positives.",
        scan=regex_spans(GITHUB_TOKEN_RE, score=0.99),
        action="block",
    ),
    Detector(
        id="openai_key",
        name="OpenAI API key",
        category="secret",
        severity="critical",
        description="sk- project, service-account, admin and legacy keys.",
        false_positives="sk- prefixed 20+ char identifiers in prose are rare.",
        scan=regex_spans(OPENAI_KEY_RE, score=0.97),
        action="block",
    ),
    Detector(
        id="slack_token",
        name="Slack token",
        category="secret",
        severity="critical",
        description="Slack xox[abposr]- tokens, including bot and app tokens.",
        false_positives="Exact prefix required; near-zero false positives.",
        scan=regex_spans(SLACK_TOKEN_RE, score=0.97),
        action="block",
    ),
    Detector(
        id="private_key",
        name="Private key header",
        category="secret",
        severity="critical",
        description="PEM private key begin marker (RSA/EC/OPENSSH/DSA/PGP).",
        false_positives="Documentation that quotes a PEM header legitimately triggers this.",
        scan=regex_spans(PRIVATE_KEY_RE, score=0.99),
        action="block",
    ),
    Detector(
        id="cn_id_card",
        name="Chinese resident ID",
        category="pii",
        severity="high",
        description="18-character CN ID card with the GB 11643 checksum digit.",
        false_positives="Checksum plus birth-date sanity keeps random 18-digit numbers out.",
        scan=_cn_id_spans,
        action="block",
    ),
    Detector(
        id="generic_secret",
        name="Bare credential assignment",
        category="secret",
        severity="high",
        description="api_key/secret/token/password assignments with a 16+ char value.",
        false_positives="Config examples with real-looking placeholders may trigger it.",
        scan=_generic_secret_spans,
        action="redact",
    ),
    Detector(
        id="bearer_token",
        name="Bearer token",
        category="secret",
        severity="high",
        description="Authorization: Bearer <token> header value.",
        false_positives="Only the token, never the word Bearer, is redacted.",
        scan=_bearer_spans,
        action="redact",
    ),
    Detector(
        id="ipv4_network",
        name="IPv4 CIDR block",
        category="pii",
        severity="info",
        description="Network range such as 10.0.0.0/8 or 203.0.113.0/24.",
        false_positives="Firewall docs naturally contain CIDR blocks; allowlist them.",
        scan=regex_spans(IPV4_NET_RE, score=0.6),
        action="flag",
    ),
    Detector(
        id="mac_address",
        name="MAC address",
        category="pii",
        severity="low",
        description="Six colon-separated hex octets.",
        false_positives="Hashes written with colons can match; scored at 0.5.",
        scan=_mac_spans,
        action="flag",
    ),
]

#: Severity overrides applied from a policy without rebuilding the detector.
DEFAULT_SEVERITY: dict[str, Severity] = {d.id: d.severity for d in PII_DETECTORS}
