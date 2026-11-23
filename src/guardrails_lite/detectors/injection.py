"""Prompt-injection detectors (11 detectors).

These look for the *shape* of an attack rather than a specific payload: an
instruction override, a role hijack, a request for the system prompt, a
smuggled delimiter, an encoded blob, a tool call hidden in retrieved text, a
markdown image that exfiltrates data, or a flood of repetition. Each returns
the smallest span that carries the signal.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from collections.abc import Iterable

from .base import Detector, Span
from .pii import JWT_RE

# --------------------------------------------------------------------------
# Keyword patterns
# --------------------------------------------------------------------------

_OVERRIDE_RE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|discard|override|bypass)\b"
    r"[^.!?\n]{0,40}?\b(?:all\s+)?(?:the\s+)?"
    r"(?:previous|prior|above|earlier|preceding|system|developer)\b"
    r"[^.!?\n]{0,20}?\b(?:instructions?|prompts?|rules?|directives?|guidelines?|messages?)\b"
)

_ROLE_HIJACK_RE = re.compile(
    r"(?i)(?:\byou are now\b|\bfrom now on,? you (?:are|will be)\b|"
    r"\bact as (?:if you are |a |an |the )?|\bpretend (?:to be|you are)\b|"
    r"\byour new (?:role|persona|identity) is\b|\broleplay as\b|"
    r"\byou have no (?:restrictions|filters|limits)\b)"
)

_SYSTEM_EXFIL_RE = re.compile(
    r"(?i)(?:\b(?:reveal|print|show|repeat|output|dump|display|leak|recite|disclose|"
    r"share|give me|tell me)\b"
    r"[^.!?\n]{0,32}?\b(?:your|the)\s+(?:system|hidden|initial|original|internal)\s+"
    r"(?:prompt|instructions?|message|configuration|rules)\b|"
    r"\bwhat (?:are|were) your (?:instructions|system prompt|rules)\b|"
    r"\brepeat (?:everything|the text|all text) above\b)"
)

_DELIMITER_RE = re.compile(
    r"(?im)(?:(?:^|\n)[ \t]*(?:#{2,}[ \t]*(?:begin|start|end)[^\n]{0,40}|"
    r"={3,}[ \t]*(?:system|admin)[ \t]*={3,}|"
    r"-{3,}[ \t]*(?:end|begin) (?:system|context)[ \t]*-{3,})|"
    r"<{2,}[ \t]*(?:system|admin|developer)[^\n>]{0,30}>{2,}|"
    r"\[\[[ \t]*(?:system|admin|developer)[ \t]*\]\]|"
    r"<\|[ \t]*(?:im_start|im_end|system|endoftext)[ \t]*\|>|"
    r"<\|[ \t]*(?:start|end)\s*of\s*(?:system|instruction)[ \t]*\|>)"
)

_TOOL_CALL_RE = re.compile(
    r"(?i)(?:</?(?:tool_call|function_call|tool_use|function_results?)>|"
    r"<\|\s*tool\s*\|>|"
    r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:following\s+)?"
    r"(?:tool|function)\s+(?:named\s+)?[\"']?\w+)"
)

_MD_IMAGE_RE = re.compile(r"!\[[^\]\n]{0,120}\]\((https?:\/\/[^)\s]{8,})\)")
_MD_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]{0,120}\]\((https?:\/\/[^)\s?]{4,}\?[^)\s]{16,})\)")

_CRED_HARVEST_RE = re.compile(
    r"(?i)\b(?:list|print|output|show|dump|send|exfiltrate|upload)\b"
    r"[^.!?\n]{0,40}?\b(?:all\s+)?(?:the\s+)?"
    r"(?:api[\s_-]?keys?|secrets?|passwords?|credentials?|environment variables?|"
    r"\.env|tokens?|private keys?)\b"
)

_SAFETY_BYPASS_RE = re.compile(
    r"(?i)(?:\bdo not (?:tell|inform|alert|warn) (?:the )?(?:user|human|anyone)\b|"
    r"\bwithout (?:asking|telling|informing) (?:the )?(?:user|human)\b|"
    r"\b(?:silently|quietly) (?:execute|send|run|delete|exfiltrate)\b|"
    r"\bbypass (?:the )?(?:safety|filter|guardrail|moderation|policy)\b|"
    r"\b(?:with\s+)?no\s+(?:restrictions|filters|limitations|guardrails)\b|"
    r"\bignore (?:the )?(?:safety|content) (?:policy|guidelines)\b|"
    r"\bjailbreak\b)"
)

#: Bidi control codepoints, reported as a separate finding from invisible runs.
_BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

_INJECTION_HINTS = (
    "ignore",
    "instruction",
    "system prompt",
    "you are",
    "assistant",
    "override",
    "execute",
    "password",
    "token",
    "http",
    "delete",
    "sudo",
)


def _hits(pattern: re.Pattern[str], text: str, score: float, note: str) -> Iterable[Span]:
    for m in pattern.finditer(text):
        yield Span(m.start(), m.end(), score=score, note=note)


#: Invisible formatting codepoints, as a character-class fragment for one regex.
_INVISIBLE_CLASS = (
    "[\u200b\u200c\u200d\u2060\ufeff"
    "\u00ad\u180e\u2061\u2062\u2063\u2064"
    "\U000E0000-\U000E007F]+"
)
_INVISIBLE_RE = re.compile(_INVISIBLE_CLASS)


def _invisible_spans(text: str) -> Iterable[Span]:
    """Runs of zero-width and Unicode-tag codepoints.

    Bidi controls are deliberately excluded: they have their own detector, and
    reporting the same character twice adds noise without adding signal. A regex
    with an explicit character class is ~8x faster than iterating the string in
    Python and produces identical runs.
    """
    for m in _INVISIBLE_RE.finditer(text):
        yield Span(m.start(), m.end(), score=0.9, note="invisible-codepoints")


_BIDI_RE = re.compile("[" + _BIDI + "]")


def _bidi_spans(text: str) -> Iterable[Span]:
    for m in _BIDI_RE.finditer(text):
        yield Span(m.start(), m.end(), score=0.85, note="bidi-control")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return good / len(data)


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{36,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")


def _jwt_spans(text: str) -> list[tuple[int, int]]:
    """Spans of JWT-shaped tokens, so the decoder never eats a token segment.

    A JWT is three base64url segments joined by dots; the jwt detector owns that
    span. Decoding a segment here would split the token during redaction and add
    a second finding for the same characters.
    """
    return [m.span() for m in JWT_RE.finditer(text)]


def _in_jwt(span: tuple[int, int], jwt_spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < we and ws < end for ws, we in jwt_spans)


def _b64_spans(text: str, jwt_spans: list[tuple[int, int]] | None = None) -> Iterable[Span]:
    jwt_spans = _jwt_spans(text) if jwt_spans is None else jwt_spans
    for m in _B64_RE.finditer(text):
        if _in_jwt(m.span(), jwt_spans):
            continue
        blob = m.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < 18 or _printable_ratio(decoded) < 0.92:
            continue
        lowered = decoded.decode("utf-8", "ignore").lower()
        hot = any(h in lowered for h in _INJECTION_HINTS)
        yield Span(
            m.start(),
            m.end(),
            score=0.95 if hot else 0.7,
            note="base64-decodes" + ("-to-instructions" if hot else ""),
            metadata=(("decoded_len", str(len(decoded))),),
        )


def _hex_spans(text: str, jwt_spans: list[tuple[int, int]] | None = None) -> Iterable[Span]:
    jwt_spans = _jwt_spans(text) if jwt_spans is None else jwt_spans
    for m in _HEX_RE.finditer(text):
        if _in_jwt(m.span(), jwt_spans):
            continue
        blob = m.group(0)
        try:
            decoded = bytes.fromhex(blob)
        except ValueError:
            continue
        if _printable_ratio(decoded) < 0.92:
            continue
        lowered = decoded.decode("utf-8", "ignore").lower()
        hot = any(h in lowered for h in _INJECTION_HINTS)
        yield Span(
            m.start(),
            m.end(),
            score=0.9 if hot else 0.65,
            note="hex-decodes" + ("-to-instructions" if hot else ""),
        )


def _markdown_spans(text: str) -> Iterable[Span]:
    """Markdown images and links whose URL carries data off-site.

    A plain badge image (no query string, no beacon host) is not reported: only
    URLs that can smuggle content are. That keeps documentation from lighting up
    while still catching the classic '![x](https://evil/p?data=...)' beacon.
    """
    for pattern, score, note in (
        (_MD_IMAGE_RE, 0.9, "markdown-image-beacon"),
        (_MD_LINK_RE, 0.75, "markdown-link-with-query-data"),
    ):
        for m in pattern.finditer(text):
            url = m.group(1).lower()
            beacon = any(
                k in url
                for k in ("data=", "q=", "token=", "secret=", "email=", "key=", "http://", "ngrok")
            )
            if beacon:
                yield Span(m.start(), m.end(), score=score, note=note)


_REPEAT_CHAR_RE = re.compile(r"(\S)\\1{149,}")

#: A word must repeat consecutively this many times to count as flooding.
_WORD_RUN = 12
#: A line must repeat consecutively this many times to count as flooding.
_LINE_RUN = 8


def repetition_prefilter(text: str) -> bool:
    """Cheap necessary condition for every repetition rule.

    Every rule implies that some whitespace token occurs at least three times:
    a word run of 12, a line repeated 8 times (each repetition contributes a
    copy of every word on that line) and the character rule all satisfy it.
    Counter runs at C speed and short-circuits the linear scans in
    _repetition_spans on ordinary prose; the threshold is deliberately much
    lower than _LINE_RUN so the prefilter can never hide a real finding.
    """
    counts = Counter(re.findall(r"\S+", text))
    return any(n >= 3 for n in counts.values())


def _repetition_spans(text: str) -> Iterable[Span]:
    """Detect token/line flooding in one linear pass over the document.

    Three rules, each O(n):

    * a single character repeated 150+ times (ASCII-art banners are 3-20 wide,
      so padding and separator lines are not flagged);
    * one word repeated 12+ times consecutively;
    * one line repeated 8+ times consecutively.

    A general repeated n-gram rule was dropped because a correct
    backreference regex is quadratic on multi-megabyte input; the tradeoff is
    documented in docs/ROADMAP.md. Emitted spans cover the exact repeated run.
    """
    for m in _REPEAT_CHAR_RE.finditer(text):
        yield Span(m.start(), m.end(), score=0.8, note="char-repeated-150x")

    prev_word = None
    run_start = 0
    run_end = 0
    run = 0
    for m in re.finditer(r"\S+", text):
        word = m.group(0)
        if word == prev_word:
            run += 1
            run_end = m.end()
        else:
            if run >= _WORD_RUN:
                yield Span(run_start, run_end, score=0.8, note=f"word-repeated-{run}x")
            prev_word = word
            run_start = m.start()
            run_end = m.end()
            run = 1
    if run >= _WORD_RUN:
        yield Span(run_start, run_end, score=0.8, note=f"word-repeated-{run}x")

    prev_line = None
    line_start = 0
    line_end = 0
    run = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        end = offset + len(line)
        key = line.strip()
        if key and key == prev_line:
            run += 1
            line_end = end
        else:
            if run >= _LINE_RUN:
                yield Span(line_start, line_end, score=0.75, note=f"line-repeated-{run}x")
            prev_line = key
            line_start = offset
            line_end = end
            run = 1
        offset = end
    if run >= _LINE_RUN:
        yield Span(line_start, line_end, score=0.75, note=f"line-repeated-{run}x")

INJECTION_DETECTORS: list[Detector] = [
    Detector(
        id="instruction_override",
        name="Instruction override",
        category="injection",
        severity="critical",
        description="Text that tells the model to ignore or override earlier instructions.",
        false_positives=(
            "Quoting an incident report that contains the phrase legitimately triggers it."
        ),
        scan=lambda t: _hits(_OVERRIDE_RE, t, 0.95, "override-phrase"),
        action="block",
    ),
    Detector(
        id="role_hijack",
        name="Role hijack",
        category="injection",
        severity="high",
        description="Attempts to replace the assistant persona or remove its restrictions.",
        false_positives="Creative-writing prompts legitimately say 'act as a historian'.",
        scan=lambda t: _hits(_ROLE_HIJACK_RE, t, 0.85, "persona-replacement"),
        action="block",
    ),
    Detector(
        id="system_prompt_exfil",
        name="System prompt exfiltration",
        category="injection",
        severity="high",
        description="Asks the model to reveal its system prompt, rules or configuration.",
        false_positives="Debugging questions from developers can look identical.",
        scan=lambda t: _hits(_SYSTEM_EXFIL_RE, t, 0.9, "exfil-request"),
        action="block",
    ),
    Detector(
        id="delimiter_smuggling",
        name="Delimiter smuggling",
        category="injection",
        severity="high",
        description="Fake chat/system delimiters used to escape the user turn.",
        false_positives="Docs that show a prompt format intentionally contain delimiters.",
        scan=lambda t: _hits(_DELIMITER_RE, t, 0.85, "fake-delimiter"),
        action="block",
    ),
    Detector(
        id="tool_call_injection",
        name="Tool-call injection",
        category="injection",
        severity="critical",
        description="Tool/function invocation syntax smuggled into retrieved text.",
        false_positives="Tool documentation and API references match by design.",
        scan=lambda t: _hits(_TOOL_CALL_RE, t, 0.9, "tool-syntax"),
        action="block",
    ),
    Detector(
        id="markdown_exfil",
        name="Markdown exfiltration channel",
        category="injection",
        severity="high",
        description="Image or link whose URL carries query-string data out of the app.",
        false_positives="Legitimate tracking pixels and badge images also match.",
        scan=_markdown_spans,
        action="block",
    ),
    Detector(
        id="credential_harvest",
        name="Credential harvesting",
        category="injection",
        severity="high",
        description="Asks the model to print keys, passwords, tokens or env vars.",
        false_positives="Security documentation that says 'dump secrets to rotate them'.",
        scan=lambda t: _hits(_CRED_HARVEST_RE, t, 0.85, "harvest-request"),
        action="block",
    ),
    Detector(
        id="safety_bypass",
        name="Safety bypass request",
        category="injection",
        severity="high",
        description="Asks the model to act silently or to bypass its guardrails.",
        false_positives="'Do not tell the user until the build passes' in a changelog.",
        scan=lambda t: _hits(_SAFETY_BYPASS_RE, t, 0.85, "bypass-phrase"),
        action="block",
    ),
    Detector(
        id="repeated_content",
        name="Excessive repetition",
        category="injection",
        severity="medium",
        description="Token flooding: a character 150x, a word 12x or a line 8x in a row.",
        false_positives="ASCII-art banners and padded tables repeat characters.",
        scan=_repetition_spans,
        action="flag",
    ),
    Detector(
        id="encoded_payload",
        name="Encoded payload",
        category="encoding",
        severity="high",
        description="Base64/hex blob that decodes to printable text, escalated when the "
        "decoded text contains injection keywords.",
        false_positives="Hashes (hex) and image data URIs decode to binary and are skipped.",
        scan=lambda t: list(_b64_spans(t)) + list(_hex_spans(t)),  # jwt spans skipped inside
        action="block",
    ),
    Detector(
        id="invisible_unicode",
        name="Invisible unicode",
        category="encoding",
        severity="high",
        description="Zero-width characters and Unicode tag codepoints used for cloaking.",
        false_positives="Copy-pasted text from the web often carries zero-width joiners.",
        scan=_invisible_spans,
        action="flag",
    ),
    Detector(
        id="bidi_override",
        name="Bidi control characters",
        category="encoding",
        severity="medium",
        description="Right-to-left override characters that reorder visible text.",
        false_positives="Arabic and Hebrew documents may legitimately embed controls.",
        scan=_bidi_spans,
        action="flag",
    ),
]
