"""Scanner: single-pass scanning plus a span-preserving streaming scanner.

Two entry points:

* scan(text, policy) -> Verdict
* scan_stream(iterable_of_chunks, policy, chunk_size=..., overlap=...) -> Verdict

The streaming scanner is the nontrivial part. A detector such as an email
address or a PEM header can straddle a chunk boundary, so a naive per-chunk
scan both misses entities and (worse) reports spans relative to the wrong
offset. This implementation keeps a bounded overlap window, scans a sliding
buffer, and only finalises findings whose end lies in the safe region (the part
of the buffer a future chunk can no longer change). Findings that straddle the
cut are kept in the buffer and re-examined once more input arrives, so every
entity is reported exactly once with absolute offsets into the stream.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Iterator, Sequence

from .detectors import Detector, all_detectors
from .model import Finding, ScanStats, Verdict
from .policy import DEFAULT_POLICY, CustomRule, Policy
from .redact import redact

#: Characters of context kept between chunks. 512 is larger than the longest
#: built-in pattern (a 128-char PEM header plus surrounding prose) while small
#: enough that the overlap cost is noise on multi-megabyte documents.
DEFAULT_OVERLAP = 512


def _custom_findings(text: str, rules: tuple[CustomRule, ...]) -> list[Finding]:
    out: list[Finding] = []
    for rule in rules:
        for m in rule.pattern.finditer(text):
            start, end = m.span()
            if end <= start:
                continue
            out.append(
                Finding(
                    detector_id=rule.id,
                    name=rule.name,
                    category="custom",
                    severity=rule.severity,
                    start=start,
                    end=end,
                    text=text[start:end],
                    score=1.0,
                    note="custom-rule",
                )
            )
    return out


def _dedupe_findings(
    findings: list[Finding], exclusive: set[str] | frozenset[str]
) -> list[Finding]:
    """Resolve overlaps deterministically.

    Findings from exclusive detectors compete for characters: sort by
    (start, -score, -length) and keep a finding only when it does not overlap an
    already-kept one, so a Luhn-valid card number beats the phone number that saw
    the same digits. Findings from non-exclusive detectors (token floods) are
    context signals and never hide another detector's finding.

    The function is order-independent and returns findings sorted by offset.
    """
    ordered = sorted(findings, key=lambda f: (f.start, -f.score, -f.length, f.detector_id))
    kept: list[Finding] = []
    claimed: list[Finding] = []
    contextual: list[Finding] = []
    seen: set[tuple[int, int, str]] = set()
    for cand in ordered:
        key = (cand.start, cand.end, cand.detector_id)
        if key in seen:
            continue
        seen.add(key)
        if cand.detector_id not in exclusive:
            contextual.append(cand)
            continue
        if any(cand.overlaps(k) for k in claimed):
            continue
        claimed.append(cand)
    kept = claimed + contextual
    kept.sort(key=lambda f: (f.start, f.end, f.detector_id))
    return kept


def _exclusive_ids(detectors: list[Detector]) -> set[str]:
    """Ids of the detectors whose spans compete for characters."""
    return {d.id for d in detectors if d.exclusive}


def _apply_policy(findings: list[Finding], policy: Policy) -> tuple[list[Finding], int]:
    kept: list[Finding] = []
    suppressed = 0
    for f in findings:
        if not policy.keep(f) or policy.detector_action(f.detector_id) == "allow":
            suppressed += 1
            continue
        kept.append(f)
    return kept, suppressed


def scan(
    text: str,
    policy: Policy | None = None,
    *,
    redact_text: bool | None = None,
    detectors: Sequence[Detector] | None = None,
) -> Verdict:
    """Scan a string and return a Verdict.

    redact_text defaults to True when the verdict action is 'redact', so
    verdict.redacted is populated exactly when a caller would want it.
    detectors overrides the policy's detector set; it exists so callers can run
    a custom subset without writing a policy document, and so tests can compare
    a detector with and without its prefilter.
    """
    if not isinstance(text, str):
        raise TypeError(f"scan() expected str, got {type(text).__name__}")
    policy = policy or DEFAULT_POLICY
    started = time.perf_counter()

    raw: list[Finding] = []
    detectors = list(detectors) if detectors is not None else policy.active_detectors()
    lower = text.lower()
    for det in detectors:
        raw.extend(det.find(text, lower))
    raw.extend(_custom_findings(text, policy.custom_rules))
    exclusive = _exclusive_ids(detectors)

    kept, suppressed = _apply_policy(_dedupe_findings(raw, exclusive), policy)
    action = policy.effective_action(kept)

    should_redact = redact_text if redact_text is not None else action == "redact"
    redacted = None
    if should_redact and kept:
        redacted = redact(text, kept, salt=policy.salt).text

    elapsed = (time.perf_counter() - started) * 1_000_000
    return Verdict(
        action=action,
        findings=tuple(kept),
        redacted=redacted,
        suppressed=suppressed,
        text_length=len(text),
        policy_name=policy.name,
        elapsed_us=elapsed,
    )


def iter_chunks(stream: Iterable[str], chunk_size: int = 8192) -> Iterator[str]:
    """Normalise an iterable of arbitrary pieces into fixed-size chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    buf = ""
    for piece in stream:
        if not isinstance(piece, str):
            raise TypeError(f"stream chunks must be str, got {type(piece).__name__}")
        buf += piece
        while len(buf) >= chunk_size:
            yield buf[:chunk_size]
            buf = buf[chunk_size:]
    if buf:
        yield buf


def scan_stream(
    stream: Iterable[str],
    policy: Policy | None = None,
    *,
    chunk_size: int = 8192,
    overlap: int = DEFAULT_OVERLAP,
    stats: ScanStats | None = None,
) -> Verdict:
    """Scan a stream of text chunks with spans preserved across boundaries.

    Algorithm:

    1. Keep a buffer of not-yet-finalised text and the absolute offset of its
       first character.
    2. Append the next chunk and scan the whole buffer.
    3. Compute a cut at len(buffer) - overlap. A finding ending at or before the
       cut cannot change when more input arrives, so it is final and its
       offsets are translated to absolute document coordinates.
    4. Emit final findings, then drop everything before the cut from the buffer
       - except for a finding that straddles the cut, whose start is retained
       so the entity is never truncated.

    Step 3 makes the scanner correct (an entity split across two chunks is
    reported once, with a span that matches the concatenated document) and
    linear (each character is scanned at most twice). The tail is finalised at
    end of stream.
    """
    if overlap < 0:
        raise ValueError("overlap must be >= 0")
    policy = policy or DEFAULT_POLICY
    detectors = policy.active_detectors()
    custom = policy.custom_rules
    started = time.perf_counter()

    buffer = ""
    base = 0
    finalised: list[Finding] = []
    emitted: set[tuple[int, int, str]] = set()
    chunk_count = 0
    chars = 0

    exclusive = _exclusive_ids(detectors)

    def scan_buffer() -> list[Finding]:
        found: list[Finding] = []
        lower = buffer.lower()
        for det in detectors:
            found.extend(det.find(buffer, lower))
        found.extend(_custom_findings(buffer, custom))
        return _dedupe_findings(found, exclusive)

    def emit(final: list[Finding], limit: int | None) -> int:
        """Emit findings that end at or before limit; return the trim offset."""
        keep_from = limit if limit is not None else 0
        if limit is None:
            for f in final:
                key = (f.start + base, f.end + base, f.detector_id)
                if key in emitted:
                    continue
                emitted.add(key)
                finalised.append(_shift(f))
            return 0
        for f in final:
            if f.end <= limit:
                key = (f.start + base, f.end + base, f.detector_id)
                if key in emitted:
                    continue
                emitted.add(key)
                finalised.append(_shift(f))
            else:
                keep_from = min(keep_from, f.start)
        return max(0, keep_from)

    def _shift(f: Finding) -> Finding:
        return Finding(
            detector_id=f.detector_id,
            name=f.name,
            category=f.category,
            severity=f.severity,
            start=f.start + base,
            end=f.end + base,
            text=f.text,
            score=f.score,
            note=f.note,
            metadata=f.metadata,
        )

    pending = ""
    for piece in stream:
        if not isinstance(piece, str):
            raise TypeError(f"stream chunks must be str, got {type(piece).__name__}")
        pending += piece
        while len(pending) >= chunk_size:
            chunk, pending = pending[:chunk_size], pending[chunk_size:]
            chunk_count += 1
            chars += len(chunk)
            buffer += chunk
            cut = len(buffer) - overlap
            if cut <= 0:
                continue
            trim = emit(scan_buffer(), cut)
            buffer = buffer[trim:]
            base += trim
        if stats is not None:
            stats.chunks = chunk_count
            stats.chars_scanned = chars
    if pending:
        chunk_count += 1
        chars += len(pending)
        buffer += pending
    cut = len(buffer) - overlap
    if cut > 0:
        trim = emit(scan_buffer(), cut)
        buffer = buffer[trim:]
        base += trim
    emit(scan_buffer(), None)

    kept, suppressed = _apply_policy(finalised, policy)
    action = policy.effective_action(kept)
    elapsed = (time.perf_counter() - started) * 1_000_000
    if stats is not None:
        stats.chunks = chunk_count
        stats.chars_scanned = chars
        for f in kept:
            stats.per_detector[f.detector_id] = stats.per_detector.get(f.detector_id, 0) + 1
    return Verdict(
        action=action,
        findings=tuple(kept),
        redacted=None,
        suppressed=suppressed,
        text_length=chars,
        policy_name=policy.name,
        elapsed_us=elapsed,
    )


def detector_catalogue() -> list[dict[str, object]]:
    """Serialisable metadata for every registered detector."""
    return [d.to_dict() for d in all_detectors()]


def detector_ids() -> list[str]:
    """Sorted list of every detector id."""
    return [d.id for d in all_detectors()]
