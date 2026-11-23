#!/usr/bin/env python
"""Throughput benchmark: scan speed in MB/s, streaming overhead, per-policy.

Usage
-----
    python benchmarks/perf.py

Writes benchmarks/perf.json. Numbers are wall-clock medians on the machine that
runs the script: honest, but machine-specific. The README quotes the 5 MB row
because it is the most stable measurement on a laptop.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from guardrails_lite.policy import load_policy  # noqa: E402
from guardrails_lite.scanner import scan, scan_stream  # noqa: E402

FILLER = (
    "The quarterly report shows steady growth across all regions and segments. "
    "Support volume declined while satisfaction rose. "
)


def build_document(target_mb: float) -> str:
    """Build a ~target_mb document with PII sprinkled every 40 filler blocks."""
    chunk = FILLER * 8 + "\n"
    per_line = len(chunk) + 80
    lines = max(1, int(target_mb * 1024 * 1024 / per_line))
    parts = []
    for i in range(lines):
        parts.append(chunk)
        if i % 40 == 39:
            parts.append(f"Contact user{i}@example.com or 1380013{i % 10000:04d}.\n")
    return "".join(parts)


def timeit(fn, repeats: int = 5) -> dict[str, float]:
    """Median and minimum wall-clock time over *repeats* runs."""
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - started)
    return {"median": statistics.median(samples), "min": min(samples)}


def bench_policy(policy_path: Path, doc: str) -> dict:
    policy = load_policy(policy_path)
    actual_mb = len(doc.encode("utf-8")) / (1024 * 1024)
    timing = timeit(lambda: scan(doc, policy))
    row = {
        "policy": policy.name,
        "detectors": len(policy.active_detectors()),
        "mb": round(actual_mb, 3),
        "seconds_median": round(timing["median"], 4),
        "seconds_min": round(timing["min"], 4),
        "mb_per_s": round(actual_mb / timing["median"], 2),
    }
    print(
        f"{row['policy']:8s} {actual_mb:5.2f} MB  scan {row['seconds_median']:6.3f}s "
        f"(min {row['seconds_min']:6.3f}s)  {row['mb_per_s']:6.2f} MB/s  "
        f"({row['detectors']} detectors)"
    )
    return row


def main() -> int:
    doc = build_document(5.0)
    results = {
        "note": "medians of 5 runs on a 5 MB synthetic document; machine-specific",
        "policies": [
            bench_policy(ROOT / "policies" / "default.json", doc),
            bench_policy(ROOT / "policies" / "fast.json", doc),
        ],
        "streaming": [],
    }

    # Streaming overhead: the entity detectors must produce identical spans
    # whether the document arrives in one string or in 8 KiB chunks.
    policy = load_policy(ROOT / "policies" / "default.json")
    small = build_document(1.0)
    actual_mb = len(small.encode("utf-8")) / (1024 * 1024)
    chunks = [small[i : i + 8192] for i in range(0, len(small), 8192)]
    batch_secs = timeit(lambda: scan(small, policy))["median"]
    stream_secs = timeit(lambda: scan_stream(chunks, policy, chunk_size=8192))["median"]
    batch = scan(small, policy)
    streamed = scan_stream(chunks, policy, chunk_size=8192)
    # Entity detectors claim characters, so their spans must survive chunking
    # exactly. Whole-document structure detectors (token floods) are chunk-local
    # when streaming: that difference is reported separately, never hidden.
    context = {"repeated_content"}
    batch_entities = [
        (f.detector_id, f.start, f.end) for f in batch.findings if f.detector_id not in context
    ]
    stream_entities = [
        (f.detector_id, f.start, f.end) for f in streamed.findings if f.detector_id not in context
    ]
    identical = batch_entities == stream_entities
    results["streaming"].append(
        {
            "mb": round(actual_mb, 3),
            "chunk_size": 8192,
            "chunks": len(chunks),
            "batch_seconds": round(batch_secs, 4),
            "stream_seconds": round(stream_secs, 4),
            "overhead_x": round(stream_secs / batch_secs, 2),
            "findings_batch": len(batch.findings),
            "findings_stream": len(streamed.findings),
            "entity_findings": len(batch_entities),
            "identical_entity_spans": identical,
            "context_findings_batch": len(batch.findings) - len(batch_entities),
            "context_findings_stream": len(streamed.findings) - len(stream_entities),
        }
    )
    print(
        f"streaming: {len(chunks)} chunks, {stream_secs / batch_secs:.2f}x batch time, "
        f"{len(batch_entities)} entity spans identical: {identical}"
    )

    out = ROOT / "benchmarks" / "perf.json"
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
