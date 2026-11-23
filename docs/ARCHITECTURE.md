# Architecture

`guardrails-lite` is a pipeline with four stages and one hard invariant: a
finding's `start`/`end` always indexes the original document, even when the
document arrived in pieces.

```
                 ┌──────────────────────────────────────────────┐
 untrusted text →│ scanner.scan / scanner.scan_stream           │
                 │                                              │
                 │  detectors (29)          policy engine       │
                 │  ├─ pii.py (17)          ├─ thresholds       │
                 │  └─ injection.py (12)    ├─ allowlists       │
                 │        ↓                 └─ custom regex     │
                 │     Span[]  ──► overlap resolution ──►       │
                 │                          ↓                   │
                 │                     Verdict                  │
                 │        ┌─────────────┼──────────────┐        │
                 │     action      redacted text    exit code   │
                 └──────────────────────────────────────────────┘
```

## Modules

| module | responsibility |
| --- | --- |
| `model.py` | `Finding`, `Verdict`, severity ranking, JSON serialisation |
| `detectors/base.py` | `Span`, `Detector`, `regex_spans` helper |
| `detectors/pii.py` | 17 PII/secret detectors plus validators (Luhn, mod-97, GB 11643) |
| `detectors/injection.py` | 12 injection/encoding detectors plus base64/hex decoding |
| `detectors/__init__.py` | registry, stable id ordering, cheap prefilters |
| `policy.py` | policy parsing/validation, allowlists, custom rules, actions |
| `yamlish.py` | the supported YAML subset, with line-numbered errors |
| `redact.py` | HMAC pseudonyms, masks, removal, reversible maps |
| `scanner.py` | single-shot and streaming scanners, overlap resolution |
| `bench.py` | corpus loading, confusion matrix, miss explanations |
| `cli.py` | argument parsing, terminal rendering, exit codes |

## Finding lifecycle

1. A detector yields `Span(start, end, score, note, metadata)`.
2. `Detector.find` wraps each span in a `Finding` carrying detector metadata and
   sorts by offset.
3. `_dedupe_findings` resolves overlaps: findings sort by
   `(start, -score, -length, id)`; a finding is kept when it does not overlap an
   already-kept *exclusive* finding. Non-exclusive detectors (floods, cloaked
   runs) are appended without claiming characters.
4. `Policy.keep` drops findings below `min_score`/`min_severity` or matched by an
   allowlist; the count is reported as `Verdict.suppressed`.
5. `Policy.effective_action` reduces the survivors to one action.
6. If the action is `redact` (or the caller asks), `redact.redact` rewrites the
   text and the `Verdict` records the sanitised copy.

## Streaming invariants

`scan_stream` maintains `buffer` (unfinalised text) and `base` (its absolute
offset). After each chunk:

- `cut = len(buffer) - overlap`;
- scan the buffer;
- finalise findings whose `end <= cut`, translating offsets by `base`;
- compute the trim point as the minimum `start` among findings that straddle the
  cut (or `cut` when none do), so no entity is truncated at the boundary;
- advance `base` by the trim and drop the prefix.

At end of stream the remaining buffer is scanned and finalised. Deduplication
keys are absolute spans, so a finding is emitted exactly once even though the
overlap region is scanned repeatedly.

**Tested invariants** (`tests/test_scanner.py`, `tests/test_prefilter.py`):

- entity spans from `scan_stream` equal those from `scan` for chunk sizes
  1, 2, 3, 7, 13, 23, 37, 61, 64 and 997 characters;
- a PEM header split across every one of 61 boundary positions is still
  reported exactly once;
- removing every detector prefilter produces identical results on the whole
  committed corpus and all example files;
- output is byte-identical across runs (timing is excluded from `to_json`).

## Performance notes

Three things keep scanning linear on multi-megabyte input:

1. **Prefilters.** Each detector declares necessary lowercase substrings
   (`needs`); a mismatch skips its regex entirely. On ordinary prose that
   removes most of the 29 regex scans.
2. **No backtracking patterns.** The repeated-phrase rule was rewritten as
   character-run, word-run and line-run passes after a backreference regex
   measured quadratic; the general rule is a documented roadmap item.
3. **Cheap validators in Python, not in the regex.** Dotted-quad shape is matched
   by a simple pattern and octets are range-checked in code, which measured
   2.5× faster than spelling 0-255 four times in the pattern.

`benchmarks/perf.py` writes the numbers quoted in the README.
