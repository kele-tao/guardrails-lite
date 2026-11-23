# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-23

### Added

- 29 detectors across four categories (PII, secrets, encoding, injection), each
  with an id, severity, description and a written false-positive note.
- Span-accurate scanning with deterministic overlap resolution: every finding
  carries character offsets into the original document.
- Span-preserving streaming scanner: entity offsets are identical whether a
  document is scanned in one call or in 8 KiB chunks.
- Policy engine supporting JSON and a documented YAML subset, per-detector
  actions, severity and score thresholds, allowlists (literal or regex,
  wildcard detector supported) and custom regex rules.
- Redaction with three strategies: stable HMAC pseudonyms, shape-preserving
  masks, and removal; reversible maps only when explicitly requested.
- CLI: `scan`, `redact`, `bench`, `detectors`, `policy` with documented exit
  codes (0 clean, 1 findings, 2 usage error) and JSON output everywhere.
- Labelled corpus of 99 samples (79 positive, 20 negative) and a benchmark
  harness that publishes its own false negatives and false positives.
- Throughput benchmark for the default and fast policies, plus a streaming
  equivalence check.

### Known limitations

- Detectors are tuned for English; non-English instruction overrides are not
  caught (see docs/ROADMAP.md).
- A general repeated-phrase rule was replaced by word-run and line-run rules to
  keep scanning linear; the tradeoff is documented in docs/ROADMAP.md.
- Token-flood detectors are chunk-local when streaming, because a flood is a
  property of the whole document rather than of a span.
