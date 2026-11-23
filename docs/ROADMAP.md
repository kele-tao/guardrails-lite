# Roadmap

This file records what v1.0.0 deliberately does **not** do, so the README's
claims stay honest. Each item names the test or corpus sample that would prove
it is fixed.

## Cut from v1.0

### General repeated-phrase detection

The first implementation used a backreference regex,
`(\b.{8,40}?\b)(?:\s*\1){7,}`, to catch any phrase repeated eight times. It is
correct but quadratic: 0.56 s for 886 KB, and it dominated the scan (75% of
runtime). v1.0 ships three linear rules instead — a character repeated 150+,
a word repeated 12+ times in a row, and a line repeated 8+ times. The general
case (long varied phrases repeated with different whitespace) is not detected.

Fix: a rolling-hash or suffix-automaton n-gram counter, validated with a
`repeated_phrase` detector and a corpus family of its own.

### Streaming token floods

Token floods are properties of a whole document, so `scan_stream` reports them
per chunk and the counts differ from a batch scan. `benchmarks/perf.py` reports
this openly (`context_findings_*`) instead of hiding it. All entity detectors
are span-identical between the two modes.

Fix: a bounded ring buffer of recent lines inside `scan_stream`, with a test
comparing batch and streamed flood counts on a 1 MB document.

### Non-English and obfuscated overrides

The detectors are English-only lexical patterns. Corpus samples `inj-hard-1`
(French), `inj-hard-2` (paraphrase), `inj-hard-3` (ROT13), `inj-hard-4`
(Cyrillic homoglyphs) and `inj-hard-6` (letter-spaced) are counted as misses in
`benchmarks/results.md`.

Fix: language-specific patterns behind a policy flag, plus a Unicode NFKC and
homoglyph folding pass that keeps original-text offsets.

### Obfuscated PII forms

`alice [at] example [dot] com` and spelled-out digits are not detected
(`pii-hard-1`, `pii-hard-2`).

Fix: a de-obfuscation normaliser that maps those forms back to candidates while
reporting spans in the original text.

### HTML-comment exfiltration

A beacon hidden in `<!-- <img src=...> -->` is not reported (`inj-hard-7`).
Only markdown images/links are checked.

Fix: an HTML-comment parser for the markdown detector, plus a corpus sample.

## Candidates for v1.1+

1. **Paraphrase signal.** Bundle a small committed classifier and evaluate it
   against the same corpus, so the `instruction_override` recall stops being 50%.
2. **Entity-type expansion.** Names and postal addresses need NER; that breaks
   the zero-dependency promise, so it would ship as an optional extra
   (`pip install guardrails-lite[ner]`) rather than a default.
3. **Policy inheritance.** `extends: ./base.yaml` would avoid copy-pasted policy
   files. Requires a cycle check and a deterministic merge order.
4. **Per-span redaction strategies in policy.** Today `--style` is global for the
   CLI; the library already accepts a strategy per detector id.
5. **Fuzz harness.** A committed `hypothesis`-free fuzzer (stdlib `random` with a
   fixed seed) for offset invariants on random unicode.
