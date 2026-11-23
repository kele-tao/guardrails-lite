# Contributing

Thanks for taking the time to improve guardrails-lite. The project is small on
purpose: a new detector is a data change plus a test, not a refactor.

## Development setup

```bash
git clone https://github.com/kele-tao/guardrails-lite
cd guardrails-lite
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
ruff check .
```

There is no network access in the test suite and no runtime dependency beyond
the standard library. Please keep it that way.

## Adding a detector

1. Add the detector to `src/guardrails_lite/detectors/pii.py` or
   `injection.py`. Every detector needs an id, a severity, a one-line
   description and an honest false-positive note.
2. Return spans, not strings: use `regex_spans(...)` with a validator for
   anything that has a checksum (Luhn, mod-97, GB 11643).
3. Add a cheap `needs` hint or a prefilter in `detectors/__init__.py` if the
   pattern is expensive. The invariant is tested: prefilters may never change a
   result (`tests/test_prefilter.py`).
4. Add at least one positive sample to the detector test and, if the detector
   has realistic false positives, a negative sample to
   `benchmarks/corpus.jsonl`.
5. Run `python benchmarks/run.py` so the committed confusion matrix stays in
   sync with the code.

## Adding corpus samples

Corpus records are JSON Lines with `id`, `family`, `text`, `label`
(1 = should fire, 0 = must not), `expect` (detector ids) and `note`. Samples
must be synthetic: no real personal data, no real credentials.

## Style

- Python 3.10+, full type hints on public functions, `ruff` clean, line length
  100.
- Deterministic output. Anything random needs a seed and a test.
- No new runtime dependencies without an issue that explains why the standard
  library cannot do it.

## Pull requests

Keep the change focused, describe the user-visible behaviour, and include the
command output you used to verify it. CI runs ruff, pytest on 3.10/3.11/3.12,
the CLI smoke test and the benchmark.
