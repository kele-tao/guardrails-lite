#!/usr/bin/env python
"""Run the accuracy benchmark and write benchmarks/results.{json,md}.

Usage
-----
    python benchmarks/run.py                # default policy
    python benchmarks/run.py --policy policies/strict.json

The numbers written here are the numbers quoted in the README. The script
refuses to write anything if the corpus is missing, so a stale table cannot
survive a broken checkout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from guardrails_lite.bench import format_markdown, run_corpus  # noqa: E402
from guardrails_lite.policy import load_policy  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the labelled corpus benchmark.")
    ap.add_argument("--corpus", default=str(ROOT / "benchmarks" / "corpus.jsonl"))
    ap.add_argument("--policy", default=str(ROOT / "policies" / "default.json"))
    ap.add_argument("--out-dir", default=str(ROOT / "benchmarks"))
    args = ap.parse_args()

    policy = load_policy(args.policy)
    report = run_corpus(args.corpus, policy)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "results.md").write_text(format_markdown(report) + "\n", encoding="utf-8")
    cm = report["confusion"]
    print(
        f"{report['totals']['samples']} samples: "
        f"TP={cm['tp']} FN={cm['fn']} FP={cm['fp']} TN={cm['tn']} | "
        f"precision={report['metrics']['precision']:.3f} "
        f"recall={report['metrics']['recall']:.3f}"
    )
    print(f"wrote {out_dir / 'results.json'} and {out_dir / 'results.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
