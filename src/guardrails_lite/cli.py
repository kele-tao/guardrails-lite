"""Command-line interface for guardrails-lite.

Commands
--------
scan      Scan a file, directory or stdin and print findings / JSON.
redact    Write a redacted copy of a file or stdin.
bench     Run the labelled corpus and print a confusion matrix.
detectors List every detector with severity and false-positive notes.
policy    Validate a policy file and print the effective configuration.

Exit codes: 0 clean, 1 findings above the policy threshold, 2 usage error.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .model import Verdict
from .policy import Policy, PolicyError, load_policy, policy_summary
from .redact import redact, rehydrate
from .scanner import detector_catalogue, scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _ensure_utf8() -> None:
    """Force UTF-8 output so unicode payloads never crash on a cp936 console."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            # Exotic streams (StringIO in tests, some CI harnesses) reject
            # reconfigure; UTF-8 output is a best-effort improvement, not a
            # requirement, so a failure here must not break the CLI.
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="backslashreplace")


_ensure_utf8()

# ANSI helpers: disabled automatically when stdout is not a TTY or NO_COLOR is set.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


HIDDEN_CHARS = "\u200b\u200c\u200d\u2060\ufeff\u00ad"


def visible(text: str, limit: int = 60) -> str:
    """Make control characters visible so a terminal report can never garble."""
    out = []
    for ch in text[:limit]:
        code = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch in HIDDEN_CHARS or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
            out.append(f"<U+{code:04X}>")
        elif 0xE0000 <= code <= 0xE007F:
            out.append(f"<U+{code:05X}>")
        elif code < 0x20 and ch != "\r":
            out.append(f"<U+{code:04X}>")
        else:
            out.append(ch)
    return "".join(out) + ("…" if len(text) > limit else "")


def _c(text: str, code: str) -> str:
    if not _COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def bold(text: str) -> str:
    return _c(text, "1")


def dim(text: str) -> str:
    return _c(text, "90")


def red(text: str) -> str:
    return _c(text, "31")


def green(text: str) -> str:
    return _c(text, "32")


def yellow(text: str) -> str:
    return _c(text, "33")


def cyan(text: str) -> str:
    return _c(text, "36")


def magenta(text: str) -> str:
    return _c(text, "35")


SEVERITY_COLOR = {
    "critical": red,
    "high": magenta,
    "medium": yellow,
    "low": cyan,
    "info": dim,
}


class CliError(Exception):
    """A user error that should be printed without a traceback."""


PACKAGE_POLICY = Path(__file__).resolve().parent / "policies" / "default.json"


def _load_policy(args: argparse.Namespace) -> Policy:
    """Load --policy when given, else the balanced default shipped in the package."""
    explicit = getattr(args, "policy", None)
    if explicit:
        return load_policy(explicit)
    if PACKAGE_POLICY.exists():
        return load_policy(PACKAGE_POLICY)
    from .policy import DEFAULT_POLICY

    return DEFAULT_POLICY


def _read_text(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise CliError(f"file not found: {path}")
    if p.is_dir():
        raise CliError(f"expected a file, got a directory: {path}")
    try:
        return p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise CliError(
            f"{path} is not valid UTF-8 (byte {exc.start}); "
            "convert it to UTF-8 or pipe it through stdin"
        ) from exc
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc}") from exc


def _read_stdin() -> str:
    data = sys.stdin.buffer.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliError(
            f"stdin is not valid UTF-8 (byte {exc.start}); guardrails-lite only "
            "scans UTF-8 text"
        ) from exc


def _excerpt(text: str, start: int, end: int, width: int = 34) -> str:
    left = text[max(0, start - width) : start]
    right = text[end : end + width]
    return f"{left}{text[start:end]}{right}".replace("\n", " ").replace("\t", " ")


def _label(verdict: Verdict) -> str:
    if verdict.action == "allow":
        return green("ALLOW")
    if verdict.action == "flag":
        return yellow("FLAG")
    if verdict.action == "redact":
        return cyan("REDACT")
    return red("BLOCK")


def render_report(verdict: Verdict, text: str, *, source: str, show_text: bool = False) -> str:
    """Human-readable report used by the scan command and by the test suite."""
    lines: list[str] = []
    lines.append(f"{bold('source')}  {source}")
    lines.append(
        f"{bold('policy')}  {verdict.policy_name}   "
        f"{bold('chars')} {verdict.text_length}   "
        f"{bold('action')} {_label(verdict)}"
    )
    if not verdict.findings:
        lines.append(green("no findings — text is clean under this policy"))
        if verdict.suppressed:
            lines.append(dim(f"{verdict.suppressed} finding(s) suppressed by allowlist/threshold"))
        return "\n".join(lines)

    counts = verdict.by_category()
    lines.append(
        f"{bold('findings')} {len(verdict.findings)}"
        + ("  " + "  ".join(f"{k}={v}" for k, v in counts.items()) if counts else "")
        + (f"  {dim(f'suppressed={verdict.suppressed}')}" if verdict.suppressed else "")
    )
    lines.append("")
    header = f"{'SEVERITY':<9} {'DETECTOR':<24} {'SPAN':<13} {'SCORE':<7} MATCH"
    lines.append(dim(header))
    lines.append(dim("-" * min(100, len(header) + 24)))
    for f in verdict.findings:
        colour = SEVERITY_COLOR.get(f.severity, dim)
        span = f"{f.start}-{f.end}"
        match = visible(f.text, 80 if show_text else 40)
        severity = colour(f.severity.upper())
        rec = f"{severity:<9} {f.detector_id:<24} {span:<13} {f.score:<7.2f} {match}"
        lines.append(rec)
        if show_text:
            lines.append(dim("          excerpt: " + _excerpt(text, f.start, f.end)))
    if verdict.redacted is not None:
        lines.append("")
        lines.append(bold("redacted (pseudonymised, stable per salt):"))
        preview = verdict.redacted.splitlines()
        for line in preview[:40]:
            lines.append("  " + line)
        if len(preview) > 40:
            lines.append(dim(f"  … {len(preview) - 40} more lines"))
    lines.append("")
    lines.append(dim(f"elapsed {verdict.elapsed_us / 1000:.2f} ms"))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    if args.stdin or not args.paths:
        if not args.stdin and sys.stdin.isatty():
            raise CliError("no input: pass a file path or use --stdin")
        text = _read_stdin()
        sources: list[tuple[str, str]] = [("<stdin>", text)]
    else:
        sources = []
        for path in args.paths:
            p = Path(path)
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file() and child.suffix in {".txt", ".md", ".json", ".log"}:
                        sources.append((str(child), _read_text(str(child))))
            else:
                sources.append((path, _read_text(path)))

    worst = EXIT_OK
    payloads = []
    for source, text in sources:
        verdict = scan(text, policy)
        if args.json:
            data = verdict.to_dict(include_text=args.show_text, include_timing=True)
            data["source"] = source
            payloads.append(data)
        else:
            if len(sources) > 1:
                print(bold(f"== {source} =="))
            print(render_report(verdict, text, source=source, show_text=args.show_text))
            if len(sources) > 1:
                print()
        if verdict.action == "block" or (verdict.action in ("flag", "redact") and worst == EXIT_OK):
            worst = EXIT_FINDINGS
        if args.redact_out and verdict.action == "redact":
            out = Path(args.redact_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(verdict.redacted or text, encoding="utf-8")
            if not args.json:
                print(dim(f"wrote redacted copy to {out}"))
    if args.json:
        print(json.dumps(payloads if len(payloads) != 1 else payloads[0], indent=2))
    return worst


def _read_input(args: argparse.Namespace) -> tuple[str, str]:
    """Return (text, source_label) from --stdin or a file path."""
    if args.stdin or not args.path:
        if not args.stdin and sys.stdin.isatty():
            raise CliError("no input: pass a file path or use --stdin")
        return _read_stdin(), "<stdin>"
    return _read_text(args.path), args.path


def _write_output(text: str, out: str | None) -> None:
    if out and out != "-":
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


def cmd_redact(args: argparse.Namespace) -> int:
    text, source = _read_input(args)
    if args.reverse:
        # Rehydration is the inverse operation: it needs the map that redaction
        # produced and must not re-scan (the tokens are not findings).
        if not args.map_in:
            raise CliError("--reverse needs --map-in map.json (written by --map-out)")
        map_path = Path(args.map_in)
        if not map_path.exists():
            raise CliError(f"map file not found: {map_path}")
        try:
            forward = json.loads(map_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CliError(f"{map_path}: invalid JSON ({exc.msg})") from exc
        if not isinstance(forward, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in forward.items()
        ):
            raise CliError(f"{map_path}: expected an object mapping token -> original value")
        restored = rehydrate(text, forward)
        _write_output(restored, args.out)
        if args.out and args.out != "-":
            note = f"restored {len(forward)} token(s) into {args.out} (source {source})"
            print(dim(note), file=sys.stderr)
        return EXIT_OK

    policy = _load_policy(args)
    verdict = scan(text, policy, redact_text=True)
    strategies = {"*": "mask"} if args.style == "mask" else None
    result = redact(
        text,
        verdict.findings,
        salt=policy.salt,
        strategies=strategies,
        reversible=args.reversible,
    )
    out_text = result.text
    if args.out and args.out != "-":
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(out_text, encoding="utf-8")
        summary = f"wrote {out} ({len(result.findings)} span(s) replaced, source {source})"
        print(dim(summary), file=sys.stderr)
    else:
        sys.stdout.write(out_text)
        if not out_text.endswith("\n"):
            sys.stdout.write("\n")
    if args.map_out:
        map_path = Path(args.map_out)
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text(json.dumps(result.tokens, indent=2), encoding="utf-8")
        note = f"wrote reversible map to {map_path} ({len(result.tokens)} token(s))"
        print(dim(note), file=sys.stderr)
    return EXIT_OK


def cmd_detectors(args: argparse.Namespace) -> int:
    catalogue = detector_catalogue()
    if args.json:
        print(json.dumps(catalogue, indent=2))
        return EXIT_OK
    print(bold(f"{len(catalogue)} detectors"))
    print()
    header = f"{'SEVERITY':<9} {'ID':<24} {'CAT':<10} {'ACTION':<7} NAME"
    print(dim(header))
    print(dim("-" * 96))
    if args.verbose:
        for entry in catalogue:
            colour = SEVERITY_COLOR.get(str(entry["severity"]), dim)
            print(
                f"{colour(str(entry['severity']).upper()):<9} {entry['id']:<24} "
                f"{entry['category']:<10} {entry['action']:<7} {entry['name']}"
            )
            print(dim(f"          {entry['description']}"))
            print(dim(f"          false positives: {entry['false_positives']}"))
    else:
        for entry in catalogue:
            colour = SEVERITY_COLOR.get(str(entry["severity"]), dim)
            print(
                f"{colour(str(entry['severity']).upper()):<9} {entry['id']:<24} "
                f"{entry['category']:<10} {entry['action']:<7} {entry['name']}"
            )
    return EXIT_OK


def cmd_policy(args: argparse.Namespace) -> int:
    policy = load_policy(args.path)
    summary = policy_summary(policy)
    summary["file"] = str(args.path)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(bold(f"policy {summary['name']}") + dim(f"  ({args.path})"))
        print(f"  detectors enabled : {summary['detectors']}")
        print(f"  custom regex rules: {summary['custom_rules']}")
        print(f"  allowlist rules   : {summary['allowlist_rules']}")
        print(f"  min severity      : {summary['min_severity']}")
        print(f"  min score         : {summary['min_score']}")
        print(f"  reversible        : {summary['reversible']}")
        if summary["actions"]:
            print(f"  overrides         : {json.dumps(summary['actions'], sort_keys=True)}")
    return EXIT_OK


def cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_corpus

    corpus = Path(args.corpus) if args.corpus else (
        Path(__file__).resolve().parent.parent.parent / "benchmarks" / "corpus.jsonl"
    )
    if not corpus.exists():
        raise CliError(f"corpus not found: {corpus}")
    policy = _load_policy(args)
    report = run_corpus(corpus, policy)
    if args.json:
        print(json.dumps(report, indent=2))
        return EXIT_OK
    print(render_bench(report))
    return EXIT_OK


def render_bench(report: dict) -> str:
    """Confusion matrix and per-family breakdown, printed by 'bench'."""
    totals = report["totals"]
    lines: list[str] = []
    lines.append(bold("guardrails-lite bench") + dim(f"  corpus={report['corpus']}"))
    lines.append(dim(f"  policy={report['policy']}  samples={totals['samples']}"))
    lines.append("")
    cm = report["confusion"]
    lines.append(bold("confusion matrix (positive = adversarial or PII)"))
    lines.append(dim(f"  {'':<16}{'predicted +':>14}{'predicted -':>14}"))
    lines.append(
        f"  {'actual +':<16}{green(str(cm['tp'])):>14}{red(str(cm['fn'])):>14}"
    )
    lines.append(
        f"  {'actual -':<16}{red(str(cm['fp'])):>14}{green(str(cm['tn'])):>14}"
    )
    lines.append("")
    m = report["metrics"]
    lines.append(
        f"  precision {m['precision']:.3f}   recall {m['recall']:.3f}   "
        f"F1 {m['f1']:.3f}   accuracy {m['accuracy']:.3f}"
    )
    lines.append("")
    lines.append(bold("by family"))
    lines.append(
        dim(
            f"  {'FAMILY':<18}{'SAMPLES':>8}{'POS':>8}{'CAUGHT':>8}"
            f"{'MISSED':>8}{'FP':>6}  RECALL"
        )
    )
    for family, row in report["families"].items():
        # Recall is computed over positives only. The benign family has none, so
        # "recall" would read as 0% and mislead: it shows 'n/a' and the
        # false-positive count is the number that matters there.
        recall_text = (
            f"{row['caught'] / row['positives']:.2%}" if row["positives"] else "n/a"
        )
        lines.append(
            f"  {family:<18}{row['samples']:>8}{row['positives']:>8}{row['caught']:>8}"
            f"{row['missed']:>8}{row['fp']:>6}  {recall_text}"
        )
    if report["misses"]:
        lines.append("")
        lines.append(bold("known misses (we publish these)"))
        for miss in report["misses"]:
            lines.append(dim(f"  {miss['id']:<10} {miss['family']:<16} {miss['reason']}"))
    if report["false_positives"]:
        lines.append("")
        lines.append(bold("false positives"))
        for fp in report["false_positives"][:12]:
            lines.append(dim(f"  {fp['id']:<10} {fp['family']:<16} {fp['reason']}"))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrails-lite",
        description="Prompt-injection and PII firewall for LLM apps. Zero dependencies.",
        epilog="Exit codes: 0 clean, 1 findings, 2 usage error.",
    )
    parser.add_argument("--version", action="version", version=f"guardrails-lite {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan files or stdin and print findings")
    p_scan.add_argument(
        "paths", nargs="*", help="files or directories (default: stdin with --stdin)"
    )
    p_scan.add_argument("--stdin", action="store_true", help="read the document from stdin")
    p_scan.add_argument("--policy", help="path to a JSON or YAML policy file")
    p_scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_scan.add_argument(
        "--show-text", action="store_true", help="include matched text and excerpts"
    )
    p_scan.add_argument("--redact-out", help="write a pseudonymised copy when action is redact")
    p_scan.set_defaults(func=cmd_scan)

    p_red = sub.add_parser("redact", help="write a redacted copy of a document")
    p_red.add_argument("path", nargs="?", help="file to redact (default: stdin)")
    p_red.add_argument("--stdin", action="store_true", help="read the document from stdin")
    p_red.add_argument("--policy", help="path to a JSON or YAML policy file")
    p_red.add_argument("--out", default="-", help="output path, '-' for stdout (default: -)")
    p_red.add_argument(
        "--style", choices=["token", "mask"], default="token", help="pseudonym or mask"
    )
    p_red.add_argument("--reversible", action="store_true", help="keep a token->value map")
    p_red.add_argument("--map-out", help="write the reversible map to this JSON file")
    p_red.add_argument("--map-in", help="read a reversible map (used with --reverse)")
    p_red.add_argument(
        "--reverse",
        action="store_true",
        help="restore the original values using --map-in instead of redacting",
    )
    p_red.set_defaults(func=cmd_redact)

    p_bench = sub.add_parser("bench", help="run the labelled corpus and print a confusion matrix")
    p_bench.add_argument("--corpus", help="path to corpus.jsonl (default: benchmarks/corpus.jsonl)")
    p_bench.add_argument("--policy", help="path to a JSON or YAML policy file")
    p_bench.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_bench.set_defaults(func=cmd_bench)

    p_det = sub.add_parser("detectors", help="list every detector with severity and notes")
    p_det.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_det.add_argument(
        "-v", "--verbose", action="store_true", help="include descriptions and FP notes"
    )
    p_det.set_defaults(func=cmd_detectors)

    p_pol = sub.add_parser("policy", help="validate a policy file and print the effective config")
    p_pol.add_argument("path", help="path to a JSON or YAML policy file")
    p_pol.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p_pol.set_defaults(func=cmd_policy)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed the message
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    try:
        return int(args.func(args))
    except (CliError, PolicyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


def run() -> int:
    """Entry point used by the console script."""
    return main()
