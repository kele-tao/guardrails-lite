"""CLI behaviour: exit codes, JSON output, redaction, benchmark, error handling."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import SAMPLE_AWS_KEY_ID
from guardrails_lite.cli import main, render_report, visible
from guardrails_lite.scanner import scan

ROOT = Path(__file__).resolve().parent.parent


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_scan_clean_file_exits_zero(tmp_path, capsys):
    path = tmp_path / "clean.txt"
    path.write_text("Nothing to see here, just deployment notes.", encoding="utf-8")
    code, out, err = run(capsys, "scan", str(path))
    assert code == 0
    assert "ALLOW" in out
    assert err == ""
    assert "no findings" in out


def test_scan_pii_file_exits_one(tmp_path, capsys):
    path = tmp_path / "pii.txt"
    path.write_text("write to jane@example.com", encoding="utf-8")
    code, out, _ = run(capsys, "scan", str(path))
    assert code == 1
    assert "REDACT" in out
    assert "jane@example.com" in out
    assert "email" in out


def test_scan_blocking_credentials_exits_one_with_block_label(tmp_path, capsys):
    path = tmp_path / "secret.txt"
    path.write_text("key " + SAMPLE_AWS_KEY_ID, encoding="utf-8")
    code, out, _ = run(capsys, "scan", str(path))
    assert code == 1
    assert "BLOCK" in out


def test_scan_json_output(tmp_path, capsys):
    path = tmp_path / "pii.txt"
    path.write_text("write to jane@example.com", encoding="utf-8")
    code, out, _ = run(capsys, "scan", "--json", str(path))
    payload = json.loads(out)
    assert code == 1
    assert payload["action"] == "redact"
    assert payload["source"].endswith("pii.txt")
    assert payload["findings"][0]["detector"] == "email"
    assert payload["findings"][0]["start"] == 9


def test_scan_directory_walks_text_files(tmp_path, capsys):
    (tmp_path / "a.md").write_text("mail a@example.com", encoding="utf-8")
    (tmp_path / "b.log").write_text("clean line", encoding="utf-8")
    (tmp_path / "skip.bin").write_bytes(b"\x00\x01")
    code, out, _ = run(capsys, "scan", str(tmp_path))
    assert code == 1
    assert "== " in out
    assert out.count("source") == 2


def test_scan_missing_file_is_usage_error(tmp_path, capsys):
    code, out, err = run(capsys, "scan", str(tmp_path / "nope.txt"))
    assert code == 2
    assert out == ""
    assert "file not found" in err
    assert "Traceback" not in err


def test_scan_directory_given_as_file_is_usage_error(tmp_path, capsys):
    empty = tmp_path / "empty_dir"
    empty.mkdir()
    code, out, err = run(capsys, "scan", str(empty))
    assert code == 0
    assert out == ""
    assert err == ""


def test_scan_bad_policy_reports_cleanly(tmp_path, capsys):
    policy = tmp_path / "p.json"
    policy.write_text("{bad", encoding="utf-8")
    code, _, err = run(capsys, "scan", "--policy", str(policy), "x.txt")
    assert code == 2
    assert "invalid JSON" in err


def test_scan_latin1_file_is_usage_error(tmp_path, capsys):
    path = tmp_path / "latin1.txt"
    path.write_bytes("caf\xe9".encode("latin-1"))
    code, _, err = run(capsys, "scan", str(path))
    assert code == 2
    assert "not valid UTF-8" in err


def test_scan_policy_flag_changes_action(tmp_path, capsys):
    doc = tmp_path / "doc.txt"
    doc.write_text("mail jane@example.com", encoding="utf-8")
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"actions": {"email": "allow"}}), encoding="utf-8")
    code, out, _ = run(capsys, "scan", "--policy", str(policy), str(doc))
    assert code == 0
    assert "ALLOW" in out


def test_scan_show_text_adds_excerpt(tmp_path, capsys):
    doc = tmp_path / "doc.txt"
    doc.write_text("prefix mail jane@example.com suffix", encoding="utf-8")
    code, out, _ = run(capsys, "scan", "--show-text", str(doc))
    assert code == 1
    assert "excerpt:" in out


def test_scan_redact_out_writes_file(tmp_path, capsys):
    doc = tmp_path / "doc.txt"
    doc.write_text("mail jane@example.com", encoding="utf-8")
    out_path = tmp_path / "safe.txt"
    code, _, _ = run(capsys, "scan", "--redact-out", str(out_path), str(doc))
    assert code == 1
    assert "jane@example.com" not in out_path.read_text(encoding="utf-8")
    assert out_path.read_text(encoding="utf-8").startswith("mail [[EMAIL:")


def test_redact_command_to_file(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane@example.com and 13800138000", encoding="utf-8")
    out_path = tmp_path / "out.md"
    code, _, err = run(capsys, "redact", str(doc), "--out", str(out_path))
    assert code == 0
    text = out_path.read_text(encoding="utf-8")
    assert "[[EMAIL:" in text and "[[PHONE:" in text
    assert "wrote" in err


def test_redact_command_mask_style(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane.doe@example.com", encoding="utf-8")
    out_path = tmp_path / "out.md"
    run(capsys, "redact", str(doc), "--out", str(out_path), "--style", "mask")
    text = out_path.read_text(encoding="utf-8")
    assert text.startswith("mail j")
    assert "@example.com" in text


def test_redact_command_reversible_map(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane@example.com", encoding="utf-8")
    out_path = tmp_path / "out.md"
    map_path = tmp_path / "map.json"
    code, _, _ = run(
        capsys,
        "redact",
        str(doc),
        "--out",
        str(out_path),
        "--reversible",
        "--map-out",
        str(map_path),
    )
    assert code == 0
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    token = next(iter(mapping))
    assert token.startswith("[[EMAIL:")
    assert mapping[token] == "jane@example.com"
    assert token in out_path.read_text(encoding="utf-8")


def test_redact_command_stdout(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane@example.com", encoding="utf-8")
    code, out, _ = run(capsys, "redact", str(doc))
    assert code == 0
    assert "[[EMAIL:" in out


def test_detectors_command_lists_everything(capsys):
    code, out, _ = run(capsys, "detectors")
    assert code == 0
    assert out.count("\n") + 1 >= 29
    for detector_id in ("email", "instruction_override", "invisible_unicode"):
        assert detector_id in out


def test_detectors_json_and_verbose(capsys):
    code, out, _ = run(capsys, "detectors", "--json")
    assert code == 0
    catalogue = json.loads(out)
    assert len(catalogue) >= 25
    assert all("false_positives" in entry for entry in catalogue)
    code, out, _ = run(capsys, "detectors", "-v")
    assert "false positives:" in out


def test_policy_command_summary(tmp_path, capsys):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"name": "demo", "min_severity": "high"}), encoding="utf-8")
    code, out, _ = run(capsys, "policy", str(policy))
    assert code == 0
    assert "demo" in out
    code, out, _ = run(capsys, "policy", "--json", str(policy))
    payload = json.loads(out)
    assert payload["name"] == "demo"
    assert payload["min_severity"] == "high"


def test_policy_command_bad_file(tmp_path, capsys):
    code, _, err = run(capsys, "policy", str(tmp_path / "missing.yaml"))
    assert code == 2
    assert "not found" in err


def test_bench_command_runs_corpus(capsys):
    code, out, _ = run(capsys, "bench")
    assert code == 0
    assert "confusion matrix" in out
    assert "precision" in out
    assert "by family" in out


def test_bench_json_is_serialisable(capsys):
    code, out, _ = run(capsys, "bench", "--json")
    assert code == 0
    report = json.loads(out)
    assert report["totals"]["samples"] >= 80
    cm = report["confusion"]
    assert cm["tp"] + cm["fn"] + cm["fp"] + cm["tn"] == report["totals"]["samples"]


def test_bench_missing_corpus(tmp_path, capsys):
    code, _, err = run(capsys, "bench", "--corpus", str(tmp_path / "none.jsonl"))
    assert code == 2
    assert "corpus not found" in err


def test_version_flag(capsys):
    """--version prints and exits 0 without raising a traceback."""
    code, out, _ = run(capsys, "--version")
    assert code == 0
    assert "guardrails-lite 1.0.0" in out


def test_no_arguments_is_usage_error(capsys):
    code, _, err = run(capsys)
    assert code == 2
    assert "usage:" in err


def test_unknown_command_is_usage_error(capsys):
    code, _, err = run(capsys, "frobnicate")
    assert code == 2
    assert "invalid choice" in err


def test_render_report_includes_summary_and_findings():
    text = "mail jane@example.com and key " + SAMPLE_AWS_KEY_ID
    verdict = scan(text)
    report = render_report(verdict, text, source="inline")
    assert "source  inline" in report
    assert "BLOCK" in report
    assert "aws_access_key" in report
    assert "CRITICAL" in report


def test_visible_escapes_control_and_zero_width_characters():
    assert visible("a\u200bb") == "a<U+200B>b"
    assert visible("a\tb") == "a\\tb"
    assert visible("x" * 80, limit=4) == "xxxx…"


def test_redact_reverse_round_trip(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane@example.com and 13800138000", encoding="utf-8")
    safe = tmp_path / "safe.md"
    mapping = tmp_path / "map.json"
    code, _, _ = run(
        capsys,
        "redact",
        str(doc),
        "--out",
        str(safe),
        "--reversible",
        "--map-out",
        str(mapping),
    )
    assert code == 0
    assert "jane" not in safe.read_text(encoding="utf-8")
    restored = tmp_path / "restored.md"
    code, _, err = run(
        capsys,
        "redact",
        str(safe),
        "--reverse",
        "--map-in",
        str(mapping),
        "--out",
        str(restored),
    )
    assert code == 0
    assert restored.read_text(encoding="utf-8") == doc.read_text(encoding="utf-8")
    assert "restored 2 token(s)" in err


def test_redact_reverse_requires_map(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane@example.com", encoding="utf-8")
    code, _, err = run(capsys, "redact", str(doc), "--reverse")
    assert code == 2
    assert "--map-in" in err


def test_redact_reverse_missing_or_bad_map(tmp_path, capsys):
    doc = tmp_path / "doc.md"
    doc.write_text("mail jane@example.com", encoding="utf-8")
    code, _, err = run(
        capsys, "redact", str(doc), "--reverse", "--map-in", str(tmp_path / "nope.json")
    )
    assert code == 2
    assert "not found" in err
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    code, _, err = run(capsys, "redact", str(doc), "--reverse", "--map-in", str(bad))
    assert code == 2
    assert "invalid JSON" in err
    wrong = tmp_path / "wrong.json"
    wrong.write_text("[1, 2]", encoding="utf-8")
    code, _, err = run(capsys, "redact", str(doc), "--reverse", "--map-in", str(wrong))
    assert code == 2
    assert "token -> original" in err


def test_stdin_scan(capsys, monkeypatch):
    import io
    import sys

    class FakeStdin:
        buffer = io.BytesIO(b"mail jane@example.com")

        def isatty(self):
            return False

    monkeypatch.setattr(sys, "stdin", FakeStdin())
    code, out, _ = run(capsys, "scan", "--stdin")
    assert code == 1
    assert "jane@example.com" in out
