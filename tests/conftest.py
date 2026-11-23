"""Shared fixtures: a policy loader helper and a tiny corpus writer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardrails_lite.policy import Policy, load_policy, parse_policy

ROOT = Path(__file__).resolve().parent.parent

#: Credential-shaped samples, assembled at runtime.
#:
#: Hosting providers scan pushed commits for live-looking credentials; a
#: realistic fake token is indistinguishable from a leak to those scanners. The
#: tests therefore build the literals from pieces, and the detector still sees
#: the exact shape it is meant to catch.
SAMPLE_AWS_KEY_ID = "ASIA" + "IOSFODNN7EXAMPLE"
SAMPLE_GITHUB_TOKEN = "gh" + "u_" + "16C7e42F292c6912E7710c838347Ae178B4a"
SAMPLE_OPENAI_KEY = "sk" + "-proj-" + "abcdEFGH1234ijklMNOP5678qrst"
SAMPLE_SLACK_TOKEN = "xox" + "b-" + "1234567890-0987654321-AbCdEfGhIjKlMnOp"
SAMPLE_PEM_HEADER = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"
SAMPLE_PEM_FOOTER = "-----END " + "PGP PRIVATE KEY BLOCK-----"


@pytest.fixture()
def default_policy() -> Policy:
    return load_policy(ROOT / "policies" / "default.json")


@pytest.fixture()
def strict_policy() -> Policy:
    return load_policy(ROOT / "policies" / "strict.json")


@pytest.fixture()
def corpus_path() -> Path:
    return ROOT / "benchmarks" / "corpus.jsonl"


def write_corpus(tmp_path: Path, records: list[dict]) -> Path:
    """Write a JSONL corpus and return its path."""
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )
    return path


__all__ = ["ROOT", "parse_policy", "write_corpus"]
