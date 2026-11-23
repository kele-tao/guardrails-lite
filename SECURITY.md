# Security policy

guardrails-lite is a defence-in-depth filter, not a security boundary. It
reduces the blast radius of prompt injection and PII leakage; it does not make
an LLM safe on its own. Treat a clean verdict as "no known signal", never as
"trusted input".

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" tab on this repository rather than a public issue.

Useful reports include:

- a detector that can be bypassed with a short, realistic payload;
- an input that causes a crash, unbounded memory use or quadratic time;
- a redaction bug that lets an entity survive verbatim, or that corrupts
  unrelated text;
- a policy that can be made to fail open by a malformed document.

Please include the smallest reproduction you can, the version, and the
observed versus expected behaviour. Do not include real personal data,
credentials or customer documents: synthesise a look-alike instead.

## Scope

In scope: the library code under `src/guardrails_lite`, the CLI, and the
packaged policies.

Out of scope: the accuracy of any third-party model you place behind this
filter, and the security of example hosts and services mentioned in the
documentation.

## What we already publish

Known detector misses are part of the benchmark, not a secret:
`benchmarks/results.md` lists every false negative in the committed corpus with
its reason. Bypass classes that are not covered are documented in
`docs/ROADMAP.md`.
