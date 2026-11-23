# Detector catalogue

Generated from the live registry: `python -m guardrails_lite detectors -v`
prints the same table with the false-positive notes. Count: **29**.

## PII and credentials (17: 9 PII + 8 secret)

| id | severity | action | description | false positives |
| --- | --- | --- | --- | --- |
| `email` | medium | redact | RFC-5322-ish address, local part up to 64 chars | version strings like `user@2.0.1-nightly` (rejected by TLD validation) |
| `phone` | medium | redact | E.164, CN mobile, NANP local | order ids and timestamps; short digit runs score 0.55 |
| `credit_card` | critical | block | 13-19 digits, Luhn-validated | random 16-digit ids pass Luhn 1 in 10 |
| `iban` | high | redact | ISO 13616 / mod-97 | near zero (checksum) |
| `ipv4` | low | redact | dotted quad, public or private | version strings, telemetry IPs |
| `ipv6` | low | redact | full or compressed | rare |
| `jwt` | high | redact | three base64url segments, `eyJ` header | very rare outside tokens |
| `aws_access_key` | critical | block | AKIA/ASIA/AGPA/AIDA/AROA/ANPA + 16 | near zero |
| `github_token` | critical | block | `gh[pousr]_`, `github_pat_` | near zero |
| `openai_key` | critical | block | `sk-` with optional project/svcacct prefix | rare |
| `slack_token` | critical | block | `xox[abposr]-` | near zero |
| `private_key` | critical | block | PEM private-key header | docs quoting a PEM header |
| `cn_id_card` | high | block | 18-char CN ID with GB 11643 check digit | near zero (checksum + birth date) |
| `generic_secret` | high | redact | `api_key = ...` style assignments | config examples with realistic placeholders |
| `bearer_token` | high | redact | `Bearer <token>` value | rare |
| `ipv4_network` | info | flag | CIDR block such as `10.0.0.0/8` | firewall documentation |
| `mac_address` | low | flag | six colon-separated hex octets | colon-separated hashes |

## Injection and encoding (12: 9 injection + 3 encoding)

| id | severity | action | description | false positives |
| --- | --- | --- | --- | --- |
| `instruction_override` | critical | block | "ignore all previous instructions" family | quoting an incident report |
| `role_hijack` | high | block | persona replacement, "you have no filters" | creative-writing prompts |
| `system_prompt_exfil` | high | block | asks for the system prompt or rules | developer debugging questions |
| `delimiter_smuggling` | high | block | fake `<|im_start|>`, `=== SYSTEM ===`, `[[admin]]` | prompt-format documentation |
| `tool_call_injection` | critical | block | `<tool_call>`, `<function_call>`, "call the function named X" | tool API docs |
| `markdown_exfil` | high | block | image/link URL carrying data or pointing at a beacon | legitimate tracking pixels |
| `credential_harvest` | high | block | "list all the api keys / .env" | security runbooks |
| `safety_bypass` | high | block | "do not tell the user", "bypass the filter", jailbreak | changelog phrasing |
| `repeated_content` | medium | flag | char 150×, word 12×, line 8× | ASCII-art banners (kept below 150 chars) |
| `encoded_payload` | high | block | base64/hex decoding to printable text | hashes decode to binary, skipped |
| `invisible_unicode` | high | flag | zero-width and Unicode-tag codepoints | copy-pasted web text |
| `bidi_override` | medium | flag | RTL override controls | Arabic/Hebrew documents |

## Overlap semantics

Detectors whose span *claims characters* (`email`, `credit_card`, `jwt`,
`tool_call_injection`, …) are exclusive: the higher-scoring, longer match wins.
Detectors that describe a *region* (`repeated_content`, `invisible_unicode`,
`instruction_override`, `markdown_exfil`, …) are non-exclusive, so a flood or an
instruction phrase never hides the credentials inside it.

The set is declared once in `src/guardrails_lite/detectors/__init__.py` as
`_CONTEXT_DETECTORS`.