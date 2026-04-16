# glassglyph-scanner

**A reference scanner for invisible unicode and homoglyph attacks on text-based systems.**

In March 2026, the [Glassworm campaign](https://www.aikido.dev/blog/glassworm) compromised 151+ GitHub repositories, npm packages, and VS Code extensions by smuggling malicious code inside invisible Unicode characters — text that renders as zero pixels in every editor, terminal, code review tool, and browser. The same class of attack works against RAG pipelines, LLM agents, email, chat, and any system that ingests text and later retrieves it as context.

glassglyph-scanner scans text for three attack classes:

1. **Invisible unicode encoding** — Glassworm's substitution cipher (variation selectors `U+FE00`–`U+FE0F` and `U+E0100`–`U+E01EF`) plus tag characters that map 1:1 to printable ASCII
2. **Bidi override attacks** — control characters that visually reorder text (`safe.txt` → `safe[RLO]txt.exe`)
3. **Homoglyph substitution** — Cyrillic and Greek characters replacing visually identical Latin letters (`аnthropic.com` with Cyrillic `а`)

Cost: **under a millisecond per document**. Pure string iteration, zero external dependencies in the core library.

---

## Quick start

=== "Docker"

    ```bash
    git clone https://github.com/pringlized/glassglyph-scanner.git
    cd glassglyph-scanner
    docker compose up -d

    curl -X POST http://localhost:8080/scan \
      -H 'Content-Type: application/json' \
      -d '{"content":"visit dоcs.аnthropic.com"}'
    ```

    The scanner flags the Cyrillic `о` and `а` as a medium-severity homoglyph finding.

=== "CLI"

    ```bash
    pip install -e '.[cli]'

    echo 'visit dоcs.аnthropic.com' | glassglyph-scanner scan -
    # → FLAGGED (exit 1)

    echo 'plain text' | glassglyph-scanner scan -
    # → clean (exit 0)
    ```

=== "Python library"

    ```python
    from glassglyph_scanner import sanitize

    result = sanitize("visit dоcs.аnthropic.com")
    print(result.findings[0].description)
    # 1 mixed-script word(s) with confusable characters: "dоcs.аnthropic.com"
    ```

---

## Why this matters

Traditional supply-chain attacks need a decoder at the execution site. **RAG pipelines are different — the LLM is both target and decoder.** When a poisoned item is retrieved as agent context:

1. The agent reads it as knowledge
2. LLMs tokenize at the byte level — invisible characters are not invisible to the model
3. The model may follow instructions encoded in them
4. The item was embedded and clustered with legitimate knowledge, so it has full semantic credibility

**Ingestion-time scanning is the only viable enforcement point.** Once the content is embedded, it's semantically indistinguishable from clean knowledge.

See the [threat model](threat-model.md) for the full attack analysis.

---

## Detection summary

| Attack class | Severity | Action |
|---|---|---|
| Glassworm variation selectors | Critical | Block |
| Tag characters (pure encoding medium) | Critical | Block |
| Zero-width / bidi marks | High | Strip |
| Bidi overrides (`U+202E` etc.) | High | Strip |
| Invisible math operators | High | Strip |
| Homoglyph with known confusable | Medium | Flag |
| Mixed-script without confusable | Low | Flag |

Full rule reference: [Detection Rules](detection-rules.md).

---

## What this is NOT

- **Not a semantic/intent scanner.** Character-level detection only. Natural-language prompt injection in plain ASCII is outside the scope — that class requires LLM inference to detect. See the [threat model](threat-model.md#two-gate-defense-model) for the two-gate defense pattern.
- **Not a content filter.** Scans for encoding-based attacks, not policy violations, PII, or toxic content.
- **Not a replacement for TLS, authentication, rate limiting, or other perimeter controls.**

---

## Project structure

```
glassglyph-scanner/
├── src/glassglyph_scanner/    # core library + CLI + HTTP service
│   ├── sanitizer.py           # the detection logic (zero deps)
│   ├── cli.py                 # typer CLI
│   └── server.py              # FastAPI HTTP service
├── tests/                     # unit + CLI + HTTP tests
├── examples/                  # real attack payloads + payload generator
├── docs/                      # this site
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

Research basis: Aikido Security's March 2026 Glassworm writeup, Unicode Consortium TR39 confusables data, and community security research on invisible-unicode supply-chain attacks. Built as a reference extraction from the Mens Altera ingestion pipeline's Gate 1 character sanitization layer.
