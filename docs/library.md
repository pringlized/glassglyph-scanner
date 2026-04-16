# Library Reference

Core Python API. Zero external dependencies — only the stdlib.

```python
from glassglyph_scanner import sanitize, SanitizationResult, SanitizationFinding
```

---

## sanitize(content: str) -> SanitizationResult

The single public entry point. Scans content for invisible-unicode and homoglyph attacks.

```python
from glassglyph_scanner import sanitize

result = sanitize("visit dоcs.аnthropic.com")

if result.has_critical_findings:
    # BLOCK — invisible encoding detected
    log_and_reject(result.findings)
elif result.was_modified:
    # STRIP — use sanitized content going forward
    process(result.sanitized_content)
elif result.findings:
    # FLAG — content unmodified, review findings
    queue_for_review(result.findings)
else:
    # CLEAN — proceed
    process(result.sanitized_content)
```

---

## Types

### SanitizationResult

```python
@dataclass
class SanitizationResult:
    clean: bool                      # True iff no findings
    sanitized_content: str           # content with high-sev chars removed
    findings: list[SanitizationFinding]
    has_critical_findings: bool      # signal to block
    was_modified: bool               # True iff sanitized != input
    scan_duration_ms: float
```

| Field | Meaning |
|---|---|
| `clean` | No detections of any severity. `findings == []`. |
| `sanitized_content` | For critical findings, equals the input (we block rather than strip). For high findings, the input with dangerous chars removed. For medium/low, equals the input. |
| `findings` | List of [SanitizationFinding](#sanitizationfinding). Empty iff clean. |
| `has_critical_findings` | True iff any finding has `severity == "critical"`. Callers MUST block content when this is True. |
| `was_modified` | True iff `sanitized_content` differs from the input. When True, downstream code should use `sanitized_content`, not the original. |
| `scan_duration_ms` | Scan time in milliseconds, rounded to 2 decimals. |

### SanitizationFinding

```python
@dataclass
class SanitizationFinding:
    threat_category: str    # "invisible_unicode" | "homoglyph" | "bidi_override"
    severity: str           # "critical" | "high" | "medium" | "low"
    description: str
    character_ranges: list
    action_taken: str       # "blocked" | "stripped" | "flagged"
```

| Field | Meaning |
|---|---|
| `threat_category` | One of `invisible_unicode`, `homoglyph`, `bidi_override`. |
| `severity` | `critical` (block), `high` (strip), `medium` / `low` (flag). |
| `description` | Human-readable finding with counts and example tokens. |
| `character_ranges` | For invisible findings: `list[tuple[int, str, str]]` — `(position, "U+XXXX", name)`. For homoglyph findings: `list[tuple[str, list[str]]]` — `(word, [scripts])`. |
| `action_taken` | The action performed: `blocked`, `stripped`, or `flagged`. |

---

## Usage patterns

### Gate at an ingestion boundary

The most common integration. Scan raw content before any LLM sees it.

```python
def ingest(source_doc):
    result = sanitize(source_doc.raw_content)

    if result.has_critical_findings:
        log.error(f"blocked source {source_doc.id}: {result.findings}")
        source_doc.status = "FAILED"
        return

    if result.was_modified:
        log.warning(f"stripped {len(result.findings)} findings from {source_doc.id}")
        source_doc.raw_content = result.sanitized_content

    for finding in result.findings:
        source_doc.security_findings.append({
            "category": finding.threat_category,
            "severity": finding.severity,
            "action": finding.action_taken,
            "description": finding.description,
        })

    proceed_to_chunking(source_doc)
```

### Fail-fast validation

For stricter systems that reject anything suspicious:

```python
def validate_strict(content: str) -> str:
    result = sanitize(content)
    if result.findings:
        raise ValueError(f"suspicious content: {result.findings[0].description}")
    return content
```

### Defensive retrieval

Optional second gate at retrieval time:

```python
def retrieve_and_scan(doc_id: str) -> str | None:
    doc = load(doc_id)
    result = sanitize(doc.content)
    if result.has_critical_findings:
        # Someone bypassed the ingestion gate or a rule was added later
        alert_security(doc_id, result.findings)
        return None
    return result.sanitized_content
```

### Batch processing

The scanner is stateless and thread-safe. Parallelize freely:

```python
from concurrent.futures import ThreadPoolExecutor

def scan_many(documents: list[str]) -> list[SanitizationResult]:
    with ThreadPoolExecutor() as pool:
        return list(pool.map(sanitize, documents))
```

---

## Extending the confusables table

The default table covers the highest-risk Latin ↔ Cyrillic and Latin ↔ Greek substitutions. Extend it for your domain:

```python
# Monkey-patch at application startup, before any sanitize() call
from glassglyph_scanner import sanitizer

sanitizer._CONFUSABLES.update({
    0x0501: 0x0064,  # ԁ → d (additional Cyrillic)
    # ... more pairs
})
```

For a production system that needs the full Unicode TR39 confusables list, fork the module and expand the table. The detection logic needs no other changes.

---

## Installation

```bash
# Core library only (zero external dependencies)
pip install glassglyph-scanner

# With CLI
pip install 'glassglyph-scanner[cli]'

# With HTTP service
pip install 'glassglyph-scanner[server]'

# Everything (library + CLI + server)
pip install 'glassglyph-scanner[all]'
```

Minimum Python: **3.10** (uses `dataclass` defaults and modern type syntax).
