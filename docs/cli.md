# CLI Reference

```bash
glassglyph-scanner scan FILE            # scan a file
glassglyph-scanner scan -               # scan stdin
glassglyph-scanner scan FILE --json     # machine-readable output
glassglyph-scanner scan FILE --quiet    # exit code only, no output
glassglyph-scanner --version
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings |
| `1` | Findings present (stripped or flagged) but not critical |
| `2` | Critical findings — content should be blocked |
| `64` | Usage error (file not found, etc.) |

Designed for pipe and CI use. `glassglyph-scanner scan file.txt && echo clean` works as expected.

---

## Installation

```bash
pip install 'glassglyph-scanner[cli]'
```

Or from source:
```bash
pip install -e '.[cli]'
```

---

## Examples

### Scan a file

```bash
$ glassglyph-scanner scan examples/homoglyph_url_spoof.txt
⚠ examples/homoglyph_url_spoof.txt: FLAGGED (0.24ms)
  [medium  ] homoglyph          flagged   4 mixed-script word(s) with confusable characters: "dоcs.аnthropic.com", "рython,", "Аnthrоріс", "Роlісу"
```

### Scan stdin

```bash
$ echo 'visit dоcs.аnthropic.com' | glassglyph-scanner scan -
⚠ <stdin>: FLAGGED (0.05ms)
  [medium  ] homoglyph          flagged   1 mixed-script word(s) with confusable characters: "dоcs.аnthropic.com"
```

### Machine-readable output

```bash
$ glassglyph-scanner scan examples/clean.txt --json
{
  "source": "examples/clean.txt",
  "clean": true,
  "has_critical_findings": false,
  "was_modified": false,
  "scan_duration_ms": 0.22,
  "findings": [],
  "sanitized_content": null
}
```

### Quiet mode (exit code only)

Useful in shell scripts and CI:

```bash
if ! glassglyph-scanner scan "$FILE" --quiet; then
    echo "security issues in $FILE"
    exit 1
fi
```

### Batch scan all example fixtures

```bash
for f in examples/*.txt; do
    glassglyph-scanner scan "$f" --quiet
    echo "$f exit=$?"
done
```

Output:
```
examples/bidi_override.txt exit=1
examples/clean.txt exit=0
examples/glassworm_attack.txt exit=2
examples/homoglyph_url_spoof.txt exit=1
examples/zero_width_strip.txt exit=1
```

### Generate your own Glassworm payload

```bash
python examples/generate_glassworm.py "rm -rf /" > /tmp/attack.txt
glassglyph-scanner scan /tmp/attack.txt
# → BLOCKED (exit 2)
```
