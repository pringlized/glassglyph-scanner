# Detection Rules

The full set of rules glassglyph-scanner applies to input text. Each rule has a severity and an action.

## Severity → action mapping

| Severity | Action | Effect on content |
|---|---|---|
| **critical** | `blocked` | Content not modified. Caller should reject the document wholesale. `has_critical_findings=True`. |
| **high** | `stripped` | Offending characters removed. Caller uses `sanitized_content` for downstream processing. `was_modified=True`. |
| **medium** | `flagged` | Content not modified. Finding logged for review. |
| **low** | `flagged` | Content not modified. Finding logged for review. |

Critical findings take precedence: if any critical rule fires, the content is blocked and no stripping is attempted (nothing to strip into — we are rejecting).

---

## Invisible unicode rules

### Critical (blocked)

| Range | Rule ID | Description |
|---|---|---|
| `U+FE00`–`U+FE0F` | Variation Selectors | Glassworm primary encoding range. Maps bytes 0–15 to invisible characters. No legitimate natural-language use. |
| `U+E0100`–`U+E01EF` | Supplementary Variation Selectors | Glassworm secondary encoding range. Maps bytes 16–255. Together with the primary range, covers the full byte space for arbitrary payload encoding. |
| `U+E0020`–`U+E007F` | Tag Characters | Deprecated Unicode block. Maps 1-to-1 to printable ASCII (`U+0020`–`U+007F`) as invisible characters. Pure encoding medium, no legitimate text use. |

### High (stripped)

| Range / Codepoint | Rule ID | Description |
|---|---|---|
| `U+200B` | Zero-Width Space | Line-break hint. Can be used as payload separator. |
| `U+200C` | Zero-Width Non-Joiner | Script shaping. Payload separator risk. |
| `U+200D` | Zero-Width Joiner | Emoji sequences, Indic scripts. Payload separator risk. |
| `U+200E` | Left-to-Right Mark | Bidi layout. Direction manipulation risk. |
| `U+200F` | Right-to-Left Mark | Bidi layout. Direction manipulation risk. |
| `U+202A` | Left-to-Right Embedding | Bidi override (control). |
| `U+202B` | Right-to-Left Embedding | Bidi override (control). |
| `U+202C` | Pop Directional Formatting | Bidi override (control). |
| `U+202D` | Left-to-Right Override | Bidi override (control). Visual reordering attack. |
| `U+202E` | Right-to-Left Override | Bidi override (control). `safe.txt`/`safe.exe` rename attack. |
| `U+2060` | Word Joiner | Prevent line breaks. Payload separator risk. |
| `U+2061`–`U+2064` | Invisible Math Operators | MathML rendering. No use in natural language. |
| `U+FEFF` (position > 0) | Zero-Width No-Break Space | Legitimate at position 0 only (BOM). Elsewhere, hidden marker. |
| `U+E0001` | Language Tag (deprecated) | Legacy language-tagging mechanism. No modern use. |

---

## Homoglyph rules

### Medium (flagged)

Applied per whitespace-delimited word. Fires when:

1. The word contains characters from **multiple scripts**, and
2. **Latin is one of them**, and
3. At least one non-Latin character is in the confusables table

```
Mixed-script word with confusable → medium
```

Examples:
- `аnthropic` (Cyrillic `а` + Latin `nthropic`) → medium
- `рython` (Cyrillic `р` + Latin `ython`) → medium
- `pαrameter` (Latin `p` + Greek `α` + Latin `rameter`) → medium

### Low (flagged)

Same mixed-script + Latin condition as medium, but no character in the word is on the confusables table.

```
Mixed-script word without known confusable → low
```

Examples:
- `aжb` (Latin `a` + Cyrillic `ж` + Latin `b`) → low. Cyrillic `ж` has no Latin lookalike, but mixing is still unusual enough to note.

### Confusables table

Current coverage (Latin ← lookalike):

| Latin | Cyrillic | Greek |
|---|---|---|
| `a` | `а` (U+0430) | `α` (U+03B1) |
| `c` | `с` (U+0441) | — |
| `e` | `е` (U+0435) | `ε` (U+03B5) |
| `o` | `о` (U+043E) | `ο` (U+03BF) |
| `p` | `р` (U+0440) | `ρ` (U+03C1) |
| `x` | `х` (U+0445) | `χ` (U+03C7) |
| `y` | `у` (U+0443) | `υ` (U+03C5) |
| `A` | `А` (U+0410) | — |
| `B` | `В` (U+0412) | `Β` (U+0392) |
| `C` | `С` (U+0421) | — |
| `E` | `Е` (U+0415) | — |
| `H` | `Н` (U+041D) | `Η` (U+0397) |
| `M` | `М` (U+041C) | `Μ` (U+039C) |
| `O` | `О` (U+041E) | — |
| `P` | `Р` (U+0420) | — |
| `T` | `Т` (U+0422) | `Τ` (U+03A4) |
| `X` | `Х` (U+0425) | — |

This is a curated subset of Unicode TR39 confusables, covering the highest-risk substitutions. The table is defined in `src/glassglyph_scanner/sanitizer.py::_CONFUSABLES` and can be extended by appending entries.

### Scripts excluded from mixed-script detection

For false-positive control, the following scripts are classified as **Other** and excluded from the mixed-script check:

- Arabic
- Hebrew
- Devanagari
- CJK (Chinese/Japanese/Korean)
- All other non-Latin/Cyrillic/Greek scripts

Rationale: Arabic and Hebrew names in English text are common and legitimate. CJK mixed with Latin appears in technical documentation. Flagging these would produce unusable false-positive rates. Homoglyph attacks in the wild overwhelmingly use Cyrillic or Greek — those are the only scripts the detector targets.

If your use case legitimately mixes Latin with a script this detector ignores, no findings will fire for those words. If your use case needs to flag those mixes, extend `_get_char_script` in the sanitizer.

---

## Clean path

Content produces no findings when:

- All characters are printable ASCII, OR
- All characters are in a single script (including non-Latin scripts like Cyrillic, Greek, Arabic, CJK), OR
- Mixed-script words use only scripts classified as "Other" (Arabic+Latin, etc.), OR
- The only BOM character is at position 0

Clean content returns `clean=True`, `findings=[]`, `sanitized_content` identical to input, `was_modified=False`, `has_critical_findings=False`.

---

## Stacked findings

A single input can produce multiple findings. Example: a document with both a Glassworm payload and a homoglyph URL produces a critical finding (Glassworm) and a medium finding (homoglyph). The critical finding wins: `has_critical_findings=True`, `was_modified=False` (no stripping attempted on a blocked document).

A document with both zero-width characters (high, stripped) and homoglyphs (medium, flagged) produces both findings. The content is modified (high path strips), and the homoglyph finding is reported separately. `has_critical_findings=False`, `was_modified=True`.

---

## Performance

| Content size | Typical scan time |
|---|---|
| 100 bytes | ~0.05 ms |
| 1 KB | ~0.1 ms |
| 10 KB | ~0.3 ms |
| 100 KB | ~2 ms |
| 1 MB | ~20 ms |

Scan cost is linear in content length. No network I/O, no LLM inference, no external dependencies — only stdlib string iteration.
