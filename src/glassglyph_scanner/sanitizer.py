"""Glassglyph Scanner — character-level sanitization for invisible unicode and
homoglyph attacks.

Scans text for three attack classes:

1. **Invisible unicode encoding** (Glassworm-class). Variation selectors and
   supplementary variation selectors span 256 codepoints that map one-to-one
   to byte values 0-255, allowing arbitrary binary payloads to be encoded
   as invisible characters. Zero-width marks, bidi overrides, and tag
   characters are additional invisible channels.

2. **Bidi override attacks.** Control characters that reverse visual text
   direction, used to make `safe.txt` display identically to `safe[RLO]txt.exe`.

3. **Homoglyph substitution.** Mixed-script words using characters from
   Cyrillic or Greek that visually resemble Latin letters. `аnthropic.com`
   (Cyrillic а) looks identical to `anthropic.com` (Latin a).

Cost: <1ms per document. Pure string iteration, no external dependencies,
no network I/O, no LLM inference.

Public API: call `sanitize(text)` and inspect the returned
`SanitizationResult`. Critical findings block the document (sanitizer sets
`has_critical_findings=True`); high findings are stripped from the content
(`was_modified=True`); medium/low findings are flagged without modifying
content.
"""
from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field

# ────────────────────────────────────────────────────────────────────
# Invisible character ranges
# ────────────────────────────────────────────────────────────────────

# Glassworm primary — variation selectors (maps bytes 0-15)
_VS_START = 0xFE00
_VS_END = 0xFE0F

# Glassworm secondary — supplementary variation selectors (maps bytes 16-255)
_SVS_START = 0xE0100
_SVS_END = 0xE01EF

# Zero-width and bidi marks
_ZW_BIDI = {
    0x200B: "Zero-Width Space",
    0x200C: "Zero-Width Non-Joiner",
    0x200D: "Zero-Width Joiner",
    0x200E: "Left-to-Right Mark",
    0x200F: "Right-to-Left Mark",
}

# Bidi override controls — used for visual reordering attacks
_BIDI_OVERRIDES = {
    0x202A: "Left-to-Right Embedding",
    0x202B: "Right-to-Left Embedding",
    0x202C: "Pop Directional Formatting",
    0x202D: "Left-to-Right Override",
    0x202E: "Right-to-Left Override",
}

# Invisible operators and deprecated language tag
_OTHER_INVISIBLE = {
    0x2060: "Word Joiner",
    0x2061: "Function Application",
    0x2062: "Invisible Times",
    0x2063: "Invisible Separator",
    0x2064: "Invisible Plus",
    0xE0001: "Language Tag (deprecated)",
}

# Tag characters — maps 1:1 to printable ASCII as invisible chars.
# No legitimate text use → critical/block.
_TAG_START = 0xE0020
_TAG_END = 0xE007F

# Byte Order Mark — legitimate at position 0 only
_BOM = 0xFEFF


# ────────────────────────────────────────────────────────────────────
# Homoglyph confusables (Latin ← Cyrillic / Greek)
# ────────────────────────────────────────────────────────────────────
#
# This is a curated subset of Unicode TR39 confusables covering the
# highest-risk substitutions. Extending the table requires no other
# code changes.

_CONFUSABLES: dict[int, int] = {
    # Cyrillic → Latin
    0x0430: 0x0061,  # а → a
    0x0441: 0x0063,  # с → c
    0x0435: 0x0065,  # е → e
    0x043E: 0x006F,  # о → o
    0x0440: 0x0070,  # р → p
    0x0445: 0x0078,  # х → x
    0x0443: 0x0079,  # у → y
    0x041D: 0x0048,  # Н → H
    0x0412: 0x0042,  # В → B
    0x041C: 0x004D,  # М → M
    0x0422: 0x0054,  # Т → T
    0x0410: 0x0041,  # А → A
    0x0415: 0x0045,  # Е → E
    0x041E: 0x004F,  # О → O
    0x0420: 0x0050,  # Р → P
    0x0421: 0x0043,  # С → C
    0x0425: 0x0058,  # Х → X
    # Greek → Latin
    0x03B1: 0x0061,  # α → a
    0x03B5: 0x0065,  # ε → e
    0x03BF: 0x006F,  # ο → o
    0x03C1: 0x0070,  # ρ → p
    0x03C7: 0x0078,  # χ → x
    0x03C5: 0x0079,  # υ → y
    0x0397: 0x0048,  # Η → H
    0x0392: 0x0042,  # Β → B
    0x039C: 0x004D,  # Μ → M
    0x03A4: 0x0054,  # Τ → T
}


# ────────────────────────────────────────────────────────────────────
# Public data types
# ────────────────────────────────────────────────────────────────────

@dataclass
class SanitizationFinding:
    """A single detection event.

    Attributes:
        threat_category: "invisible_unicode" | "homoglyph" | "bidi_override"
        severity: "critical" | "high" | "medium" | "low"
        description: human-readable finding
        character_ranges: list of (position, codepoint_hex, name) tuples for
            invisible characters, or list of (word, [scripts]) tuples for
            homoglyph findings
        action_taken: "blocked" | "stripped" | "flagged"
    """
    threat_category: str
    severity: str
    description: str
    character_ranges: list
    action_taken: str


@dataclass
class SanitizationResult:
    """The full output of `sanitize()`.

    Attributes:
        clean: True if no findings at any severity
        sanitized_content: content with high-severity chars stripped out.
            For critical findings, this equals the original content (we
            block rather than strip).
        findings: list of SanitizationFinding, possibly empty
        has_critical_findings: True if any finding is severity="critical".
            Callers should block the document when this is True.
        was_modified: True if sanitized_content differs from the input
            (i.e. characters were stripped)
        scan_duration_ms: how long the scan took, rounded to 2 decimals
    """
    clean: bool
    sanitized_content: str
    findings: list = field(default_factory=list)
    has_critical_findings: bool = False
    was_modified: bool = False
    scan_duration_ms: float = 0.0


# ────────────────────────────────────────────────────────────────────
# Script classification
# ────────────────────────────────────────────────────────────────────

def _get_char_script(cp: int) -> str:
    """Return the Unicode script for a codepoint.

    Returns one of: Latin, Cyrillic, Greek, Common, Other, Unknown.

    Non-alphabetic scripts (Arabic, Hebrew, CJK, etc.) return "Other" and
    are excluded from mixed-script detection. This is a deliberate
    false-positive hedge — Arabic names in English text are common and
    legitimate. Homoglyph attacks overwhelmingly use Cyrillic or Greek
    substitutions.
    """
    if 0x0400 <= cp <= 0x04FF or 0x0500 <= cp <= 0x052F:
        return "Cyrillic"
    if 0x0370 <= cp <= 0x03FF or 0x1F00 <= cp <= 0x1FFF:
        return "Greek"
    if 0x0041 <= cp <= 0x005A or 0x0061 <= cp <= 0x007A:
        return "Latin"
    if 0x0030 <= cp <= 0x0039:
        return "Common"
    try:
        cat = unicodedata.category(chr(cp))
    except ValueError:
        return "Unknown"
    if cat.startswith("P") or cat.startswith("Z") or cat.startswith("S"):
        return "Common"
    return "Other"


# ────────────────────────────────────────────────────────────────────
# Scanners
# ────────────────────────────────────────────────────────────────────

def _scan_invisible(content: str) -> list[SanitizationFinding]:
    glassworm_hits = []      # critical — variation selectors
    tag_hits = []            # critical — tag chars (pure encoding medium)
    zw_bidi_hits = []        # high — zero-width / bidi marks
    bidi_override_hits = []  # high — bidi overrides
    other_hits = []          # high — invisible operators, language tag, BOM

    for pos, char in enumerate(content):
        cp = ord(char)

        if _VS_START <= cp <= _VS_END:
            glassworm_hits.append((pos, f"U+{cp:04X}", "Variation Selector"))
            continue
        if _SVS_START <= cp <= _SVS_END:
            glassworm_hits.append((pos, f"U+{cp:05X}", "Supp. Variation Selector"))
            continue
        if cp in _ZW_BIDI:
            zw_bidi_hits.append((pos, f"U+{cp:04X}", _ZW_BIDI[cp]))
            continue
        if cp in _BIDI_OVERRIDES:
            bidi_override_hits.append((pos, f"U+{cp:04X}", _BIDI_OVERRIDES[cp]))
            continue
        if cp in _OTHER_INVISIBLE:
            other_hits.append((pos, f"U+{cp:04X}", _OTHER_INVISIBLE[cp]))
            continue
        if _TAG_START <= cp <= _TAG_END:
            tag_hits.append((pos, f"U+{cp:05X}", "Tag Character"))
            continue
        # BOM at position 0 is a legitimate file-encoding marker; elsewhere
        # it's a hidden marker that could be used as a separator.
        if cp == _BOM and pos > 0:
            other_hits.append((pos, f"U+{cp:04X}", "BOM (not at position 0)"))

    findings: list[SanitizationFinding] = []

    if glassworm_hits or tag_hits:
        combined = glassworm_hits + tag_hits
        findings.append(SanitizationFinding(
            threat_category="invisible_unicode",
            severity="critical",
            description=(
                f"Invisible encoding characters detected: {len(combined)} "
                f"character(s) from ranges with no legitimate text use. "
                f"These ranges are used to encode arbitrary binary payloads "
                f"as invisible text."
            ),
            character_ranges=combined,
            action_taken="blocked",
        ))

    if zw_bidi_hits:
        findings.append(SanitizationFinding(
            threat_category="invisible_unicode",
            severity="high",
            description=f"{len(zw_bidi_hits)} zero-width / bidi mark(s) detected and stripped.",
            character_ranges=zw_bidi_hits,
            action_taken="stripped",
        ))

    if bidi_override_hits:
        findings.append(SanitizationFinding(
            threat_category="bidi_override",
            severity="high",
            description=f"{len(bidi_override_hits)} bidi override control(s) detected and stripped.",
            character_ranges=bidi_override_hits,
            action_taken="stripped",
        ))

    if other_hits:
        findings.append(SanitizationFinding(
            threat_category="invisible_unicode",
            severity="high",
            description=f"{len(other_hits)} invisible operator / marker character(s) detected and stripped.",
            character_ranges=other_hits,
            action_taken="stripped",
        ))

    return findings


def _scan_homoglyphs(content: str) -> list[SanitizationFinding]:
    mixed_script_words = []

    for word in re.findall(r"\S+", content):
        scripts: set[str] = set()
        has_confusable = False

        for char in word:
            cp = ord(char)
            script = _get_char_script(cp)
            if script not in ("Common", "Other"):
                scripts.add(script)
            if cp in _CONFUSABLES:
                has_confusable = True

        # Only flag when the word mixes Latin with another script
        if len(scripts) > 1 and "Latin" in scripts:
            mixed_script_words.append({
                "word": word,
                "scripts": sorted(scripts),
                "has_confusable": has_confusable,
            })

    if not mixed_script_words:
        return []

    with_conf = [w for w in mixed_script_words if w["has_confusable"]]
    without_conf = [w for w in mixed_script_words if not w["has_confusable"]]

    findings: list[SanitizationFinding] = []
    if with_conf:
        word_list = ", ".join(f'"{w["word"]}"' for w in with_conf[:5])
        findings.append(SanitizationFinding(
            threat_category="homoglyph",
            severity="medium",
            description=(
                f"{len(with_conf)} mixed-script word(s) with confusable characters: "
                f"{word_list}"
            ),
            character_ranges=[(w["word"], w["scripts"]) for w in with_conf],
            action_taken="flagged",
        ))

    if without_conf:
        word_list = ", ".join(f'"{w["word"]}"' for w in without_conf[:5])
        findings.append(SanitizationFinding(
            threat_category="homoglyph",
            severity="low",
            description=(
                f"{len(without_conf)} mixed-script word(s) without known confusables: "
                f"{word_list}"
            ),
            character_ranges=[(w["word"], w["scripts"]) for w in without_conf],
            action_taken="flagged",
        ))

    return findings


def _strip_characters(content: str, findings: list[SanitizationFinding]) -> str:
    positions_to_strip: set[int] = set()
    for finding in findings:
        if finding.action_taken != "stripped":
            continue
        for entry in finding.character_ranges:
            # Invisible findings carry (pos, cp_hex, name); homoglyph findings
            # carry (word, [scripts]) — only the former are strippable.
            if isinstance(entry[0], int):
                positions_to_strip.add(entry[0])

    if not positions_to_strip:
        return content
    return "".join(
        char for pos, char in enumerate(content)
        if pos not in positions_to_strip
    )


# ────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────

def sanitize(content: str) -> SanitizationResult:
    """Scan content for invisible unicode and homoglyph attacks.

    Returns a SanitizationResult with:

    - `has_critical_findings=True` → callers should BLOCK this content.
      No legitimate text contains Glassworm variation selectors or tag
      characters; their presence indicates an encoding attack.

    - `was_modified=True` → content was STRIPPED of zero-width / bidi /
      invisible-operator characters. Use `sanitized_content` going forward;
      the findings record what was removed.

    - `findings` with severity medium/low only → content was FLAGGED but
      not modified. Mixed-script words can appear in legitimate multilingual
      content; review the findings to decide.

    - `clean=True, findings=[]` → no suspicious characters detected.

    The scan is a pure string iteration with no I/O; for any reasonable
    content size this completes in well under a millisecond.
    """
    start = time.monotonic()

    all_findings = _scan_invisible(content) + _scan_homoglyphs(content)
    has_critical = any(f.severity == "critical" for f in all_findings)

    if has_critical:
        # Don't strip on a block — we're rejecting the content wholesale
        duration_ms = (time.monotonic() - start) * 1000
        return SanitizationResult(
            clean=False,
            sanitized_content=content,
            findings=all_findings,
            has_critical_findings=True,
            was_modified=False,
            scan_duration_ms=round(duration_ms, 2),
        )

    sanitized = _strip_characters(content, all_findings)
    was_modified = sanitized != content
    duration_ms = (time.monotonic() - start) * 1000

    return SanitizationResult(
        clean=len(all_findings) == 0,
        sanitized_content=sanitized,
        findings=all_findings,
        has_critical_findings=False,
        was_modified=was_modified,
        scan_duration_ms=round(duration_ms, 2),
    )
