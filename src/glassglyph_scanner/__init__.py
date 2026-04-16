"""Glassglyph Scanner — invisible unicode & homoglyph scanner.

Public API:

    from glassglyph_scanner import sanitize, SanitizationResult, SanitizationFinding

    result = sanitize("some text")
    if result.has_critical_findings:
        # block — invisible encoding detected
        ...
    elif result.was_modified:
        # strip path — use result.sanitized_content
        ...
    elif result.findings:
        # flag path — content unmodified, review findings
        ...

CLI: `glassglyph-scanner scan <file>` (requires `pip install glassglyph-scanner[cli]`)
HTTP: `uvicorn glassglyph_scanner.server:app` (requires `pip install glassglyph-scanner[server]`)
"""
from .sanitizer import (
    sanitize,
    SanitizationResult,
    SanitizationFinding,
)

__version__ = "0.1.0"

__all__ = [
    "sanitize",
    "SanitizationResult",
    "SanitizationFinding",
    "__version__",
]
