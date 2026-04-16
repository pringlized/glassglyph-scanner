"""Glassglyph Scanner HTTP service.

A tiny FastAPI wrapper around the scanner so platform teams can POST content
and get a JSON verdict. Stateless, no database, no auth — drop behind a
reverse proxy for production.

    uvicorn glassglyph_scanner.server:app --host 0.0.0.0 --port 8080

Endpoints:
    GET  /              landing page with quick usage
    GET  /health        liveness probe
    POST /scan          scan the `content` field of the JSON body
    GET  /docs          auto-generated OpenAPI UI (FastAPI built-in)
"""
from __future__ import annotations

from dataclasses import asdict

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import __version__
from .sanitizer import sanitize

app = FastAPI(
    title="Glassglyph Scanner",
    description="Invisible unicode & homoglyph scanner.",
    version=__version__,
)


class ScanRequest(BaseModel):
    content: str = Field(..., description="Text to scan. Empty strings return clean.")


class FindingModel(BaseModel):
    threat_category: str
    severity: str
    description: str
    character_ranges: list
    action_taken: str


class ScanResponse(BaseModel):
    clean: bool
    has_critical_findings: bool
    was_modified: bool
    scan_duration_ms: float
    findings: list[FindingModel]
    sanitized_content: str | None = Field(
        None,
        description="Present only when content was modified (high-severity chars stripped).",
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/scan", response_model=ScanResponse)
def scan_endpoint(req: ScanRequest) -> ScanResponse:
    result = sanitize(req.content)
    return ScanResponse(
        clean=result.clean,
        has_critical_findings=result.has_critical_findings,
        was_modified=result.was_modified,
        scan_duration_ms=result.scan_duration_ms,
        findings=[FindingModel(**asdict(f)) for f in result.findings],
        sanitized_content=result.sanitized_content if result.was_modified else None,
    )


@app.get("/", response_class=HTMLResponse)
def landing() -> str:
    return f"""<!doctype html>
<html><head>
<title>Glassglyph Scanner {__version__}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 3em auto; padding: 0 1em; color: #222; }}
  code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }}
  pre {{ background: #f7f7f7; padding: 12px; border-radius: 4px; overflow-x: auto; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.3em; }}
</style>
</head><body>
<h1>Glassglyph Scanner <small>v{__version__}</small></h1>
<p>Invisible unicode &amp; homoglyph scanner.
<a href="/docs">OpenAPI docs</a> ·
<a href="/health">health</a>
</p>
<h2>Quick try</h2>
<pre>curl -X POST http://localhost:8080/scan \\
  -H 'Content-Type: application/json' \\
  -d '{{"content":"visit dоcs.аnthropic.com"}}'</pre>
<p>The Cyrillic <code>о</code> and <code>а</code> in that URL are homoglyphs — the scanner flags them.</p>
<h2>Paths</h2>
<ul>
  <li><code>POST /scan</code> — body: <code>{{"content": "..."}}</code>, returns a scan verdict.</li>
  <li><code>GET /health</code> — liveness probe.</li>
  <li><code>GET /docs</code> — interactive OpenAPI docs.</li>
</ul>
</body></html>"""
