# HTTP API Reference

Three endpoints. Stateless. No authentication (place behind a reverse proxy / auth service for production).

Default port `8080`. Override with `--port` on the uvicorn command line or `PORT` env in a container.

---

## POST /scan

Scan a string for security issues.

**Request:**
```http
POST /scan HTTP/1.1
Content-Type: application/json

{
  "content": "visit dоcs.аnthropic.com for the API"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `content` | string | yes | Text to scan. Empty string returns clean. |

**Response (clean):**
```json
{
  "clean": true,
  "has_critical_findings": false,
  "was_modified": false,
  "scan_duration_ms": 0.05,
  "findings": [],
  "sanitized_content": null
}
```

**Response (critical — block):**
```json
{
  "clean": false,
  "has_critical_findings": true,
  "was_modified": false,
  "scan_duration_ms": 0.12,
  "findings": [
    {
      "threat_category": "invisible_unicode",
      "severity": "critical",
      "description": "Invisible encoding characters detected: 45 character(s)...",
      "character_ranges": [
        [14, "U+E0155", "Supp. Variation Selector"],
        ...
      ],
      "action_taken": "blocked"
    }
  ],
  "sanitized_content": null
}
```

**Response (high — stripped):**
```json
{
  "clean": false,
  "has_critical_findings": false,
  "was_modified": true,
  "scan_duration_ms": 0.08,
  "findings": [
    {
      "threat_category": "invisible_unicode",
      "severity": "high",
      "description": "4 zero-width / bidi mark(s) detected and stripped.",
      "character_ranges": [
        [7, "U+200B", "Zero-Width Space"],
        ...
      ],
      "action_taken": "stripped"
    }
  ],
  "sanitized_content": "the content with the zero-width characters removed"
}
```

**Response (medium — flagged):**
```json
{
  "clean": false,
  "has_critical_findings": false,
  "was_modified": false,
  "scan_duration_ms": 0.05,
  "findings": [
    {
      "threat_category": "homoglyph",
      "severity": "medium",
      "description": "1 mixed-script word(s) with confusable characters: \"dоcs.аnthropic.com\"",
      "character_ranges": [
        ["dоcs.аnthropic.com", ["Cyrillic", "Latin"]]
      ],
      "action_taken": "flagged"
    }
  ],
  "sanitized_content": null
}
```

### Response fields

| Field | Type | Notes |
|---|---|---|
| `clean` | bool | True iff `findings` is empty |
| `has_critical_findings` | bool | True iff any finding has severity `critical` — caller should block |
| `was_modified` | bool | True iff `sanitized_content` differs from the input — caller should use `sanitized_content` going forward |
| `scan_duration_ms` | float | Scan time in milliseconds, rounded to 2 decimals |
| `findings` | list[Finding] | All detections, possibly empty |
| `sanitized_content` | string or null | Stripped content when `was_modified=True`, otherwise null |

### Finding fields

| Field | Type | Notes |
|---|---|---|
| `threat_category` | string | `"invisible_unicode"` \| `"homoglyph"` \| `"bidi_override"` |
| `severity` | string | `"critical"` \| `"high"` \| `"medium"` \| `"low"` |
| `description` | string | Human-readable finding |
| `character_ranges` | list | For invisible-unicode findings: list of `[position, codepoint_hex, name]`. For homoglyph findings: list of `[word, [scripts]]`. |
| `action_taken` | string | `"blocked"` \| `"stripped"` \| `"flagged"` |

### Errors

| Status | Body | Cause |
|---|---|---|
| 200 | ScanResponse | Success (even when content has critical findings — the response body describes it) |
| 422 | Pydantic validation error | `content` field missing or wrong type |

---

## GET /health

Liveness probe. Always returns 200 when the service is up.

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

Suitable for Kubernetes readiness/liveness probes and uptime monitoring.

---

## GET /

HTML landing page with a quick-start example. Human-readable. Link to `/docs`.

---

## GET /docs

FastAPI auto-generated OpenAPI UI (Swagger). Interactive schema for the `/scan` endpoint.

## GET /openapi.json

Raw OpenAPI 3.1 schema. Useful for client code generation.

---

## Client examples

### curl

```bash
curl -X POST http://localhost:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"content":"visit dоcs.аnthropic.com"}'
```

### Python (requests)

```python
import requests

r = requests.post(
    "http://localhost:8080/scan",
    json={"content": "some text to scan"},
    timeout=5,
)
verdict = r.json()
if verdict["has_critical_findings"]:
    raise SecurityError(verdict["findings"])
elif verdict["was_modified"]:
    process(verdict["sanitized_content"])
else:
    process(verdict["sanitized_content"] or original_content)
```

### JavaScript (fetch)

```javascript
const response = await fetch('http://localhost:8080/scan', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({content: userInput}),
});
const verdict = await response.json();
if (verdict.has_critical_findings) {
  throw new Error(`blocked: ${verdict.findings[0].description}`);
}
```

---

## Deployment notes

### Resource requirements

- Memory: ~80 MB resident (Python + FastAPI + uvicorn + dependencies)
- CPU: minimal — scans are pure string iteration
- Network: inbound HTTP only; no outbound calls

### Stateless

The service is fully stateless. Scale horizontally by running multiple instances behind a load balancer. No database, no cache, no shared state.

### Rate limiting

Not built in. Use a reverse proxy (nginx, Caddy, Cloudflare) or API gateway for rate limits.

### Authentication

Not built in. Deploy behind an auth layer (mTLS, JWT middleware, API key gateway).

### Request size limits

FastAPI's default JSON body size limit applies (~1 MB). Tune via uvicorn startup if you need larger payloads. Scan time is linear in content length — a 10 MB document will take roughly 200 ms to scan.
