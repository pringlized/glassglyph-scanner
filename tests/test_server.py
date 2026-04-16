"""Tests for the HTTP service."""
from __future__ import annotations

from fastapi.testclient import TestClient

from glassglyph_scanner.server import app

client = TestClient(app)


def test_health() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_landing_page() -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "Glassglyph Scanner" in r.text


def test_scan_clean_content() -> None:
    r = client.post("/scan", json={"content": "plain ASCII text"})
    assert r.status_code == 200
    body = r.json()
    assert body["clean"] is True
    assert body["has_critical_findings"] is False
    assert body["findings"] == []
    assert body["sanitized_content"] is None


def test_scan_glassworm_blocks() -> None:
    payload = "const data = `" + chr(0xFE05) + chr(0xE0155) + "`;"
    r = client.post("/scan", json={"content": payload})
    body = r.json()
    assert body["clean"] is False
    assert body["has_critical_findings"] is True
    assert any(f["severity"] == "critical" for f in body["findings"])


def test_scan_homoglyph_flagged() -> None:
    r = client.post("/scan", json={"content": "visit dоcs.аnthropic.com"})
    body = r.json()
    assert body["has_critical_findings"] is False
    assert body["was_modified"] is False
    assert any(f["severity"] == "medium" for f in body["findings"])


def test_scan_zero_width_stripped_returns_sanitized() -> None:
    r = client.post("/scan", json={"content": "Hello\u200bworld"})
    body = r.json()
    assert body["has_critical_findings"] is False
    assert body["was_modified"] is True
    assert body["sanitized_content"] == "Helloworld"


def test_scan_missing_content_field_422() -> None:
    r = client.post("/scan", json={})
    assert r.status_code == 422


def test_openapi_available() -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert "/scan" in spec["paths"]
