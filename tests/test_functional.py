"""Functional regression guards. GREEN against the naive code and after hardening."""

import httpx

from src.server import _fetch_doc, _query_records, _read_sandboxed


def test_search_files_reads_note():
    """Legitimate sandbox read keeps working (regression guard for the path-traversal fix)."""
    result = _read_sandboxed("notes.txt")
    assert "quarterly numbers" in result


def test_query_records_public_returns_public_not_internal():
    """Legitimate category lookup keeps working (regression guard for the SQL-injection fix)."""
    result = _query_records("public")
    assert "Acme Landing Page" in result
    assert "INTERNAL_TOKEN" not in result


def test_fetch_doc_allowlisted_host_returns_body(monkeypatch):
    """Legitimate fetch of an allowlisted host keeps working (regression guard for the SSRF fix)."""

    def fake_get(url, **kwargs):
        return httpx.Response(
            status_code=200,
            text="hello from example",
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(httpx, "get", fake_get)
    result = _fetch_doc("https://example.com")
    assert "hello from example" in result
