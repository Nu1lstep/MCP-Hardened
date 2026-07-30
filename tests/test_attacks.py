"""Security assertions. RED against the naive code, GREEN after hardening lands.

Every test asserts the SECURE behavior, so each one fails today and passes once
the corresponding check is added to the helpers in src/server.py.
"""

import httpx
import pytest

from src.server import _fetch_doc, _query_records, _read_sandboxed


# --- search_files: path traversal ---


def test_search_files_relative_traversal_rejected():
    """Path traversal: a relative ../ escape out of the sandbox must be rejected."""
    with pytest.raises(ValueError):
        _read_sandboxed("../OUTSIDE_SANDBOX.txt")


def test_search_files_absolute_path_rejected():
    """Path traversal: an absolute path that discards the sandbox prefix must be rejected."""
    with pytest.raises(ValueError):
        _read_sandboxed("/etc/passwd")


# --- query_records: SQL injection ---


def test_query_records_boolean_injection_no_leak():
    """SQL injection: a boolean tautology must not leak rows outside the requested category."""
    result = _query_records("' OR '1'='1")
    assert "INTERNAL_TOKEN" not in result


def test_query_records_union_injection_no_schema_leak():
    """SQL injection: a UNION SELECT against sqlite_master must not leak the schema."""
    result = _query_records("' UNION SELECT name, sql, null, null FROM sqlite_master --")
    assert "CREATE TABLE" not in result


# --- fetch_doc: SSRF ---


@pytest.fixture
def no_network(monkeypatch):
    """Fail loudly on any real HTTP call; a ValueError instead proves the URL was rejected pre-request."""

    def boom(*args, **kwargs):
        raise RuntimeError("network call attempted; URL should have been rejected before request")

    monkeypatch.setattr(httpx, "get", boom)
    return boom


def test_fetch_doc_link_local_metadata_rejected(no_network):
    """SSRF: a request to the link-local cloud metadata address must be rejected before any request."""
    with pytest.raises(ValueError):
        _fetch_doc("http://169.254.169.254/latest/meta-data/")


def test_fetch_doc_non_https_scheme_rejected(no_network):
    """SSRF: a non-https scheme must be rejected before any request."""
    with pytest.raises(ValueError):
        _fetch_doc("http://example.com")


def test_fetch_doc_disallowed_host_rejected(no_network):
    """SSRF: a host that is not on the allowlist must be rejected before any request."""
    with pytest.raises(ValueError):
        _fetch_doc("https://not-on-the-allowlist.example.net")


def test_fetch_doc_redirect_to_metadata_rejected(monkeypatch):
    """SSRF: a redirect hop to a link-local address must be validated per-hop and rejected."""

    def fake_get(url, **kwargs):
        return httpx.Response(
            status_code=302,
            headers={"location": "http://169.254.169.254/"},
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(httpx, "get", fake_get)
    with pytest.raises(ValueError):
        _fetch_doc("https://example.com/")
