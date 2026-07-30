"""Audit log assertions.

Every test redirects AUDIT_LOG_PATH into tmp_path, so nothing here writes into
the real logs/ directory. All offline and deterministic — the rejection case
uses a traversal attempt rather than a network call.

These exercise the @mcp.tool functions rather than the _helpers, because the
audit log records tool invocations and a direct helper call is not one.
"""

import json

import pytest

from src import server
from src.server import ping, search_files


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Point the audit log at a temp file and hand back its path."""
    path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setattr(server, "AUDIT_LOG_PATH", path)
    return path


def _entries(path):
    """Parse the log, asserting every line is valid JSON as it goes."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_successful_call_appends_ok_entry(audit_log):
    """A call that succeeds writes exactly one entry with outcome "ok"."""
    ping("hello")

    entries = _entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["outcome"] == "ok"
    assert entries[0]["result_len"] == len("pong: hello")
    assert "error" not in entries[0]


def test_rejected_call_appends_rejected_entry_with_error(audit_log):
    """A rejected traversal attempt is recorded, and the exception still raises."""
    with pytest.raises(ValueError):
        search_files("../OUTSIDE_SANDBOX.txt")

    entries = _entries(audit_log)
    assert len(entries) == 1
    assert entries[0]["outcome"] == "rejected"
    assert entries[0]["error"]
    assert "result_len" not in entries[0]


def test_every_line_is_valid_json(audit_log):
    """The file stays parseable as JSON Lines across mixed outcomes."""
    ping("one")
    with pytest.raises(ValueError):
        search_files("/etc/passwd")
    ping("two")

    lines = audit_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for line in lines:
        assert isinstance(json.loads(line), dict)


def test_entries_carry_timestamp_and_tool_name(audit_log):
    """Each entry identifies when it happened and which tool ran."""
    ping("hello")
    with pytest.raises(ValueError):
        search_files("../OUTSIDE_SANDBOX.txt")

    entries = _entries(audit_log)
    assert [e["tool"] for e in entries] == ["ping", "search_files"]
    for entry in entries:
        assert entry["timestamp"]
        assert entry["arguments"]


def test_newline_in_argument_cannot_forge_an_entry(audit_log):
    """JSON Lines is the log-injection defense: \\n is escaped, not literal."""
    ping("forged\nnot-a-real-entry")

    lines = audit_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["arguments"]["message"] == "forged\nnot-a-real-entry"
