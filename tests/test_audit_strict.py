"""F2: audit() must be fail-closed when the caller asks for it.

The credential path passes strict=True: if the audit line cannot be persisted,
the fill is aborted by the caller (AuditError). Everything else stays
best-effort so a full disk never breaks read-only tools.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import keygate_lib as kg  # noqa: E402


def test_strict_write_appends_and_is_0600(tmp_path):
    home = tmp_path / ".hermes"
    kg.audit(home, {"ev": "fill", "decision": "intent"}, strict=True)
    fp = home / kg.AUDIT_NAME
    assert fp.exists()
    assert fp.read_text().strip()
    assert (fp.stat().st_mode & 0o777) == 0o600


def test_strict_raises_when_home_is_not_writable(tmp_path):
    blocked = tmp_path / "nope"
    blocked.write_text("soy un archivo, no un directorio")
    with pytest.raises(kg.AuditError):
        kg.audit(blocked, {"ev": "fill"}, strict=True)


def test_best_effort_never_raises(tmp_path):
    blocked = tmp_path / "nope"
    blocked.write_text("soy un archivo, no un directorio")
    kg.audit(blocked, {"ev": "status"})  # must not raise


def test_audit_error_points_at_the_cause(tmp_path):
    blocked = tmp_path / "nope"
    blocked.write_text("x")
    try:
        kg.audit(blocked, {"ev": "fill"}, strict=True)
    except kg.AuditError as exc:
        assert "audit write failed" in str(exc)
        assert exc.__cause__ is not None
    else:  # pragma: no cover
        pytest.fail("AuditError not raised")
