"""H15: alias-auto fills are rate limited per alias."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keygate_lib as kg


def test_sixth_fill_in_window_is_refused():
    kg._auto_hits.clear()
    for _ in range(kg.AUTO_FILL_MAX):
        assert kg.autofill_rate_ok("cuenta-1") is True
    assert kg.autofill_rate_ok("cuenta-1") is False


def test_limit_is_per_alias():
    kg._auto_hits.clear()
    for _ in range(kg.AUTO_FILL_MAX):
        kg.autofill_rate_ok("cuenta-2")
    assert kg.autofill_rate_ok("cuenta-2") is False
    assert kg.autofill_rate_ok("cuenta-3") is True
