"""H11: the fill guard must be atomic, top-level-only and origin-exact."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keygate_lib as kg


def test_guard_blocks_non_top_level_frame():
    js = kg.harden_fill_js("(() => { return JSON.stringify({filled: 1}); })()",
                           "https://accounts.google.com")
    assert "window.top !== window.self" in js
    assert "frame_not_top_level" in js


def test_guard_pins_exact_origin():
    js = kg.harden_fill_js("(() => {})()", "https://accounts.google.com")
    assert 'window.location.origin !== "https://accounts.google.com"' in js
    assert "origin_changed_toctou" in js


def test_guard_runs_before_the_write_and_preserves_inner_js():
    inner = "(() => { return JSON.stringify({filled: 2}); })()"
    js = kg.harden_fill_js(inner, "https://example.com")
    assert inner in js
    assert js.index("window.top") < js.index(inner)
    assert js.index("window.location.origin") < js.index(inner)
