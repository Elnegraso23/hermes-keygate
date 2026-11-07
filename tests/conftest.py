"""pytest bootstrap.

Layout gotcha: the repo root holds the plugin's `__init__.py`, which imports
the Hermes runtime (`agent.secret_sources`). With pytest run from the repo
root, that `__init__.py` looks like the package of `tests/` and collection
fails with `ModuleNotFoundError: No module named 'agent'` (29 errors, and CI
never noticed because it only ran unittest on test_autofill*).

Running pytest **from inside this directory** makes `tests/` the rootdir and
avoids importing the plugin package at all:

    cd tests && python -m pytest . -q     # 29 passed
    scripts/keygate-test                  # same thing, wrapper

This conftest keeps the repo root importable so the modules can `import
keygate_lib` without installing anything.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
