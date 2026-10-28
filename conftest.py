"""Pytest bootstrap: ensure the repository root is importable.

When pytest is invoked from an arbitrary directory, the repo root may not be
on ``sys.path``, which makes ``import suvari`` fail. Inserting it here keeps
the ``suvari`` package importable regardless of the working directory.
"""

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
