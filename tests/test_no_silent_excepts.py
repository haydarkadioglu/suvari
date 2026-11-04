"""S-08 regression gate: no ``except ...: pass`` anywhere in the package."""

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "suvari"


def _silent_handlers() -> list[str]:
    offenders = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.ExceptHandler)
                    and len(node.body) == 1
                    and isinstance(node.body[0], ast.Pass)):
                offenders.append(f"{path.relative_to(PACKAGE.parent)}:{node.lineno}")
    return offenders


def test_package_is_scanned():
    assert any(PACKAGE.rglob("*.py"))


def test_no_except_handler_is_only_pass():
    offenders = _silent_handlers()
    assert not offenders, (
        "silent exception handlers (log the failure instead):\n  " + "\n  ".join(offenders)
    )
