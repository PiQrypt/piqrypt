# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
"""Verify that every name imported from aiss.license in cli/*.py exists in the module."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_DIR = REPO_ROOT / "cli"


def _get_imports_from_file(path: Path):
    """Return list of (module, names) for all 'from X import ...' in path."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod == "aiss.license" or mod.startswith("aiss.license."):
                names = [alias.name for alias in node.names]
                results.append((mod, names, path.name))
    return results


def test_cli_license_imports_exist():
    """Every name imported from aiss.license in cli/*.py must exist in aiss.license."""
    import aiss.license as _lic

    missing = []
    for cli_file in sorted(CLI_DIR.glob("*.py")):
        for mod, names, filename in _get_imports_from_file(cli_file):
            for name in names:
                if not hasattr(_lic, name):
                    missing.append(
                        f"{filename}: from {mod} import {name!r}"
                        " -- not found in aiss.license"
                    )

    assert not missing, "Missing aiss.license exports:\n" + "\n".join(missing)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
