"""Verify that version strings in key files match pyproject.toml."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract(pattern: str, text: str) -> str:
    m = re.search(pattern, text, re.MULTILINE)
    assert m, f"Pattern {pattern!r} not found"
    return m.group(1)


def test_versions_in_sync():
    pyproject = _read(ROOT / "pyproject.toml")
    ref = _extract(r'^version\s*=\s*"([^"]+)"', pyproject)

    aiss_init = _read(ROOT / "aiss" / "__init__.py")
    aiss_ver = _extract(r'^__version__\s*=\s*"([^"]+)"', aiss_init)

    piqrypt_init = _read(ROOT / "piqrypt" / "__init__.py")
    piqrypt_ver = _extract(r'^__version__\s*=\s*"([^"]+)"', piqrypt_init)

    telemetry = _read(ROOT / "aiss" / "telemetry.py")
    telemetry_ver = _extract(r'^_VERSION\s*=\s*"([^"]+)"', telemetry)

    assert aiss_ver == ref, (
        f"aiss/__init__.py __version__ {aiss_ver!r} != pyproject.toml {ref!r}"
    )
    assert piqrypt_ver == ref, (
        f"piqrypt/__init__.py __version__ {piqrypt_ver!r} != pyproject.toml {ref!r}"
    )
    assert telemetry_ver == ref, (
        f"aiss/telemetry.py _VERSION {telemetry_ver!r} != pyproject.toml {ref!r}"
    )
