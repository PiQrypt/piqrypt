# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Propagate version strings from pyproject.toml to documentation files.

Source of truth: <repo>/pyproject.toml → [project] version = "x.y.z"
This script READS that value and propagates it. It never decides the version.

Usage:
    python scripts/bump_version.py            # apply changes
    python scripts/bump_version.py --dry-run  # show diffs, write nothing
"""

import argparse
import re
import sys
from datetime import date
from pathlib import Path

# Force UTF-8 output on Windows (avoids cp1252 errors for ✓ etc.)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── tomllib with Python < 3.11 fallback ──────────────────────────────────────
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
    except ImportError:
        print(
            "Error: tomllib (stdlib ≥3.11) or tomli (pip install tomli) required.",
            file=sys.stderr,
        )
        sys.exit(1)

# ── Repo root — this script lives in scripts/, repo root is parent ────────────
REPO_ROOT = Path(__file__).parent.parent


def _read_version(toml_path: Path) -> str:
    with open(toml_path, "rb") as fh:
        data = tomllib.load(fh)
    return data["project"]["version"]


# ── File list ─────────────────────────────────────────────────────────────────
# Each entry: (relative_path, [(regex_pattern, replacement_template), ...])
# Templates: {V} → PIQRYPT_VERSION   {D} → TODAY (YYYY-MM-DD)
#
# EXCLUDED by design (never touched):
#   - pyproject.toml itself (source of truth)
#   - aiss/__init__.py, vigil/__init__.py, trustgate/*, bridges/* (functional code)
#   - aiss/schemas/*.json, test_vectors/*.json  (schemas & test vectors)
#   - docs/TRUST_SCORING_Technical_v2.1.md  (**Version:** = AISS spec version)
#   - docs/WHITEPAPER_v2.0.md               (**Version:** = whitepaper edition)
#   - docs/A2A_HANDSHAKE_GUIDE.md           (**Version:** = protocol revision)
FILES = [
    # ── docs/ — **Version:** + **Date:** headers ────────────────────────────
    (
        "docs/BADGES.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
            (r"\*\*Date:\*\* \d{4}-\d{2}-\d{2}", "**Date:** {D}"),
            # shields.io badge  …/badge/version-1.8.4-blue…
            (r"version-[\d.]+-blue", "version-{V}-blue"),
        ],
    ),
    (
        "docs/IMPLEMENTATION_STATUS.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
            (r"\*\*Date:\*\* \d{4}-\d{2}-\d{2}", "**Date:** {D}"),
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "docs/LICENSE-SYSTEM.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
        ],
    ),
    (
        "docs/LOGGING.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
        ],
    ),
    (
        "docs/LOGS-REFERENCE.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
        ],
    ),
    (
        "docs/OPENCLAW_INTEGRATION.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
            (r"\*\*Date:\*\* \d{4}-\d{2}-\d{2}", "**Date:** {D}"),
        ],
    ),
    (
        "docs/TELEMETRY.md",
        [
            (r"\*\*Version:\*\* [\d.]+", "**Version:** {V}"),
            (r"\*\*Date:\*\* \d{4}-\d{2}-\d{2}", "**Date:** {D}"),
        ],
    ),
    # ── docs/ — **Version :** PiQrypt vX.Y.Z (space before colon) ───────────
    (
        "docs/TSI_Trust_Stability_Index.md",
        [
            (r"\*\*Version :\*\* PiQrypt v[\d.]+", "**Version :** PiQrypt v{V}"),
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "docs/Vigil_Continuous_Monitoring.md",
        [
            (r"\*\*Version :\*\* PiQrypt v[\d.]+", "**Version :** PiQrypt v{V}"),
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    # ── docs/ — inline PiQrypt vX.Y.Z references ────────────────────────────
    (
        "docs/A2A_SESSION_GUIDE.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "docs/PCP_Protocol_Paper.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "docs/Real_World_Use_Cases.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "docs/RFC_AISS_v2.0.md",
        [
            # Matches "PiQrypt v1.7.1" only — leaves "v2.1" (HSM version) alone
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "docs/RFC_AISS_v2.0_narrative.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    # ── Root docs ─────────────────────────────────────────────────────────────
    (
        "QUICK-START.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "INTEGRATION.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "README.md",
        [
            # Project Status table: **v1.7.1** · Python 3.9–3.12 · …
            (r"\*\*v[\d.]+\*\* · Python", "**v{V}** · Python"),
        ],
    ),
    (
        "ANALYSE_DIFFERENCIANTS.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    (
        "COMMANDES_VALIDEES.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
    # ── agents/ ───────────────────────────────────────────────────────────────
    (
        "agents/AGENT_PROMPT.md",
        [
            (r"PiQrypt v[\d.]+", "PiQrypt v{V}"),
        ],
    ),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Propagate version from pyproject.toml to documentation."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show diffs without writing files.",
    )
    args = parser.parse_args()
    dry_run: bool = args.dry_run

    # ── Read versions ─────────────────────────────────────────────────────────
    pyproject = REPO_ROOT / "pyproject.toml"
    if not pyproject.exists():
        print(f"Error: {pyproject} not found.", file=sys.stderr)
        return 1

    V = _read_version(pyproject)

    # AISS spec version — optional sibling repo
    aiss_spec = REPO_ROOT.parent / "aiss-spec" / "pyproject.toml"
    A = _read_version(aiss_spec) if aiss_spec.exists() else None

    TODAY = date.today().isoformat()  # YYYY-MM-DD

    mode = "[DRY-RUN] " if dry_run else ""
    print(f"{mode}PIQRYPT_VERSION = {V}")
    if A:
        print(f"{mode}AISS_VERSION    = {A}")
    print(f"{mode}TODAY           = {TODAY}")
    print()

    exit_code = 0
    changed_count = 0
    no_change_count = 0

    for rel_path, patterns in FILES:
        path = REPO_ROOT / rel_path

        if not path.exists():
            print(f"  no change  {rel_path}")
            no_change_count += 1
            continue

        original = path.read_text(encoding="utf-8")
        updated = original

        for pattern, template in patterns:
            replacement = template.replace("{V}", V).replace("{D}", TODAY)
            updated = re.sub(pattern, replacement, updated)

        if updated == original:
            print(f"  no change  {rel_path}")
            no_change_count += 1
            continue

        # Compute changed lines for display
        orig_lines = original.splitlines()
        upd_lines = updated.splitlines()
        n = min(len(orig_lines), len(upd_lines))
        diffs = [
            (i + 1, orig_lines[i], upd_lines[i])
            for i in range(n)
            if orig_lines[i] != upd_lines[i]
        ]

        if dry_run:
            print(f"✓ WOULD FIX  {rel_path}  ({len(diffs)} line(s))")
            for lineno, before, after in diffs:
                print(f"    L{lineno:>4}  - {before.strip()}")
                print(f"    L{lineno:>4}  + {after.strip()}")
        else:
            path.write_text(updated, encoding="utf-8")
            print(f"✓ updated    {rel_path}  ({len(diffs)} line(s))")

        changed_count += 1

    print()
    action = "Would update" if dry_run else "Updated"
    print(
        f"{action} {changed_count} file(s), "
        f"{no_change_count} already up-to-date."
    )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
