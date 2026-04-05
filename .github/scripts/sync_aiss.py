#!/usr/bin/env python3
"""
sync_aiss.py — Synchronise les fichiers AISS core de piqrypt vers aiss-standard.

Usage:
    python sync_aiss.py --src <piqrypt_path> --dst <aiss_standard_path> \
                        --piqrypt-version <tag> [--dry-run true]

Ce script :
  - Copie la liste exacte des fichiers autorisés (allowlist)
  - Applique des transformations légères (licence, chemins, version dans metadata)
  - N'efface jamais de fichiers dans aiss-standard
  - Affiche un diff lisible avant tout changement
"""

import argparse
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# ALLOWLIST — seuls ces fichiers sont synchronisés depuis piqrypt vers aiss-standard
# Toute modification de périmètre passe par cette liste.
# ─────────────────────────────────────────────────────────────────────────────

AISS_CORE_FILES: List[Tuple[str, str]] = [
    # (source dans piqrypt,          destination dans aiss-standard)

    # ── Protocole AISS core ───────────────────────────────────────────────────
    ("aiss/identity.py",             "aiss/identity.py"),
    ("aiss/stamp.py",                "aiss/stamp.py"),
    ("aiss/stamp_aiss2.py",          "aiss/stamp_aiss2.py"),
    ("aiss/verify.py",               "aiss/verify.py"),
    ("aiss/chain.py",                "aiss/chain.py"),
    ("aiss/canonical.py",            "aiss/canonical.py"),
    ("aiss/fork.py",                 "aiss/fork.py"),
    ("aiss/replay.py",               "aiss/replay.py"),
    ("aiss/exceptions.py",           "aiss/exceptions.py"),
    ("aiss/authority.py",            "aiss/authority.py"),
    ("aiss/a2a.py",                  "aiss/a2a.py"),
    ("aiss/agent_context.py",        "aiss/agent_context.py"),
    ("aiss/history.py",              "aiss/history.py"),
    ("aiss/index.py",                "aiss/index.py"),
    ("aiss/logger.py",               "aiss/logger.py"),
    ("aiss/agent_registry.py",       "aiss/agent_registry.py"),
    ("aiss/bridge_protocol.py",      "aiss/bridge_protocol.py"),

    # ── Crypto ────────────────────────────────────────────────────────────────
    ("aiss/crypto/__init__.py",      "aiss/crypto/__init__.py"),
    ("aiss/crypto/ed25519.py",       "aiss/crypto/ed25519.py"),
    ("aiss/crypto/dilithium_liboqs.py", "aiss/crypto/dilithium_liboqs.py"),

    # ── Schemas JSON ──────────────────────────────────────────────────────────
    ("aiss/schemas/aiss-1.0.json",          "aiss/schemas/aiss-1.0.json"),
    ("aiss/schemas/aiss-2.0.json",          "aiss/schemas/aiss-2.0.json"),
    ("aiss/schemas/aiss1_event.schema.json","aiss/schemas/aiss1_event.schema.json"),
    ("aiss/schemas/aiss1_identity.schema.json","aiss/schemas/aiss1_identity.schema.json"),
    ("aiss/schemas/audit.schema.json",      "aiss/schemas/audit.schema.json"),

    # ── Vigil standard ────────────────────────────────────────────────────────
    ("vigil/vigil_server.py",        "vigil/vigil_server.py"),
    ("vigil/vigil_v4_final.html",    "vigil/vigil_v4_final.html"),

    # ── Vecteurs de test normatifs ────────────────────────────────────────────
    ("vectors/ed25519-test.json",    "vectors/ed25519-test.json"),
    ("vectors/dilithium-test.json",  "vectors/dilithium-test.json"),
]

# Fichiers gérés manuellement dans aiss-standard (jamais écrasés par le sync)
AISS_MANAGED_FILES = {
    "aiss/__init__.py",       # nettoyé manuellement — sans license/badges/telemetry
    "aiss/exports.py",        # nettoyé manuellement — sans export_certified
    "aiss/memory.py",         # nettoyé manuellement — sans Pro/encryption
    "vigil/__init__.py",      # marqueur "Powered by PiQrypt" + limites standard
    "pyproject.toml",         # package "aiss", MIT, indépendant
    "CHANGELOG.md",
    "README.md",
    "conftest.py",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
}

# Transformations appliquées sur le contenu de chaque fichier copié
TRANSFORMATIONS: List[Tuple[str, str]] = [
    # Licence — Elastic → MIT dans les headers
    (
        r"# SPDX-License-Identifier: Elastic-2\.0",
        "# SPDX-License-Identifier: MIT",
    ),
    (
        r"# Licensed under the Elastic License 2\.0 \(ELv2\)\..*?\n"
        r"# You may not provide this software as a hosted or managed service.*?\n"
        r"# to third parties without a commercial license\..*?\n"
        r"# Commercial license: contact@piqrypt\.com\n",
        "",
    ),
    # Chemins ~/.piqrypt → ~/.aiss dans les commentaires/strings
    (r"~/\.piqrypt", r"~/.aiss"),
    (r'Path\.home\(\) / "\.piqrypt"', r'Path.home() / ".aiss"'),
    # Metadonnée exporter
    (r'"exporter":\s*"piqrypt/[\d.]+"', '"exporter": "aiss/2.0.0"'),
    # Log prefix
    (r'\[PiQrypt\]', "[AISS]"),
]


# ─────────────────────────────────────────────────────────────────────────────

def apply_transformations(content: str, filename: str) -> str:
    """Apply text transformations to file content."""
    # Ne pas toucher aux fichiers JSON, HTML, binaires
    if any(filename.endswith(ext) for ext in [".json", ".html", ".enc", ".key"]):
        return content

    for pattern, replacement in TRANSFORMATIONS:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

    return content


def sync_file(
    src_path: Path,
    dst_path: Path,
    dry_run: bool,
    piqrypt_version: str,
) -> bool:
    """
    Sync a single file from piqrypt to aiss-standard.

    Returns True if the file was changed (or would be changed in dry_run).
    """
    if not src_path.exists():
        print(f"  ⚠️  SKIP (not found in piqrypt): {src_path}")
        return False

    # Read source
    try:
        content = src_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # Binary file — copy as-is
        if not dry_run:
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dst_path)
        print(f"  📦 BINARY: {dst_path}")
        return True

    # Apply transformations
    new_content = apply_transformations(content, src_path.name)

    # Add sync header comment (Python files only)
    if src_path.suffix == ".py" and not new_content.startswith("# sync:"):
        sync_comment = (
            f"# sync: generated from piqrypt@{piqrypt_version} — do not edit manually\n"
            f"# Source: https://github.com/piqrypt/piqrypt/blob/main/{src_path}\n"
            f"# To modify: edit in piqrypt, changes will be synced on next release\n"
        )
        # Insert after the SPDX line if present
        if new_content.startswith("# SPDX-"):
            lines = new_content.split("\n")
            # Find end of header block
            insert_at = 0
            for i, line in enumerate(lines):
                if line.startswith("#"):
                    insert_at = i + 1
                else:
                    break
            lines.insert(insert_at, sync_comment.rstrip())
            new_content = "\n".join(lines)
        else:
            new_content = sync_comment + new_content

    # Check if changed
    existing_content = ""
    if dst_path.exists():
        try:
            existing_content = dst_path.read_text(encoding="utf-8")
        except Exception:
            pass

    # Strip sync header for comparison (avoid false positives on version bump)
    def strip_sync_header(text: str) -> str:
        lines = text.split("\n")
        filtered = [l for l in lines if not l.startswith("# sync:") and not l.startswith("# Source:") and not l.startswith("# To modify:")]
        return "\n".join(filtered)

    if strip_sync_header(new_content) == strip_sync_header(existing_content):
        print(f"  ✓  unchanged: {dst_path}")
        return False

    # Show diff summary
    src_lines = len(existing_content.splitlines())
    dst_lines = len(new_content.splitlines())
    delta = dst_lines - src_lines
    sign  = "+" if delta >= 0 else ""
    print(f"  📝 {'DRY ' if dry_run else ''}UPDATE: {dst_path} ({sign}{delta} lines)")

    if not dry_run:
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        dst_path.write_text(new_content, encoding="utf-8")

    return True


def main():
    parser = argparse.ArgumentParser(description="Sync AISS core from piqrypt to aiss-standard")
    parser.add_argument("--src",              required=True, help="Path to piqrypt repo")
    parser.add_argument("--dst",              required=True, help="Path to aiss-standard repo")
    parser.add_argument("--piqrypt-version",  default="unknown", help="piqrypt release tag")
    parser.add_argument("--dry-run",          default="false", help="true = no write")
    args = parser.parse_args()

    src_root  = Path(args.src).resolve()
    dst_root  = Path(args.dst).resolve()
    dry_run   = args.dry_run.lower() == "true"
    version   = args.piqrypt_version

    print()
    print("=" * 60)
    print(f"  AISS sync — piqrypt {version} → aiss-standard")
    print(f"  Source : {src_root}")
    print(f"  Dest   : {dst_root}")
    print(f"  DryRun : {dry_run}")
    print("=" * 60)
    print()

    changed = 0
    skipped = 0
    managed = 0

    for src_rel, dst_rel in AISS_CORE_FILES:
        if dst_rel in AISS_MANAGED_FILES:
            print(f"  🔒 MANAGED (skip): {dst_rel}")
            managed += 1
            continue

        src_path = src_root / src_rel
        dst_path = dst_root / dst_rel

        was_changed = sync_file(src_path, dst_path, dry_run, version)
        if was_changed:
            changed += 1
        else:
            skipped += 1

    print()
    print("─" * 60)
    print(f"  Updated : {changed}")
    print(f"  Unchanged: {skipped}")
    print(f"  Managed (skipped): {managed}")
    if dry_run:
        print()
        print("  DRY RUN — no files written.")
    print()

    # Exit 0 even if nothing changed — not an error
    sys.exit(0)


if __name__ == "__main__":
    main()
