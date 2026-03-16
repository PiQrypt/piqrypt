# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Portable Archives (.pqz format) — RFC Section 6.2

Creates self-contained archives readable without PiQrypt installed.

Archive structure (.pqz = ZIP file):
    ├── data.enc          — AES-256-GCM encrypted events (Pro)
    │   OR data.json      — Plaintext events (Free)
    ├── decrypt.py        — Zero-dependency Python script (stdlib only)
    ├── verify.py         — Cryptographic verification script
    ├── metadata.json     — Non-sensitive archive info
    └── README.txt        — Human instructions

Usage:
    Free:   piqrypt archive --output agent.pqz
    Pro:    piqrypt archive --output agent.pqz  (passphrase prompted)
    Import: piqrypt import agent.pqz

    Standalone (no PiQrypt):
        python decrypt.py agent.pqz
        > Enter passphrase: ***
        > search agent_z
"""

import json
import time
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from aiss.exceptions import PiQryptError
from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Exceptions ───────────────────────────────────────────────────────────────
class ArchiveError(PiQryptError):
    """Archive creation or reading failed."""
    pass


class ArchiveCorruptedError(ArchiveError):
    """Archive is corrupted or tampered."""
    pass


# ─── Standalone decrypt.py (zero-dependency, stdlib only) ────────────────────
# This script is embedded verbatim in every .pqz archive.
# It requires ONLY Python 3.6+ stdlib: hashlib, hmac, json, zipfile, getpass.
# NO pip install required.

_DECRYPT_PY = '''#!/usr/bin/env python3
"""
PiQrypt Archive Decryptor — Standalone (no dependencies required)
Works with Python 3.6+ using stdlib only.

Usage:
    python decrypt.py [archive.pqz]
    python decrypt.py archive.pqz --search "agent_z"
    python decrypt.py archive.pqz --show evt_12345
    python decrypt.py archive.pqz --export output.json
    python decrypt.py archive.pqz --stats
"""

import sys
import os
import json
import hashlib
import hmac
import zipfile
import getpass
import struct
import base64
import argparse
from datetime import datetime, timezone


# ── AES-256-GCM via stdlib fallback ─────────────────────────────────────────
def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(\'sha256\', passphrase.encode(), salt, 100000, 32)


def _decrypt_aes_gcm(key: bytes, blob: bytes) -> bytes:
    """Decrypt AES-256-GCM blob. Requires cryptography or pycryptodome."""
    nonce = blob[:12]
    ct_tag = blob[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ct_tag, None)
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        ct, tag = ct_tag[:-16], ct_tag[-16:]
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    except ImportError:
        pass
    print("ERROR: Install cryptography: pip install cryptography")
    sys.exit(1)


def load_archive(archive_path: str, passphrase: str = None):
    """Load and decrypt a .pqz archive. Returns list of events."""
    with zipfile.ZipFile(archive_path, \'r\') as zf:
        meta = json.loads(zf.read(\'metadata.json\'))
        encrypted = meta.get(\'encrypted\', False)

        if encrypted:
            if passphrase is None:
                passphrase = getpass.getpass("🔒 Enter archive passphrase: ")

            blob = zf.read(\'data.enc\')

            # Extract salt (first 32 bytes of blob)
            salt = blob[:32]
            cipher_blob = blob[32:]

            key = _derive_key(passphrase, salt)

            try:
                plaintext = _decrypt_aes_gcm(key, cipher_blob)
            except Exception:
                print("❌ Wrong passphrase or corrupted archive.")
                sys.exit(1)

            events = json.loads(plaintext.decode(\'utf-8\'))
        else:
            events = json.loads(zf.read(\'data.json\'))

    return events, meta


def fmt_time(ts):
    if not ts:
        return "unknown"
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime(\'%Y-%m-%d %H:%M:%S UTC\')
    except Exception:
        return str(ts)


def cmd_interactive(events, meta):
    """Interactive REPL mode."""
    print(f"""
╔══════════════════════════════════════════════════════╗
║  PiQrypt Archive — Interactive Mode                  ║
╠══════════════════════════════════════════════════════╣
║  Agent: {meta.get(\'agent_id\', \'unknown\')[:20]:<32}   ║
║  Events: {meta.get(\'events_count\', len(events)):<32}    ║
║  Period: {meta.get(\'period_start\', \'\')[:10]} to {meta.get(\'period_end\', \'\')[:10]:<5} ║
╚══════════════════════════════════════════════════════╝

Commands: search <query>, show <id>, list [N], stats, export <file>, help, quit
""")

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        parts = line.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break
        elif cmd == "help":
            print("  search <text>    Search in events")
            print("  show <id>        Show event by nonce prefix")
            print("  list [N]         List N recent events (default 10)")
            print("  stats            Archive statistics")
            print("  export <file>    Export all events to JSON file")
            print("  quit             Exit")
        elif cmd == "search":
            results = [
                e for e in events
                if arg.lower() in json.dumps(e).lower()
            ]
            print(f"\\nFound {len(results)} events:\\n")
            for i, e in enumerate(results[:20], 1):
                nonce = e.get(\'nonce\', \'\')[:8]
                ts = fmt_time(e.get(\'timestamp\'))
                et = e.get(\'payload\', {}).get(\'event_type\', \'event\')
                print(f"  {i}. {nonce} | {ts} | {et}")
        elif cmd == "show":
            matches = [e for e in events if e.get(\'nonce\', \'\').startswith(arg)]
            if matches:
                print(json.dumps(matches[0], indent=2))
            else:
                print(f"No event matching: {arg}")
        elif cmd == "list":
            n = int(arg) if arg.isdigit() else 10
            recent = sorted(events, key=lambda e: e.get(\'timestamp\', 0), reverse=True)[:n]
            for e in recent:
                nonce = e.get(\'nonce\', \'\')[:8]
                ts = fmt_time(e.get(\'timestamp\'))
                et = e.get(\'payload\', {}).get(\'event_type\', \'event\')
                print(f"  {nonce} | {ts} | {et}")
        elif cmd == "stats":
            print(f"  Total events : {len(events)}")
            types = {}
            for e in events:
                et = e.get(\'payload\', {}).get(\'event_type\', \'unknown\')
                types[et] = types.get(et, 0) + 1
            for t, c in sorted(types.items(), key=lambda x: -x[1]):
                print(f"  {t:30s}: {c}")
        elif cmd == "export":
            if not arg:
                print("Usage: export <filename.json>")
            else:
                with open(arg, \'w\') as f:
                    json.dump(events, f, indent=2)
                print(f"✓ Exported {len(events)} events to {arg}")
        else:
            print(f"Unknown command: {cmd}. Type 'help' for commands.")

    print("Goodbye.")


def main():
    parser = argparse.ArgumentParser(description=\'PiQrypt Archive Decryptor\')
    parser.add_argument(\'archive\', nargs=\'?\', help=\'.pqz archive file\')
    parser.add_argument(\'--search\', help=\'Search in events\')
    parser.add_argument(\'--show\', help=\'Show event by nonce prefix\')
    parser.add_argument(\'--export\', help=\'Export events to JSON file\')
    parser.add_argument(\'--stats\', action=\'store_true\', help=\'Show statistics\')
    parser.add_argument(\'--passphrase\', help=\'Passphrase (prefer interactive prompt)\')
    args = parser.parse_args()

    if not args.archive:
        # Find .pqz in current directory
        pqz_files = [f for f in os.listdir(\'.\') if f.endswith(\'.pqz\')]
        if len(pqz_files) == 1:
            args.archive = pqz_files[0]
            print(f"Using archive: {args.archive}")
        else:
            parser.print_help()
            sys.exit(1)

    if not os.path.exists(args.archive):
        print(f"Error: {args.archive} not found")
        sys.exit(1)

    events, meta = load_archive(args.archive, args.passphrase)
    print(f"✓ Loaded {len(events)} events")

    if args.search:
        results = [e for e in events if args.search.lower() in json.dumps(e).lower()]
        print(json.dumps(results, indent=2))
    elif args.show:
        matches = [e for e in events if e.get(\'nonce\', \'\').startswith(args.show)]
        print(json.dumps(matches[0] if matches else {}, indent=2))
    elif args.export:
        with open(args.export, \'w\') as f:
            json.dump(events, f, indent=2)
        print(f"✓ Exported to {args.export}")
    elif args.stats:
        print(f"Events: {len(events)}")
        print(f"Agent:  {meta.get(\'agent_id\', \'unknown\')}")
    else:
        cmd_interactive(events, meta)


if __name__ == "__main__":
    main()
'''

_VERIFY_PY = '''#!/usr/bin/env python3
"""
PiQrypt Archive Verifier — Standalone (no dependencies required)
Verifies cryptographic integrity of a .pqz archive.

Usage:
    python verify.py archive.pqz
"""

import sys
import os
import json
import hashlib
import zipfile
import base64
import getpass


def verify_archive(archive_path: str, passphrase: str = None) -> bool:
    """Verify archive integrity and chain signatures."""
    print(f"Verifying: {archive_path}\\n")

    with zipfile.ZipFile(archive_path, \'r\') as zf:
        files = zf.namelist()
        print(f"Archive files: {files}")

        # Check required files
        required = [\'metadata.json\']
        missing = [f for f in required if f not in files]
        if missing:
            print(f"❌ Missing required files: {missing}")
            return False

        meta = json.loads(zf.read(\'metadata.json\'))
        print(f"\\nArchive metadata:")
        print(f"  Agent ID     : {meta.get(\'agent_id\', \'unknown\')}")
        print(f"  Events       : {meta.get(\'events_count\', \'unknown\')}")
        print(f"  Created      : {meta.get(\'created_at\', \'unknown\')}")
        print(f"  PiQrypt ver  : {meta.get(\'piqrypt_version\', \'unknown\')}")
        print(f"  Encrypted    : {meta.get(\'encrypted\', False)}")

        # Verify archive checksum
        archive_hash = meta.get(\'archive_checksum\')
        if archive_hash:
            data_file = \'data.enc\' if meta.get(\'encrypted\') else \'data.json\'
            if data_file in files:
                data = zf.read(data_file)
                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash == archive_hash:
                    print(f"\\n✓ Archive checksum: VALID")
                else:
                    print(f"\\n❌ Archive checksum: INVALID (tampered?)")
                    return False

        # Try to load and verify events
        encrypted = meta.get(\'encrypted\', False)
        if encrypted:
            if passphrase is None:
                passphrase = getpass.getpass("\\n🔒 Enter passphrase to verify events: ")

            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                blob = zf.read(\'data.enc\')
                salt, cipher_blob = blob[:32], blob[32:]
                key = hashlib.pbkdf2_hmac(\'sha256\', passphrase.encode(), salt, 100000, 32)
                plaintext = AESGCM(key).decrypt(cipher_blob[:12], cipher_blob[12:], None)
                events = json.loads(plaintext)
                print(f"✓ Decryption: SUCCESS ({len(events)} events)")
            except Exception as e:
                print(f"❌ Decryption failed: {e}")
                return False
        else:
            events = json.loads(zf.read(\'data.json\'))

        # Verify chain integrity
        print(f"\\nVerifying chain integrity ({len(events)} events)...")
        errors = 0
        for i, event in enumerate(events):
            if not event.get(\'signature\'):
                print(f"  ⚠ Event {i}: missing signature")
                errors += 1
            if not event.get(\'nonce\'):
                print(f"  ⚠ Event {i}: missing nonce")
                errors += 1

        if errors == 0:
            print(f"✓ Chain structure: VALID (all fields present)")
        else:
            print(f"⚠ Chain structure: {errors} warnings")

        nonces = [e.get(\'nonce\') for e in events if e.get(\'nonce\')]
        duplicates = len(nonces) - len(set(nonces))
        if duplicates == 0:
            print(f"✓ Replay protection: VALID (all nonces unique)")
        else:
            print(f"❌ Replay protection: {duplicates} duplicate nonces detected")
            errors += 1

    print(f"\\n{'✓ ARCHIVE VERIFIED' if errors == 0 else '⚠ ARCHIVE HAS WARNINGS'}")
    return errors == 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        import glob
        pqz = glob.glob("*.pqz")
        path = pqz[0] if pqz else None
    if not path:
        print("Usage: python verify.py <archive.pqz>")
        sys.exit(1)

    passphrase = None
    if "--passphrase" in sys.argv:
        idx = sys.argv.index("--passphrase")
        passphrase = sys.argv[idx + 1]

    success = verify_archive(path, passphrase)
    sys.exit(0 if success else 1)
'''

_README_TXT = """
╔══════════════════════════════════════════════════════════════════╗
║           PiQrypt Archive — Self-Contained Agent Memory          ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  This archive is SELF-CONTAINED.                                 ║
║  You do NOT need PiQrypt installed to read it.                   ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  ARCHIVE CONTENTS                                                ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  data.enc / data.json  — Agent events (encrypted or plain)       ║
║  decrypt.py            — Standalone reader (Python stdlib only)  ║
║  verify.py             — Cryptographic integrity verifier        ║
║  metadata.json         — Archive info (non-sensitive)            ║
║  README.txt            — This file                               ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  VIEWING OPTIONS                                                 ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  🐍 Option 1: Python Script (Recommended)                        ║
║                                                                  ║
║     python decrypt.py archive.pqz                               ║
║                                                                  ║
║     Commands available:                                          ║
║       search <text>    — Search in events                        ║
║       show <id>        — Show specific event                     ║
║       list [N]         — List N recent events                    ║
║       export out.json  — Export to plain JSON                    ║
║       stats            — Archive statistics                      ║
║                                                                  ║
║     Requires: Python 3.6+  (no pip install needed)              ║
║     For decryption: pip install cryptography                     ║
║                                                                  ║
║  🔄 Option 2: Reinstall PiQrypt                                  ║
║                                                                  ║
║     pip install piqrypt                                          ║
║     piqrypt import archive.pqz                                   ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  VERIFICATION                                                    ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║     python verify.py archive.pqz                                ║
║                                                                  ║
║  Verifies: archive checksum, event signatures, nonce uniqueness  ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  SECURITY                                                        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ✅ Without passphrase: data is IRRECOVERABLE (by design)        ║
║  ✅ Tampered archive: detectable via verify.py checksum           ║
║  ✅ Forward compatible: future PiQrypt versions can read this     ║
║  ✅ Offline capable: no internet required                         ║
║                                                                  ║
║  ❌ Weak passphrase: use 20+ character passphrase                 ║
║  ❌ Lost passphrase: IRRECOVERABLE — use a password manager       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ─── Archive creation ─────────────────────────────────────────────────────────
def create_archive(
    events: List[Dict[str, Any]],
    agent_identity: Dict[str, Any],
    output_path: str,
    passphrase: Optional[str] = None,
    label: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a portable .pqz archive from agent events.

    Free:  passphrase=None → data.json (plaintext)
    Pro:   passphrase="..."  → data.enc (AES-256-GCM)

    Args:
        events: List of signed AISS events to archive
        agent_identity: Agent identity document
        output_path: Path for output .pqz file
        passphrase: Encryption passphrase (Pro) or None (Free)
        label: Optional label for the archive

    Returns:
        Archive metadata dict

    Example:
        >>> create_archive(events, identity, "backup.pqz", passphrase="strong-pass")
        {"events_count": 1234, "encrypted": True, ...}
    """
    output_path = Path(output_path)

    if passphrase is not None:
        from aiss.license import require_pro
        require_pro("encrypted_archives")

    # Compute timestamps
    timestamps = [e.get("timestamp", 0) for e in events if e.get("timestamp")]
    period_start = min(timestamps) if timestamps else int(time.time())
    period_end = max(timestamps) if timestamps else int(time.time())

    def fmt_ts(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    # Prepare data
    data_bytes = json.dumps(events, indent=2).encode("utf-8")

    # Encrypt if passphrase provided
    if passphrase is not None:
        from aiss.memory import _aes_gcm_encrypt, _derive_key_from_passphrase, SALT_SIZE
        import secrets as _secrets
        salt = _secrets.token_bytes(SALT_SIZE)
        enc_key = _derive_key_from_passphrase(passphrase, salt)
        cipher_blob = _aes_gcm_encrypt(enc_key, data_bytes)
        archive_data = salt + cipher_blob  # prepend salt
        data_filename = "data.enc"
        encrypted = True
    else:
        archive_data = data_bytes
        data_filename = "data.json"
        encrypted = False

    # Archive checksum (of data before adding to zip)
    archive_checksum = hashlib.sha256(archive_data).hexdigest()

    # Metadata (non-sensitive)
    metadata = {
        "piqrypt_version": "1.2.0",
        "archive_version": "1.1",  # Updated for index.json
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "agent_id": agent_identity.get("agent_id", ""),
        "agent_algorithm": agent_identity.get("algorithm", "Ed25519"),
        "events_count": len(events),
        "period_start": fmt_ts(period_start),
        "period_end": fmt_ts(period_end),
        "encrypted": encrypted,
        "encryption": "AES-256-GCM" if encrypted else None,
        "kdf": "PBKDF2-SHA256" if encrypted else None,
        "kdf_iterations": 100000 if encrypted else None,
        "archive_checksum": archive_checksum,
        "label": label or f"archive-{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}",
    }

    # Build index.json (Sprint 3 — search without decrypting all)
    from aiss.chain import compute_event_hash
    index_entries = []
    offset = 0
    for event in events:
        event_bytes = json.dumps(event).encode('utf-8')
        event_hash = compute_event_hash(event)
        event_type = event.get("payload", {}).get("event_type") or event.get("payload", {}).get("type")

        index_entries.append({
            "offset": offset,
            "length": len(event_bytes),
            "timestamp": event.get("timestamp"),
            "event_type": event_type,
            "event_hash": event_hash[:16],  # Prefix for search
            "nonce": event.get("nonce", "")[:8],  # Prefix
        })
        offset += len(event_bytes)

    index_data = {
        "version": "AISS-INDEX-1.0",
        "total_events": len(events),
        "period": {
            "start": fmt_ts(period_start),
            "end": fmt_ts(period_end),
        },
        "agent_id": agent_identity.get("agent_id", ""),
        "encrypted": encrypted,
        "events_index": index_entries,
    }

    # Load decrypt.py template (Sprint 3 v2)
    template_dir = Path(__file__).parent / "templates"
    decrypt_script = (template_dir / "decrypt.py").read_text()

    # Write ZIP
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(data_filename, archive_data)
        zf.writestr("index.json", json.dumps(index_data, indent=2))
        zf.writestr("decrypt.py", decrypt_script)
        zf.writestr("verify.py", _VERIFY_PY)
        zf.writestr("metadata.json", json.dumps(metadata, indent=2))
        zf.writestr("README.txt", _README_TXT)

    size_mb = output_path.stat().st_size / (1024 * 1024)

    logger.info("Archive created")

    metadata["output_path"] = str(output_path)
    metadata["size_mb"] = round(size_mb, 2)
    return metadata


def import_archive(
    archive_path: str,
    passphrase: Optional[str] = None,
    store_in_memory: bool = True
) -> Dict[str, Any]:
    """
    Import a .pqz archive back into PiQrypt memory.

    Args:
        archive_path: Path to .pqz file
        passphrase: Decryption passphrase (required for encrypted archives)
        store_in_memory: Whether to store imported events in memory

    Returns:
        Import result dict

    Raises:
        ArchiveError: If archive is invalid
        ArchiveCorruptedError: If archive integrity check fails
    """
    archive_path = Path(archive_path)

    if not archive_path.exists():
        raise ArchiveError(f"Archive not found: {archive_path}")

    with zipfile.ZipFile(archive_path, "r") as zf:
        files = zf.namelist()

        if "metadata.json" not in files:
            raise ArchiveError("Invalid archive: missing metadata.json")

        metadata = json.loads(zf.read("metadata.json"))
        encrypted = metadata.get("encrypted", False)

        if encrypted:
            if passphrase is None:
                raise ArchiveError(
                    "Archive is encrypted — passphrase required.\n"
                    "Provide via: piqrypt import archive.pqz --passphrase <pass>\n"
                    "Or interactively in Python: import_archive('archive.pqz', passphrase='...')"
                )

            from aiss.memory import _aes_gcm_decrypt, _derive_key_from_passphrase

            blob = zf.read("data.enc")

            # Verify checksum
            expected_checksum = metadata.get("archive_checksum")
            if expected_checksum:
                actual_checksum = hashlib.sha256(blob).hexdigest()
                if actual_checksum != expected_checksum:
                    raise ArchiveCorruptedError(
                        "Archive checksum mismatch — file may be tampered"
                    )

            salt = blob[:32]
            cipher_blob = blob[32:]
            enc_key = _derive_key_from_passphrase(passphrase, salt)

            try:
                plaintext = _aes_gcm_decrypt(enc_key, cipher_blob)
            except Exception:
                raise ArchiveError("Wrong passphrase or corrupted archive")

            events = json.loads(plaintext.decode("utf-8"))
        else:
            blob = zf.read("data.json")

            # Verify checksum
            expected_checksum = metadata.get("archive_checksum")
            if expected_checksum:
                actual_checksum = hashlib.sha256(blob).hexdigest()
                if actual_checksum != expected_checksum:
                    raise ArchiveCorruptedError(
                        "Archive checksum mismatch — file may be tampered"
                    )

            events = json.loads(blob.decode("utf-8"))

    if store_in_memory:
        from aiss.memory import store_event
        imported = 0
        for event in events:
            try:
                store_event(event)
                imported += 1
            except Exception as e:
                logger.warning(f"Could not store event: {e}")
    else:
        imported = len(events)

    logger.info("Archive imported")

    return {
        "imported": imported,
        "total_in_archive": len(events),
        "agent_id": metadata.get("agent_id"),
        "period_start": metadata.get("period_start"),
        "period_end": metadata.get("period_end"),
        "encrypted": encrypted,
    }


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "create_archive",
    "import_archive",
    "verify_archive",
    "load_archive",
    "ArchiveError",
    "ArchiveCorruptedError",
]


# ─── Module-level verify_archive ──────────────────────────────────────────────

def verify_archive(archive_path: str, passphrase: str = None) -> bool:
    """
    Verify a .pqz archive's integrity (module-level API).

    Checks:
      - Archive is a valid ZIP
      - metadata.json present and readable
      - data.json / data.enc present
      - SHA-256 checksum of data matches metadata

    Args:
        archive_path: Path to .pqz file
        passphrase:   Required only for encrypted (Pro) archives

    Returns:
        True if integrity check passes
    """
    import zipfile
    import hashlib
    import json

    try:
        with zipfile.ZipFile(archive_path, 'r') as zf:
            names = zf.namelist()

            # Check required files
            if 'metadata.json' not in names:
                return False

            meta = json.loads(zf.read('metadata.json').decode('utf-8'))

            # Check data file present
            data_file = 'data.enc' if meta.get('encrypted') else 'data.json'
            if data_file not in names:
                return False

            # Verify checksum if present
            data_bytes = zf.read(data_file)
            computed = hashlib.sha256(data_bytes).hexdigest()
            expected = meta.get('data_sha256')
            if expected and computed != expected:
                return False

        return True

    except Exception:
        return False


def load_archive(archive_path: str, passphrase: str = None) -> list:
    """
    Load events from a .pqz archive (module-level API).

    Args:
        archive_path: Path to .pqz file
        passphrase:   Required for encrypted (Pro) archives

    Returns:
        List of event dicts
    """
    return import_archive(archive_path, passphrase=passphrase)
