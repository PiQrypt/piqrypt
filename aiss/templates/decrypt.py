#!/usr/bin/env python3
"""
PiQrypt Archive Decryptor v2 — Standalone (Python 3.6+ stdlib only)

Supports:
  - Fast search via index.json (no decryption needed)
  - Interactive shell
  - Selective decryption (only decrypt matching events)
  - Export to JSON

Usage:
    python decrypt.py archive.pqz
    python decrypt.py archive.pqz --search trade
    python decrypt.py archive.pqz --show a3f7e8c9
    python decrypt.py archive.pqz --export output.json --type trade_executed
    python decrypt.py archive.pqz --stats
"""

import sys
import json
import hashlib
import zipfile
import getpass
import argparse
from datetime import datetime

# ── AES-256-GCM (requires cryptography or pycryptodome) ──────────────────────
def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, 32)

def _decrypt_aes_gcm(key: bytes, blob: bytes) -> bytes:
    """Decrypt AES-256-GCM. Falls back to pycryptodome if cryptography unavailable."""
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
        print("ERROR: Encrypted archive requires: pip install cryptography")
        sys.exit(1)

# ── Archive Loader ───────────────────────────────────────────────────────────
class ArchiveReader:
    def __init__(self, archive_path: str):
        self.archive_path = archive_path
        self.zf = zipfile.ZipFile(archive_path, 'r')
        self.metadata = json.loads(self.zf.read('metadata.json'))
        self.index = json.loads(self.zf.read('index.json'))
        self.encrypted = self.metadata.get('encrypted', False)
        self.passphrase = None
        self.key = None
        self._events_cache = None

    def unlock(self, passphrase: str = None):
        """Unlock encrypted archive."""
        if not self.encrypted:
            return

        if passphrase is None:
            passphrase = getpass.getpass("🔒 Enter passphrase: ")

        blob = self.zf.read('data.enc')
        salt = blob[:32]
        self.key = _derive_key(passphrase, salt)
        self.passphrase = passphrase

    def load_all_events(self):
        """Load and decrypt all events (cached)."""
        if self._events_cache is not None:
            return self._events_cache

        if self.encrypted:
            if self.key is None:
                self.unlock()
            blob = self.zf.read('data.enc')
            cipher_blob = blob[32:]
            plaintext = _decrypt_aes_gcm(self.key, cipher_blob)
            events = json.loads(plaintext.decode('utf-8'))
        else:
            events = json.loads(self.zf.read('data.json'))

        self._events_cache = events
        return events

    def search_index(self, query: str = None, event_type: str = None, limit: int = 100):
        """Search index without decrypting. Returns index entries."""
        results = []
        for entry in self.index['events_index']:
            if event_type and entry.get('event_type') != event_type:
                continue
            if query:
                q = query.lower()
                if (q not in entry.get('event_hash', '').lower() and
                    q not in entry.get('event_type', '').lower() and
                    q not in str(entry.get('timestamp', '')).lower()):
                    continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    def get_event_by_hash(self, hash_prefix: str):
        """Get full event by hash prefix."""
        events = self.load_all_events()
        for e in events:
            from hashlib import sha256
            h = sha256(json.dumps({k: v for k, v in e.items() if k != 'signature'}, sort_keys=True).encode()).hexdigest()
            if h.startswith(hash_prefix):
                return e
        return None

    def close(self):
        self.zf.close()

# ── CLI ──────────────────────────────────────────────────────────────────────
def cmd_stats(archive: ArchiveReader):
    """Show archive statistics."""
    meta = archive.metadata
    idx = archive.index

    print("\nPiQrypt Archive Statistics")
    print("─" * 50)
    print(f"  Events      : {idx['total_events']}")
    print(f"  Period      : {idx['period']['start'][:10]} → {idx['period']['end'][:10]}")
    print(f"  Agent       : {idx['agent_id'][:16]}...")
    print(f"  Encrypted   : {'Yes (AES-256-GCM)' if meta['encrypted'] else 'No'}")

    # Event types
    types = {}
    for e in idx['events_index']:
        t = e.get('event_type', 'unknown')
        types[t] = types.get(t, 0) + 1

    if types:
        print("\n  Event Types :")
        for t, count in sorted(types.items(), key=lambda x: -x[1])[:10]:
            print(f"    {t:30s} {count:5d}")

def cmd_search(archive: ArchiveReader, query: str, event_type: str = None):
    """Search events by query."""
    results = archive.search_index(query=query, event_type=event_type, limit=50)

    if not results:
        print(f"No events matching '{query}'")
        return

    print(f"\nFound {len(results)} events matching '{query}':")
    print("─" * 80)
    for i, entry in enumerate(results, 1):
        ts = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M')
        et = entry.get('event_type', 'unknown')[:30]
        h = entry['event_hash']
        print(f"  [{i:3d}] {ts} — {et:30s} ({h}...)")

def cmd_show(archive: ArchiveReader, hash_prefix: str):
    """Show full event by hash."""
    event = archive.get_event_by_hash(hash_prefix)
    if not event:
        print(f"Event {hash_prefix}... not found")
        return

    print(f"\nEvent {hash_prefix}:")
    print("─" * 80)
    print(json.dumps(event, indent=2))

def cmd_export(archive: ArchiveReader, output: str, event_type: str = None, query: str = None):
    """Export matching events to JSON."""
    if event_type or query:
        # Filtered export
        index_results = archive.search_index(query=query, event_type=event_type, limit=10000)
        events = archive.load_all_events()

        # Match by hash
        hashes = {e['event_hash'] for e in index_results}

        filtered = []
        for e in events:
            from hashlib import sha256
            h = sha256(json.dumps({k: v for k, v in e.items() if k != 'signature'}, sort_keys=True).encode()).hexdigest()[:16]
            if h in hashes:
                filtered.append(e)

        export_data = filtered
    else:
        # Full export
        export_data = archive.load_all_events()

    with open(output, 'w') as f:
        json.dump(export_data, f, indent=2)

    print(f"✓ Exported {len(export_data)} events to {output}")

def cmd_interactive(archive: ArchiveReader):
    """Interactive shell."""
    print(f"\nPiQrypt Archive — {archive.index['total_events']} events")
    print(f"Period: {archive.index['period']['start'][:10]} → {archive.index['period']['end'][:10]}")
    print(f"Agent: {archive.index['agent_id'][:16]}...")
    print("\nCommands:")
    print("  search <query>     — search by event_type, date, hash")
    print("  show <hash>        — display full event")
    print("  export <file>      — export all events to JSON")
    print("  stats              — show statistics")
    print("  quit               — exit")
    print()

    while True:
        try:
            cmd = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            break

        if not cmd:
            continue

        parts = cmd.split(None, 1)
        action = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None

        if action == 'quit' or action == 'exit':
            break
        elif action == 'stats':
            cmd_stats(archive)
        elif action == 'search':
            if arg:
                cmd_search(archive, arg)
            else:
                print("Usage: search <query>")
        elif action == 'show':
            if arg:
                cmd_show(archive, arg)
            else:
                print("Usage: show <hash_prefix>")
        elif action == 'export':
            if arg:
                cmd_export(archive, arg)
            else:
                print("Usage: export <output.json>")
        else:
            print(f"Unknown command: {action}")

def main():
    parser = argparse.ArgumentParser(description='PiQrypt Archive Decryptor')
    parser.add_argument('archive', help='Path to .pqz archive')
    parser.add_argument('--search', help='Search query')
    parser.add_argument('--show', help='Show event by hash prefix')
    parser.add_argument('--export', help='Export to JSON file')
    parser.add_argument('--type', help='Filter by event_type')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--passphrase', help='Passphrase (prompted if not provided)')

    args = parser.parse_args()

    archive = ArchiveReader(args.archive)

    try:
        if archive.encrypted and args.passphrase:
            archive.unlock(args.passphrase)

        if args.stats:
            cmd_stats(archive)
        elif args.search:
            cmd_search(archive, args.search, event_type=args.type)
        elif args.show:
            cmd_show(archive, args.show)
        elif args.export:
            cmd_export(archive, args.export, event_type=args.type)
        else:
            cmd_interactive(archive)
    finally:
        archive.close()

if __name__ == '__main__':
    main()
