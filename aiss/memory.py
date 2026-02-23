"""
Agent Memory System (PCP Layer 2)

Implements cryptographically-backed agent memory:
- FREE: plaintext JSON storage in ~/.piqrypt/events/
- PRO:  AES-256-GCM encrypted storage + PBKDF2 passphrase unlock

RFC Sections 6 (Mémoire d'Agent), 11.2 (AISS-2 nonce retention)

Architecture:
    ~/.piqrypt/
    ├── events/
    │   ├── plain/          # FREE: monthly JSON files
    │   │   ├── 2025-01.json
    │   │   └── 2025-02.json
    │   └── encrypted/      # PRO: AES-256-GCM monthly files
    │       ├── 2025-01.enc
    │       └── 2025-02.enc
    ├── keys/
    │   └── master.key.enc  # PRO: master key encrypted with passphrase
    └── config.json
"""

import json
import time
import hashlib
import secrets
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from aiss.exceptions import PiQryptError
from aiss.logger import (
    get_logger,
    log_memory_unlocked, log_memory_locked,
    log_replay_detection_limited,
)

logger = get_logger(__name__)

# Import index (Sprint 3)
try:
    from aiss.index import get_index
    INDEX_AVAILABLE = True
except ImportError:
    INDEX_AVAILABLE = False
    get_index = None

# ─── Constants ────────────────────────────────────────────────────────────────
PIQRYPT_DIR = Path.home() / ".piqrypt"
EVENTS_PLAIN_DIR = PIQRYPT_DIR / "events" / "plain"
EVENTS_ENC_DIR = PIQRYPT_DIR / "events" / "encrypted"
KEYS_DIR = PIQRYPT_DIR / "keys"
MASTER_KEY_FILE = KEYS_DIR / "master.key.enc"
CONFIG_FILE = PIQRYPT_DIR / "config.json"

AES_KEY_SIZE = 32       # 256 bits
AES_NONCE_SIZE = 12     # 96 bits (GCM standard)
AES_TAG_SIZE = 16       # 128 bits GCM tag
PBKDF2_ITERATIONS = 100_000
PBKDF2_HASH = "sha256"
SALT_SIZE = 32


# ─── Exceptions ───────────────────────────────────────────────────────────────
class MemoryLockedError(PiQryptError):
    """Memory is locked — passphrase required."""
    pass


class MemoryCorruptedError(PiQryptError):
    """Memory file is corrupted or tampered."""
    pass


class PassphraseError(PiQryptError):
    """Invalid passphrase."""
    pass


# ─── AES-256-GCM via stdlib (no external deps) ────────────────────────────────
def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-GCM encryption using Python stdlib cryptography.
    
    Returns: nonce (12B) + ciphertext + tag (16B)
    
    Note: Uses cryptography package if available, falls back to
    PyCryptodome, or raises ImportError with clear message.
    """
    nonce = secrets.token_bytes(AES_NONCE_SIZE)

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct_with_tag
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ct + tag
    except ImportError:
        pass

    raise ImportError(
        "Pro memory encryption requires: pip install cryptography\n"
        "  or: pip install pycryptodome"
    )


def _aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    """
    AES-256-GCM decryption.
    
    Input: nonce (12B) + ciphertext + tag (16B)
    """
    if len(blob) < AES_NONCE_SIZE + AES_TAG_SIZE:
        raise MemoryCorruptedError("Encrypted blob too short")

    nonce = blob[:AES_NONCE_SIZE]
    ct_with_tag = blob[AES_NONCE_SIZE:]

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct_with_tag, None)
        except Exception:
            raise PassphraseError("Decryption failed — wrong passphrase or corrupted data")
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        ct = ct_with_tag[:-AES_TAG_SIZE]
        tag = ct_with_tag[-AES_TAG_SIZE:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ct, tag)
            return plaintext
        except Exception:
            raise PassphraseError("Decryption failed — wrong passphrase or corrupted data")
    except ImportError:
        pass

    raise ImportError("Pro memory requires: pip install cryptography")


def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation — 100k iterations."""
    return hashlib.pbkdf2_hmac(
        PBKDF2_HASH,
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=AES_KEY_SIZE
    )


# ─── Directory initialization ─────────────────────────────────────────────────
def init_memory_dirs() -> None:
    """Create ~/.piqrypt directory structure."""
    for d in [PIQRYPT_DIR, EVENTS_PLAIN_DIR, EVENTS_ENC_DIR, KEYS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    if not CONFIG_FILE.exists():
        config = {
            "version": "1.1.0",
            "retention_years": 10,
            "auto_backup": False,
            "backup_interval_months": 6,
            "created_at": int(time.time())
        }
        CONFIG_FILE.write_text(json.dumps(config, indent=2))

    logger.info(f"[PiQrypt] Memory directories initialized at {PIQRYPT_DIR}")


def get_config() -> Dict[str, Any]:
    """Load ~/.piqrypt/config.json."""
    if not CONFIG_FILE.exists():
        init_memory_dirs()
    return json.loads(CONFIG_FILE.read_text())


# ─── Master key management (PRO) ─────────────────────────────────────────────
def _setup_master_key(passphrase: str) -> bytes:
    """
    Generate and store a new master key encrypted with passphrase.
    Called once on first Pro unlock.
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    master_key = secrets.token_bytes(AES_KEY_SIZE)
    salt = secrets.token_bytes(SALT_SIZE)
    passphrase_key = _derive_key_from_passphrase(passphrase, salt)

    encrypted_master = _aes_gcm_encrypt(passphrase_key, master_key)

    # Format: salt (32B) + encrypted_master
    blob = salt + encrypted_master
    MASTER_KEY_FILE.write_bytes(blob)
    MASTER_KEY_FILE.chmod(0o600)

    logger.info("Master key created and encrypted")
    return master_key


def _load_master_key(passphrase: str) -> bytes:
    """Decrypt and return the master key using passphrase."""
    if not MASTER_KEY_FILE.exists():
        return _setup_master_key(passphrase)

    blob = MASTER_KEY_FILE.read_bytes()
    if len(blob) < SALT_SIZE:
        raise MemoryCorruptedError("Master key file corrupted")

    salt = blob[:SALT_SIZE]
    encrypted_master = blob[SALT_SIZE:]

    passphrase_key = _derive_key_from_passphrase(passphrase, salt)

    try:
        master_key = _aes_gcm_decrypt(passphrase_key, encrypted_master)
    except PassphraseError:
        raise PassphraseError("Wrong passphrase — cannot unlock memory")

    return master_key


# ─── Session management ───────────────────────────────────────────────────────
_session: Dict[str, Any] = {
    "master_key": None,
    "unlocked_at": None,
    "timeout_seconds": 3600,  # 1 hour
    "permanent": False,
}


def unlock(passphrase: str, permanent: bool = False) -> None:
    """
    Unlock Pro memory with passphrase.
    
    Args:
        passphrase: User passphrase
        permanent: If True, stays unlocked until lock() called
    
    Example:
        >>> unlock("my-strong-passphrase")
        >>> # Pro memory now accessible for 1 hour
    """
    from aiss.license import is_pro

    if not is_pro():
        logger.warning("[PiQrypt] Encrypted memory requires Pro license")
        raise PiQryptError("Memory encryption requires PiQrypt Pro")

    master_key = _load_master_key(passphrase)
    _session["master_key"] = master_key
    _session["unlocked_at"] = time.time()
    _session["permanent"] = permanent

    mode = "permanent" if permanent else "1 hour"
    log_memory_unlocked()


def lock() -> None:
    """Lock Pro memory — clear master key from session."""
    _session["master_key"] = None
    _session["unlocked_at"] = None
    _session["permanent"] = False
    log_memory_locked()


def is_unlocked() -> bool:
    """Check if Pro memory session is currently active."""
    if _session["master_key"] is None:
        return False
    if _session["permanent"]:
        return True
    if _session["unlocked_at"] is None:
        return False
    elapsed = time.time() - _session["unlocked_at"]
    if elapsed > _session["timeout_seconds"]:
        lock()
        return False
    return True


def _require_unlocked() -> bytes:
    """Return master key or raise MemoryLockedError."""
    if not is_unlocked():
        raise MemoryLockedError(
            "Pro memory is locked.\n"
            "Run: piqrypt unlock --session\n"
            "Or in Python: from aiss.memory import unlock; unlock('passphrase')"
        )
    return _session["master_key"]


# ─── Monthly file helpers ─────────────────────────────────────────────────────
def _month_key(timestamp: int) -> str:
    """Return 'YYYY-MM' for a Unix timestamp."""
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m")


def _current_month() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m")


# ─── FREE: plaintext event storage ───────────────────────────────────────────
def store_event_free(event: Dict[str, Any]) -> None:
    """
    Store a signed event in plaintext monthly JSON file.
    FREE tier — no encryption.
    
    Args:
        event: Signed AISS-1.0 event dict
    """
    init_memory_dirs()

    month = _month_key(event.get("timestamp", int(time.time())))
    filepath = EVENTS_PLAIN_DIR / f"{month}.json"

    events = []
    if filepath.exists():
        try:
            events = json.loads(filepath.read_text())
        except (json.JSONDecodeError, OSError):
            events = []

    # Calculate offset before append
    offset = len(json.dumps(events).encode('utf-8')) if events else 0

    events.append(event)
    content = json.dumps(events, indent=2)
    filepath.write_text(content)

    # Update index (Sprint 3)
    if INDEX_AVAILABLE and get_index:
        try:
            from aiss.chain import compute_event_hash
            event_hash = compute_event_hash(event)
            event_type = event.get("payload", {}).get("event_type") or event.get("payload", {}).get("type")

            with get_index(encrypted=False) as idx:
                idx.add_event(
                    event_hash=event_hash,
                    timestamp=event.get("timestamp", int(time.time())),
                    event_type=event_type,
                    agent_id=event.get("agent_id", ""),
                    nonce=event.get("nonce", ""),
                    file_path=f"{month}.json",
                    offset=offset,
                    length=len(json.dumps(event).encode('utf-8')),
                )
        except Exception as e:
            logger.warning(f"Index update failed (non-critical): {e}")

    logger.info("[PiQrypt] Event stored (local memory)")


def load_events_free(
    month: Optional[str] = None,
    agent_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Load plaintext events from FREE memory.
    
    Args:
        month: 'YYYY-MM' filter, or None for all months
        agent_id: Filter by agent ID
    
    Returns:
        List of matching events (chronological order)
    """
    init_memory_dirs()

    all_events = []

    if month:
        files = [EVENTS_PLAIN_DIR / f"{month}.json"]
    else:
        files = sorted(EVENTS_PLAIN_DIR.glob("*.json"))

    for f in files:
        if not f.exists():
            continue
        try:
            events = json.loads(f.read_text())
            all_events.extend(events)
        except (json.JSONDecodeError, OSError):
            logger.warning(f"Could not read memory file: {f.name}")

    if agent_id:
        all_events = [e for e in all_events if e.get("agent_id") == agent_id]

    return sorted(all_events, key=lambda e: e.get("timestamp", 0))


# ─── PRO: encrypted event storage ─────────────────────────────────────────────
def store_event_pro(event: Dict[str, Any]) -> None:
    """
    Store a signed event in AES-256-GCM encrypted monthly file.
    PRO tier — requires unlocked session.
    
    Args:
        event: Signed AISS event dict
    
    Raises:
        MemoryLockedError: If session not unlocked
    """
    init_memory_dirs()
    master_key = _require_unlocked()

    month = _month_key(event.get("timestamp", int(time.time())))
    filepath = EVENTS_ENC_DIR / f"{month}.enc"

    # Load existing events
    events = []
    offset_before = 0
    if filepath.exists():
        try:
            blob = filepath.read_bytes()
            plaintext = _aes_gcm_decrypt(master_key, blob)
            events = json.loads(plaintext.decode("utf-8"))
            offset_before = len(plaintext)
        except (MemoryCorruptedError, PassphraseError):
            logger.warning(f"Could not decrypt {month}.enc — starting fresh")
            events = []

    events.append(event)

    plaintext = json.dumps(events, indent=2).encode("utf-8")
    encrypted = _aes_gcm_encrypt(master_key, plaintext)
    filepath.write_bytes(encrypted)
    filepath.chmod(0o600)

    # Update index (Sprint 3)
    if INDEX_AVAILABLE and get_index:
        try:
            from aiss.chain import compute_event_hash
            event_hash = compute_event_hash(event)
            event_type = event.get("payload", {}).get("event_type") or event.get("payload", {}).get("type")

            with get_index(encrypted=True) as idx:
                idx.add_event(
                    event_hash=event_hash,
                    timestamp=event.get("timestamp", int(time.time())),
                    event_type=event_type,
                    agent_id=event.get("agent_id", ""),
                    nonce=event.get("nonce", ""),
                    file_path=f"{month}.enc",
                    offset=offset_before,
                    length=len(json.dumps(event).encode('utf-8')),
                )
        except Exception as e:
            logger.warning(f"Index update failed (non-critical): {e}")

    logger.info("[PiQrypt] Event stored (encrypted memory)")


def load_events_pro(
    month: Optional[str] = None,
    agent_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Load and decrypt events from PRO memory.
    Index built in RAM — never persisted in plaintext.
    
    Args:
        month: 'YYYY-MM' filter, or None for all months
        agent_id: Filter by agent ID
    
    Returns:
        List of matching events
    
    Raises:
        MemoryLockedError: If session not unlocked
    """
    init_memory_dirs()
    master_key = _require_unlocked()

    all_events = []

    if month:
        files = [EVENTS_ENC_DIR / f"{month}.enc"]
    else:
        files = sorted(EVENTS_ENC_DIR.glob("*.enc"))

    for f in files:
        if not f.exists():
            continue
        try:
            blob = f.read_bytes()
            plaintext = _aes_gcm_decrypt(master_key, blob)
            events = json.loads(plaintext.decode("utf-8"))
            all_events.extend(events)
        except (MemoryCorruptedError, PassphraseError) as e:
            logger.warning(f"Could not decrypt {f.name}: {e}")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read {f.name}: {e}")

    if agent_id:
        all_events = [e for e in all_events if e.get("agent_id") == agent_id]

    return sorted(all_events, key=lambda e: e.get("timestamp", 0))


# ─── Unified API ─────────────────────────────────────────────────────────────
def store_event(event: Dict[str, Any]) -> None:
    """
    Store event using appropriate tier (Free or Pro).
    
    Auto-detects Pro license and session state.
    Falls back to Free if Pro not available/unlocked.
    
    Args:
        event: Signed AISS event dict
    """
    from aiss.license import is_pro

    if is_pro() and is_unlocked():
        store_event_pro(event)
    else:
        store_event_free(event)
        if is_pro() and not is_unlocked():
            log_replay_detection_limited()
            logger.warning("[PiQrypt] Memory not encrypted — run: piqrypt memory unlock")


def load_events(
    month: Optional[str] = None,
    agent_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Load events using appropriate tier.
    
    Args:
        month: Optional 'YYYY-MM' filter
        agent_id: Optional agent ID filter
    
    Returns:
        List of matching events
    """
    from aiss.license import is_pro

    if is_pro() and is_unlocked():
        return load_events_pro(month=month, agent_id=agent_id)
    else:
        return load_events_free(month=month, agent_id=agent_id)


# ─── Search (in-RAM index) ────────────────────────────────────────────────────
def search_events(
    participant: Optional[str] = None,
    event_type: Optional[str] = None,
    after: Optional[int] = None,
    before: Optional[int] = None,
    limit: int = 100,
    use_index: bool = True,
) -> List[Dict[str, Any]]:
    """
    Search events in memory (Sprint 3: uses SQLite index for fast queries).
    
    Args:
        participant: agent_id appearing as agent or in payload participants
        event_type: Filter by payload event_type or event type field
        after: Unix timestamp lower bound
        before: Unix timestamp upper bound
        limit: Max results (default 100)
        use_index: If True, use SQLite index (10-1000x faster); if False, linear scan
    
    Returns:
        List of matching events (full event dicts)
    
    Example:
        >>> results = search_events(participant="pq_agent_z", after=1700000000)
        >>> # Returns full events matching criteria
    """
    from aiss.license import is_pro
    from aiss.chain import compute_event_hash

    # Sprint 3: Fast path using index
    if use_index and INDEX_AVAILABLE and get_index:
        try:
            encrypted = is_pro()
            with get_index(encrypted=encrypted) as idx:
                # Search index
                index_results = idx.search(
                    agent_id=participant,
                    event_type=event_type,
                    from_timestamp=after,
                    to_timestamp=before,
                    limit=limit,
                )

                if not index_results:
                    return []

                # Load full events from storage
                events_dict = {}
                for entry in index_results:
                    file_path = entry["file_path"]
                    if file_path not in events_dict:
                        # Load file once
                        if encrypted:
                            month = file_path.replace(".enc", "")
                            file_events = load_events_pro(month=month)
                        else:
                            month = file_path.replace(".json", "")
                            file_events = load_events_free(month=month)
                        events_dict[file_path] = {compute_event_hash(e): e for e in file_events}

                # Reconstruct full events
                full_events = []
                for entry in index_results:
                    file_path = entry["file_path"]
                    event_hash = entry["event_hash"]
                    event = events_dict.get(file_path, {}).get(event_hash)
                    if event:
                        full_events.append(event)

                return full_events[:limit]

        except Exception as e:
            logger.warning(f"Index search failed, falling back to linear scan: {e}")
            # Fall through to linear scan

    # Fallback: linear scan (old behavior)
    events = load_events()
    results = []

    for event in events:
        ts = event.get("timestamp", 0)

        # Timestamp filters
        if after and ts < after:
            continue
        if before and ts > before:
            continue

        # Participant filter
        if participant:
            agent_match = event.get("agent_id", "") == participant
            payload = event.get("payload", {})
            participants = payload.get("participants", [])
            peer_match = participant in participants
            a2a_match = (
                event.get("peer_agent_id", "") == participant or
                payload.get("peer_agent_id", "") == participant
            )
            if not (agent_match or peer_match or a2a_match):
                continue

        # Event type filter
        if event_type:
            payload = event.get("payload", {})
            et = (
                payload.get("event_type") or
                payload.get("type") or
                event.get("event_type", "")
            )
            if et != event_type:
                continue

        results.append(event)
        if len(results) >= limit:
            break

    return results


# ─── Memory migration (Free → Pro) ───────────────────────────────────────────
def migrate_to_encrypted(passphrase: str) -> Dict[str, int]:
    """
    Migrate plaintext Free events to encrypted Pro storage.
    
    Called by: piqrypt memory encrypt
    
    Args:
        passphrase: Passphrase for new encrypted storage
    
    Returns:
        {"migrated": N, "months": M, "errors": E}
    
    Example:
        >>> result = migrate_to_encrypted("strong-passphrase")
        >>> print(f"Migrated {result['migrated']} events")
    """
    from aiss.license import require_pro
    require_pro("memory_encryption")

    plain_files = sorted(EVENTS_PLAIN_DIR.glob("*.json"))
    if not plain_files:
        logger.info("No plaintext events to migrate")
        return {"migrated": 0, "months": 0, "errors": 0}

    # Setup/load master key with new passphrase
    master_key = _load_master_key(passphrase)
    _session["master_key"] = master_key
    _session["unlocked_at"] = time.time()
    _session["permanent"] = True

    migrated = 0
    months = 0
    errors = 0

    for plain_file in plain_files:
        month = plain_file.stem  # e.g. "2025-01"
        try:
            events = json.loads(plain_file.read_text())

            for event in events:
                store_event_pro(event)
                migrated += 1

            # Backup then remove plain file
            backup_path = plain_file.with_suffix(".json.migrated")
            plain_file.rename(backup_path)
            months += 1

            logger.info(f"Migrated {month}: {len(events)} events → encrypted")

        except Exception as e:
            logger.warning(f"Error migrating {month}: {e}")
            errors += 1

    logger.info("[PiQrypt] Migration complete")

    return {"migrated": migrated, "months": months, "errors": errors}


# ─── Retention & stats ────────────────────────────────────────────────────────
def get_memory_stats() -> Dict[str, Any]:
    """
    Return memory statistics (works on Free and Pro).
    For Pro: only event count per month, no decryption of content.
    """
    config = get_config()
    retention_years = config.get("retention_years", 10)

    from aiss.license import is_pro
    tier = "pro" if is_pro() else "free"

    if tier == "free":
        files = sorted(EVENTS_PLAIN_DIR.glob("*.json"))
        total = 0
        months = []
        oldest_ts = None
        newest_ts = None

        for f in files:
            try:
                events = json.loads(f.read_text())
                count = len(events)
                total += count
                months.append({"month": f.stem, "count": count})

                for e in events:
                    ts = e.get("timestamp", 0)
                    if oldest_ts is None or ts < oldest_ts:
                        oldest_ts = ts
                    if newest_ts is None or ts > newest_ts:
                        newest_ts = ts
            except Exception:
                pass

        return {
            "tier": "free",
            "total_events": total,
            "months": months,
            "oldest_timestamp": oldest_ts,
            "newest_timestamp": newest_ts,
            "retention_years": retention_years,
            "storage_path": str(EVENTS_PLAIN_DIR),
            "encrypted": False,
        }
    else:
        # Pro: count bytes in enc files without decrypting
        files = sorted(EVENTS_ENC_DIR.glob("*.enc"))
        months = []
        total_bytes = 0

        for f in files:
            sz = f.stat().st_size if f.exists() else 0
            total_bytes += sz
            months.append({"month": f.stem, "size_bytes": sz})

        return {
            "tier": "pro",
            "months": months,
            "total_size_bytes": total_bytes,
            "retention_years": retention_years,
            "storage_path": str(EVENTS_ENC_DIR),
            "encrypted": True,
            "session_active": is_unlocked(),
        }


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    # Setup
    "init_memory_dirs",
    "get_config",
    # Session (Pro)
    "unlock",
    "lock",
    "is_unlocked",
    # Storage
    "store_event",
    "store_event_free",
    "store_event_pro",
    "load_events",
    "load_events_free",
    "load_events_pro",
    # Search
    "search_events",
    # Migration
    "migrate_to_encrypted",
    # Stats
    "get_memory_stats",
    # Exceptions
    "MemoryLockedError",
    "MemoryCorruptedError",
    "PassphraseError",
]
