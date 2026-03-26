# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Agent Memory System (PCP Layer 2)

Implements cryptographically-backed agent memory:
- FREE: plaintext JSON storage in ~/.piqrypt/agents/<n>/events/plain/
- PRO:  AES-256-GCM encrypted storage + PBKDF2 passphrase unlock

RFC Sections 6 (Mémoire d'Agent), 11.2 (AISS-2 nonce retention)

Architecture v1.8.1 (isolation par agent) :
    ~/.piqrypt/
    └── agents/
        └── <agent_name>/
            ├── events/
            │   ├── plain/          # FREE: monthly JSON files
            │   └── encrypted/      # PRO: AES-256-GCM monthly files
            ├── keys/
            │   └── master.key.enc  # PRO master key
            └── index.db            # SQLite index

Backward compat v1.6.0 :
    - agent_name optionnel → fallback "default"
    - Ancien chemin ~/.piqrypt/events/ → détecté et migré par migration.py
    - Toutes les fonctions publiques existantes inchangées

v1.7 additions (vs v1.6.0) :
    - Toutes les fonctions acceptent agent_name optionnel
    - _get_dirs(agent_name) : résolution dynamique des chemins
    - Intégration agent_registry pour init et résolution
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

# ─── Constants (backward compat — remplacés dynamiquement par _get_dirs) ──────
PIQRYPT_DIR = Path.home() / ".piqrypt"
EVENTS_PLAIN_DIR = PIQRYPT_DIR / "events" / "plain"
EVENTS_ENC_DIR = PIQRYPT_DIR / "events" / "encrypted"
KEYS_DIR = PIQRYPT_DIR / "keys"
MASTER_KEY_FILE = KEYS_DIR / "master.key.enc"
CONFIG_FILE = PIQRYPT_DIR / "config.json"

# ─── Agent Registry (v1.8.1) ──────────────────────────────────────────────────
try:
    from aiss.agent_registry import (
        get_events_plain_dir as _reg_plain_dir,
        get_events_enc_dir   as _reg_enc_dir,
        get_keys_dir         as _reg_keys_dir,
        init_agent_dirs      as _reg_init_dirs,
        resolve_agent_name   as _resolve_agent,
    )
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False


def _get_dirs(agent_name: Optional[str] = None, session: Any = None):
    """
    Résout les chemins de stockage pour un agent.

    v1.8.1 : utilise agent_registry pour l'isolation par agent.
    Fallback v1.6.0 : chemins globaux historiques.

    Returns:
        (plain_dir, enc_dir, keys_dir, master_key_file)
    """
    if REGISTRY_AVAILABLE:
        name = _resolve_agent(agent_name, session)
        plain_dir       = _reg_plain_dir(name)
        enc_dir         = _reg_enc_dir(name)
        keys_dir        = _reg_keys_dir(name)
        master_key_file = keys_dir / "master.key.enc"
    else:
        # Fallback v1.6.0 — chemins globaux
        plain_dir       = EVENTS_PLAIN_DIR
        enc_dir         = EVENTS_ENC_DIR
        keys_dir        = KEYS_DIR
        master_key_file = MASTER_KEY_FILE

    return plain_dir, enc_dir, keys_dir, master_key_file

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12
AES_TAG_SIZE = 16
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


# ─── AES-256-GCM ──────────────────────────────────────────────────────────────
def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
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
    raise ImportError("Pro memory encryption requires: pip install cryptography")


def _aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
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
            return cipher.decrypt_and_verify(ct, tag)
        except Exception:
            raise PassphraseError("Decryption failed — wrong passphrase or corrupted data")
    except ImportError:
        pass
    raise ImportError("Pro memory requires: pip install cryptography")


def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(PBKDF2_HASH, passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=AES_KEY_SIZE)


# ─── Directory initialization ─────────────────────────────────────────────────
def init_memory_dirs(agent_name: Optional[str] = None, base_dir: Optional[str] = None) -> None:
    """Create directory structure for an agent (v1.8.1) or global (v1.6.0 compat).

    Args:
        agent_name: Nom de l'agent (v1.8.1)
        base_dir:   Répertoire racine alternatif (utile en tests/CI)
    """
    if base_dir is not None:
        # Mode test : crée la structure dans base_dir
        _base = Path(base_dir)
        for subdir in ["events/plain", "events/encrypted", "keys"]:
            (_base / subdir).mkdir(parents=True, exist_ok=True)
        return
    if REGISTRY_AVAILABLE and agent_name:
        _reg_init_dirs(agent_name)
        return
    # Fallback v1.6.0
    for d in [PIQRYPT_DIR, EVENTS_PLAIN_DIR, EVENTS_ENC_DIR, KEYS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        config = {"version": "1.8.1", "retention_years": 10, "auto_backup": False,
                  "backup_interval_months": 6, "created_at": int(time.time())}
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
    logger.info(f"[PiQrypt] Memory directories initialized at {PIQRYPT_DIR}")


def get_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        init_memory_dirs()
    return json.loads(CONFIG_FILE.read_text())


# ─── Master key management (PRO) ─────────────────────────────────────────────
def _setup_master_key(passphrase: str) -> bytes:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    master_key = secrets.token_bytes(AES_KEY_SIZE)
    salt = secrets.token_bytes(SALT_SIZE)
    passphrase_key = _derive_key_from_passphrase(passphrase, salt)
    encrypted_master = _aes_gcm_encrypt(passphrase_key, master_key)
    blob = salt + encrypted_master
    MASTER_KEY_FILE.write_bytes(blob)
    MASTER_KEY_FILE.chmod(0o600)
    logger.info("Master key created and encrypted")
    return master_key


def _load_master_key(passphrase: str) -> bytes:
    if not MASTER_KEY_FILE.exists():
        return _setup_master_key(passphrase)
    blob = MASTER_KEY_FILE.read_bytes()
    if len(blob) < SALT_SIZE:
        raise MemoryCorruptedError("Master key file corrupted")
    salt = blob[:SALT_SIZE]
    encrypted_master = blob[SALT_SIZE:]
    passphrase_key = _derive_key_from_passphrase(passphrase, salt)
    try:
        return _aes_gcm_decrypt(passphrase_key, encrypted_master)
    except PassphraseError:
        raise PassphraseError("Wrong passphrase — cannot unlock memory")


# ─── Session management ───────────────────────────────────────────────────────
_session: Dict[str, Any] = {
    "master_key": None,
    "unlocked_at": None,
    "timeout_seconds": 3600,
    "permanent": False,
}


def unlock(passphrase: str, permanent: bool = False) -> None:
    from aiss.license import is_pro
    if not is_pro():
        logger.warning("[PiQrypt] Encrypted memory requires Pro license")
        raise PiQryptError("Memory encryption requires PiQrypt Pro")
    master_key = _load_master_key(passphrase)
    _session["master_key"] = master_key
    _session["unlocked_at"] = time.time()
    _session["permanent"] = permanent
    log_memory_unlocked()


def lock() -> None:
    _session["master_key"] = None
    _session["unlocked_at"] = None
    _session["permanent"] = False
    log_memory_locked()


def is_unlocked() -> bool:
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
    if not is_unlocked():
        raise MemoryLockedError(
            "Pro memory is locked.\n"
            "Run: piqrypt unlock --session\n"
            "Or in Python: from aiss.memory import unlock; unlock('passphrase')"
        )
    return _session["master_key"]


# ─── Monthly file helpers ─────────────────────────────────────────────────────
def _month_key(timestamp: int) -> str:
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m")


def _current_month() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m")


# ─── FREE: plaintext event storage ───────────────────────────────────────────
def store_event_free(
    event: Dict[str, Any],
    agent_name: Optional[str] = None,
    session: Any = None,
) -> None:
    """Store a signed event in plaintext monthly JSON file. FREE tier.

    Args:
        event:      Signed AISS event dict
        agent_name: Agent name for isolation (v1.8.1). None = fallback "default"
        session:    IdentitySession — agent_name déduit si fourni
    """
    plain_dir, _, _, _ = _get_dirs(agent_name, session)
    plain_dir.mkdir(parents=True, exist_ok=True)

    month = _month_key(event.get("timestamp", int(time.time())))
    filepath = plain_dir / f"{month}.json"

    events = []
    if filepath.exists():
        try:
            events = json.loads(filepath.read_text())
        except (json.JSONDecodeError, OSError):
            events = []

    offset = len(json.dumps(events).encode('utf-8')) if events else 0
    events.append(event)
    filepath.write_text(json.dumps(events, indent=2))

    # Update index — v1.6: + successor_agent_id + session_id
    if INDEX_AVAILABLE and get_index:
        try:
            from aiss.chain import compute_event_hash
            event_hash = compute_event_hash(event)
            payload = event.get("payload", {})
            event_type = payload.get("event_type") or payload.get("type")

            # v1.6: indexer le nouvel agent_id lors d'une rotation de clés
            successor_agent_id = None
            if event_type == "key_rotation":
                successor_agent_id = payload.get("new_agent_id")

            # v1.6: indexer le session_id si présent
            session_id = payload.get("session_id")

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
                    successor_agent_id=successor_agent_id,
                    session_id=session_id,
                )
        except Exception as e:
            logger.warning(f"Index update failed (non-critical): {e}")

    logger.info("[PiQrypt] Event stored (local memory)")


def load_events_free(
    month: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    session: Any = None,
) -> List[Dict[str, Any]]:
    plain_dir, _, _, _ = _get_dirs(agent_name, session)
    plain_dir.mkdir(parents=True, exist_ok=True)
    all_events = []
    files = [plain_dir / f"{month}.json"] if month else sorted(plain_dir.glob("*.json"))
    for f in files:
        if not f.exists():
            continue
        try:
            all_events.extend(json.loads(f.read_text()))
        except (json.JSONDecodeError, OSError):
            logger.warning(f"Could not read memory file: {f.name}")
    if agent_id:
        all_events = [e for e in all_events if e.get("agent_id") == agent_id]
    return sorted(all_events, key=lambda e: e.get("timestamp", 0))


# ─── PRO: encrypted event storage ─────────────────────────────────────────────
def store_event_pro(
    event: Dict[str, Any],
    agent_name: Optional[str] = None,
    session: Any = None,
) -> None:
    """Store a signed event in AES-256-GCM encrypted monthly file. PRO tier."""
    _, enc_dir, _, master_key_file = _get_dirs(agent_name, session)
    enc_dir.mkdir(parents=True, exist_ok=True)
    master_key = _require_unlocked()
    month = _month_key(event.get("timestamp", int(time.time())))
    filepath = enc_dir / f"{month}.enc"

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

    # Update index — v1.6: + successor_agent_id + session_id
    if INDEX_AVAILABLE and get_index:
        try:
            from aiss.chain import compute_event_hash
            event_hash = compute_event_hash(event)
            payload = event.get("payload", {})
            event_type = payload.get("event_type") or payload.get("type")

            # v1.6: indexer le nouvel agent_id lors d'une rotation de clés
            successor_agent_id = None
            if event_type == "key_rotation":
                successor_agent_id = payload.get("new_agent_id")

            # v1.6: indexer le session_id si présent
            session_id = payload.get("session_id")

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
                    successor_agent_id=successor_agent_id,
                    session_id=session_id,
                )
        except Exception as e:
            logger.warning(f"Index update failed (non-critical): {e}")

    logger.info("[PiQrypt] Event stored (encrypted memory)")


def load_events_pro(
    month: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    session: Any = None,
) -> List[Dict[str, Any]]:
    _, enc_dir, _, _ = _get_dirs(agent_name, session)
    master_key = _require_unlocked()
    all_events = []
    files = [enc_dir / f"{month}.enc"] if month else sorted(enc_dir.glob("*.enc"))
    for f in files:
        if not f.exists():
            continue
        try:
            blob = f.read_bytes()
            plaintext = _aes_gcm_decrypt(master_key, blob)
            all_events.extend(json.loads(plaintext.decode("utf-8")))
        except (MemoryCorruptedError, PassphraseError) as e:
            logger.warning(f"Could not decrypt {f.name}: {e}")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not read {f.name}: {e}")
    if agent_id:
        all_events = [e for e in all_events if e.get("agent_id") == agent_id]
    return sorted(all_events, key=lambda e: e.get("timestamp", 0))


# ─── Unified API ─────────────────────────────────────────────────────────────
def store_event(
    event: Dict[str, Any],
    agent_name: Optional[str] = None,
    session: Any = None,
    base_dir: Optional[str] = None,
) -> None:
    """
    Stocke un événement signé en mémoire.

    v1.8.1 : agent_name et session optionnels pour isolation par agent.
    Backward compat : si omis → agent "default".

    Args:
        event:      Événement signé à stocker
        agent_name: Nom de l'agent (v1.8.1)
        session:    Session IdentitySession active (optionnel)
        base_dir:   Répertoire racine alternatif (tests/CI) — stockage JSON plain
    """
    if base_dir is not None:
        # Mode test : stockage JSON plain dans base_dir/events/plain/
        plain_dir = Path(base_dir) / "events" / "plain"
        plain_dir.mkdir(parents=True, exist_ok=True)
        ts = event.get("timestamp", int(time.time()))
        month = time.strftime("%Y-%m", time.localtime(ts if isinstance(ts, (int, float)) else int(time.time())))
        ev_file = plain_dir / f"{month}.json"
        events = []
        if ev_file.exists():
            try:
                events = json.loads(ev_file.read_text())
            except Exception:
                events = []
        events.append(event)
        ev_file.write_text(json.dumps(events, indent=2))
        return
    from aiss.license import is_pro
    if is_pro() and is_unlocked():
        store_event_pro(event, agent_name=agent_name, session=session)
    else:
        store_event_free(event, agent_name=agent_name, session=session)
        if is_pro() and not is_unlocked():
            log_replay_detection_limited()
            logger.warning("[PiQrypt] Memory not encrypted — run: piqrypt memory unlock")


def load_events(
    month: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    session: Any = None,
    base_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Charge les événements d'un agent.

    v1.8.1 : agent_name et session optionnels pour isolation par agent.

    Args:
        month:      Filtre par mois (YYYY-MM)
        agent_id:   Filtre par agent_id
        agent_name: Nom de l'agent (v1.8.1)
        session:    Session IdentitySession active (optionnel)
        base_dir:   Répertoire racine alternatif (tests/CI)
    """
    if base_dir is not None:
        # Mode test : charge depuis base_dir/events/plain/
        plain_dir = Path(base_dir) / "events" / "plain"
        if not plain_dir.exists():
            return []
        all_events: List[Dict[str, Any]] = []
        for ev_file in sorted(plain_dir.glob("*.json")):
            if month and not ev_file.stem.startswith(month):
                continue
            try:
                data = json.loads(ev_file.read_text())
                if isinstance(data, list):
                    all_events.extend(data)
            except Exception:
                pass
        return all_events
    from aiss.license import is_pro
    if is_pro() and is_unlocked():
        return load_events_pro(
            month=month, agent_id=agent_id,
            agent_name=agent_name, session=session
        )
    else:
        return load_events_free(
            month=month, agent_id=agent_id,
            agent_name=agent_name, session=session
        )


# ─── Helper index v1.6 ───────────────────────────────────────────────────────
def _load_full_events_from_index(
    index_results: List[Dict[str, Any]],
    encrypted: bool,
) -> List[Dict[str, Any]]:
    """Charge les events complets depuis le storage à partir des résultats index SQLite."""
    from aiss.chain import compute_event_hash
    if not index_results:
        return []
    events_dict: Dict[str, Dict] = {}
    for entry in index_results:
        fp = entry["file_path"]
        if fp not in events_dict:
            if encrypted:
                file_events = load_events_pro(month=fp.replace(".enc", ""))
            else:
                file_events = load_events_free(month=fp.replace(".json", ""))
            events_dict[fp] = {compute_event_hash(e): e for e in file_events}
    return [events_dict.get(e["file_path"], {}).get(e["event_hash"])
            for e in index_results
            if events_dict.get(e["file_path"], {}).get(e["event_hash"])]


# ─── Search — v1.6 ───────────────────────────────────────────────────────────
def search_events(
    participant: Optional[str] = None,
    event_type: Optional[str] = None,
    after: Optional[int] = None,
    before: Optional[int] = None,
    limit: int = 100,
    use_index: bool = True,
    session_id: Optional[str] = None,
    follow_rotation: bool = False,
) -> List[Dict[str, Any]]:
    """
    Search events in memory.

    v1.6 additions:
        session_id:      Filtre par session_id multi-agents (SQL natif)
        follow_rotation: Si True, inclut tous les agent_ids de la chaîne de rotation

    Args:
        participant:     agent_id (agent ou payload.participants)
        event_type:      Filtre par event_type
        after:           Borne basse Unix timestamp
        before:          Borne haute Unix timestamp
        limit:           Max résultats (défaut 100)
        use_index:       Utilise l'index SQLite
        session_id:      Filtre par session_id (v1.6)
        follow_rotation: Suit la chaîne de rotation de clés (v1.6)

    Example:
        # Historique complet incluant avant la rotation de clés
        results = search_events(participant="agent_id_B", follow_rotation=True)

        # Tous les events d'une session multi-agents
        results = search_events(session_id="sess_a3f9...")
    """
    from aiss.license import is_pro

    # ── v1.6: session_id fast path ────────────────────────────────────────────
    if session_id and use_index and INDEX_AVAILABLE and get_index:
        try:
            encrypted = is_pro()
            with get_index(encrypted=encrypted) as idx:
                index_results = idx.search_by_session(session_id, limit=limit)
                if index_results is not None:
                    return _load_full_events_from_index(index_results, encrypted)
        except Exception as e:
            logger.warning(f"Session index search failed, falling back: {e}")

    # ── v1.6: follow_rotation — résoudre la chaîne complète d'identités ───────
    search_participants = None
    if follow_rotation and participant:
        try:
            from aiss.history import _resolve_identity_chain
            chain = _resolve_identity_chain(participant)
            if len(chain) > 1:
                search_participants = chain
                logger.debug(f"[PiQrypt] follow_rotation: {participant} → {chain}")
        except Exception as e:
            logger.debug(f"[PiQrypt] follow_rotation unavailable: {e}")

    # ── Fast path: index SQLite ───────────────────────────────────────────────
    if use_index and INDEX_AVAILABLE and get_index:
        try:
            encrypted = is_pro()
            with get_index(encrypted=encrypted) as idx:
                if search_participants:
                    seen_hashes: set = set()
                    all_results: List[Dict] = []
                    for pid in search_participants:
                        for entry in idx.search(
                            agent_id=pid,
                            event_type=event_type,
                            from_timestamp=after,
                            to_timestamp=before,
                            limit=limit,
                        ):
                            if entry["event_hash"] not in seen_hashes:
                                seen_hashes.add(entry["event_hash"])
                                all_results.append(entry)
                    all_results.sort(key=lambda x: x.get("timestamp", 0))
                    index_results = all_results[:limit]
                else:
                    index_results = idx.search(
                        agent_id=participant,
                        event_type=event_type,
                        from_timestamp=after,
                        to_timestamp=before,
                        session_id=session_id,
                        limit=limit,
                    )

                if index_results is not None:
                    return _load_full_events_from_index(index_results, encrypted)

        except Exception as e:
            logger.warning(f"Index search failed, falling back to linear scan: {e}")

    # ── Fallback: linear scan ─────────────────────────────────────────────────
    events = load_events()
    results = []
    _participants = search_participants or ([participant] if participant else None)

    for event in events:
        ts = event.get("timestamp", 0)
        if after and ts < after:
            continue
        if before and ts > before:
            continue
        if _participants:
            agent_match = event.get("agent_id", "") in _participants
            payload = event.get("payload", {})
            part_list = payload.get("participants", [])
            peer_match = any(p in part_list for p in _participants)
            a2a_match = (
                event.get("peer_agent_id", "") in _participants or
                payload.get("peer_agent_id", "") in _participants
            )
            if not (agent_match or peer_match or a2a_match):
                continue
        if event_type:
            payload = event.get("payload", {})
            et = payload.get("event_type") or payload.get("type") or event.get("event_type", "")
            if et != event_type:
                continue
        if session_id:
            if event.get("payload", {}).get("session_id") != session_id:
                continue
        results.append(event)
        if len(results) >= limit:
            break

    return results


# ─── Memory migration (Free → Pro) ───────────────────────────────────────────
def migrate_to_encrypted(passphrase: str) -> Dict[str, int]:
    """Migrate plaintext Free events to encrypted Pro storage."""
    from aiss.license import require_pro
    require_pro("memory_encryption")

    plain_files = sorted(EVENTS_PLAIN_DIR.glob("*.json"))
    if not plain_files:
        logger.info("No plaintext events to migrate")
        return {"migrated": 0, "months": 0, "errors": 0}

    master_key = _load_master_key(passphrase)
    _session["master_key"] = master_key
    _session["unlocked_at"] = time.time()
    _session["permanent"] = True

    migrated = 0
    months = 0
    errors = 0

    for plain_file in plain_files:
        month = plain_file.stem
        try:
            events = json.loads(plain_file.read_text())
            for event in events:
                store_event_pro(event)
                migrated += 1
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
def get_memory_stats(
    agent_name: Optional[str] = None,
    session: Any = None,
) -> Dict[str, Any]:
    """Statistiques mémoire d'un agent. agent_name optionnel (v1.8.1)."""
    config = get_config()
    retention_years = config.get("retention_years", 10)
    from aiss.license import is_pro
    tier = "pro" if is_pro() else "free"

    plain_dir, enc_dir, _, _ = _get_dirs(agent_name, session)

    if tier == "free":
        files = sorted(plain_dir.glob("*.json")) if plain_dir.exists() else []
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
            "tier": "free", "total_events": total, "months": months,
            "oldest_timestamp": oldest_ts, "newest_timestamp": newest_ts,
            "retention_years": retention_years, "storage_path": str(plain_dir),
            "encrypted": False,
        }
    else:
        files = sorted(enc_dir.glob("*.enc")) if enc_dir.exists() else []
        months = []
        total_bytes = 0
        for f in files:
            sz = f.stat().st_size if f.exists() else 0
            total_bytes += sz
            months.append({"month": f.stem, "size_bytes": sz})
        return {
            "tier": "pro", "months": months, "total_size_bytes": total_bytes,
            "retention_years": retention_years, "storage_path": str(enc_dir),
            "encrypted": True, "session_active": is_unlocked(),
        }


# ─── Public API ───────────────────────────────────────────────────────────────
__all__ = [
    "init_memory_dirs", "get_config",
    "unlock", "lock", "is_unlocked",
    "store_event", "store_event_free", "store_event_pro",
    "load_events", "load_events_free", "load_events_pro",
    "search_events",
    "migrate_to_encrypted",
    "get_memory_stats",
    "MemoryLockedError", "MemoryCorruptedError", "PassphraseError",
]
