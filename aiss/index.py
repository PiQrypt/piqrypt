# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
Memory Index System — v1.6

Provides fast search over encrypted/plaintext memory using SQLite.

Architecture:
    ~/.piqrypt/events/
    ├── plain/
    │   ├── 2025-01.json
    │   └── index.db         # SQLite index (Free)
    └── encrypted/
        ├── 2025-01.enc
        └── index.db         # SQLite index (Pro)

Index schema v1.6:
    CREATE TABLE events_index (
        event_hash          TEXT PRIMARY KEY,
        timestamp           INTEGER,
        event_type          TEXT,
        agent_id            TEXT,
        nonce               TEXT,
        file_path           TEXT,
        offset              INTEGER,
        length              INTEGER,
        created_at          INTEGER,
        successor_agent_id  TEXT,    -- v1.6: new_agent_id after key rotation
        session_id          TEXT     -- v1.6: multi-agent session_id
    );

RFC Compliance:
    - Index contains ONLY metadata (no sensitive payloads)
    - Events remain signed + hash-chained in storage files
    - Nonce retention for 7 years (AISS-2 §11.2)

v1.6 additions:
    - successor_agent_id: indexed for key rotation chain traversal
    - session_id: indexed for multi-agent session search
    - migrate_schema(): safe migration for existing index.db
    - search() supports session_id filter
    - find_successor(): returns next agent_id after rotation
    - find_predecessor(): returns previous agent_id before rotation
"""

import sqlite3
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

from aiss.logger import get_logger

logger = get_logger(__name__)


# ─── Schema ───────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS events_index (
    event_hash          TEXT PRIMARY KEY,
    timestamp           INTEGER NOT NULL,
    event_type          TEXT,
    agent_id            TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    offset              INTEGER NOT NULL,
    length              INTEGER NOT NULL,
    created_at          INTEGER NOT NULL,
    successor_agent_id  TEXT,
    session_id          TEXT
);

CREATE INDEX IF NOT EXISTS idx_timestamp  ON events_index(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type ON events_index(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_id   ON events_index(agent_id);
CREATE INDEX IF NOT EXISTS idx_nonce      ON events_index(nonce);
CREATE INDEX IF NOT EXISTS idx_successor  ON events_index(successor_agent_id);
CREATE INDEX IF NOT EXISTS idx_session    ON events_index(session_id);
"""

# Migration SQL for existing databases (v1.5 → v1.6)
MIGRATION_V2_COLUMNS = [
    ("successor_agent_id", "TEXT"),
    ("session_id",         "TEXT"),
]

MIGRATION_V2_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_successor ON events_index(successor_agent_id);",
    "CREATE INDEX IF NOT EXISTS idx_session   ON events_index(session_id);",
]


# ─── Index Manager ────────────────────────────────────────────────────────────

class MemoryIndex:
    """
    SQLite-backed index for fast event search.

    Supports:
    - Search by timestamp range
    - Search by event_type
    - Search by agent_id
    - Search by nonce (replay detection)
    - Search by session_id (v1.6)
    - Key rotation chain traversal (v1.6)
    """

    def __init__(self, index_path: Path):
        self.index_path = index_path
        self.conn: Optional[sqlite3.Connection] = None

        if not index_path.exists():
            index_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()
        else:
            # Migrate existing db if needed
            self._migrate_schema()

    def _init_db(self):
        """Create database schema (fresh install)."""
        conn = sqlite3.connect(str(self.index_path))
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()
        logger.debug(f"[PiQrypt] Index created at {self.index_path}")

    def _migrate_schema(self):
        """
        Safely migrate existing index.db to v1.6 schema.

        Adds successor_agent_id and session_id columns if missing.
        Safe to run multiple times (idempotent).
        """
        conn = sqlite3.connect(str(self.index_path))
        try:
            # Check existing columns
            cursor = conn.execute("PRAGMA table_info(events_index)")
            existing = {row[1] for row in cursor.fetchall()}

            migrated = False
            for col_name, col_type in MIGRATION_V2_COLUMNS:
                if col_name not in existing:
                    conn.execute(f"ALTER TABLE events_index ADD COLUMN {col_name} {col_type}")
                    logger.debug(f"[PiQrypt] Index migration: added column {col_name}")
                    migrated = True

            if migrated:
                for idx_sql in MIGRATION_V2_INDEXES:
                    try:
                        conn.execute(idx_sql)
                    except Exception:
                        pass  # Index may already exist
                conn.commit()
                logger.info("[PiQrypt] Index migrated to v1.6 schema")

        except Exception as e:
            logger.warning(f"[PiQrypt] Schema migration warning: {e}")
        finally:
            conn.close()

    def connect(self):
        """Open connection (reuse if already open)."""
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.index_path))
            self.conn.row_factory = sqlite3.Row

    def close(self):
        """Close connection."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ─── Indexing ─────────────────────────────────────────────────────────────

    def add_event(
        self,
        event_hash: str,
        timestamp: int,
        event_type: Optional[str],
        agent_id: str,
        nonce: str,
        file_path: str,
        offset: int,
        length: int,
        successor_agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """
        Add event to index.

        For key_rotation events: pass new_agent_id as successor_agent_id.
        For session events: pass session_id.
        """
        self.connect()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO events_index
            (event_hash, timestamp, event_type, agent_id, nonce,
             file_path, offset, length, created_at,
             successor_agent_id, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_hash, timestamp, event_type, agent_id, nonce,
                file_path, offset, length, int(time.time()),
                successor_agent_id, session_id,
            )
        )
        self.conn.commit()

    def add_events_batch(self, events: List[Dict[str, Any]]):
        """Batch insert events (faster for migration/rebuild)."""
        self.connect()
        rows = [
            (
                e["event_hash"], e["timestamp"], e.get("event_type"), e["agent_id"],
                e["nonce"], e["file_path"], e["offset"], e["length"], int(time.time()),
                e.get("successor_agent_id"), e.get("session_id"),
            )
            for e in events
        ]
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO events_index
            (event_hash, timestamp, event_type, agent_id, nonce,
             file_path, offset, length, created_at,
             successor_agent_id, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows
        )
        self.conn.commit()

    # ─── Search ───────────────────────────────────────────────────────────────

    def search(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        from_timestamp: Optional[int] = None,
        to_timestamp: Optional[int] = None,
        nonce: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search events by criteria.

        v1.6: Added session_id filter.

        Args:
            agent_id:       Filter by agent_id
            event_type:     Filter by event_type (exact match)
            from_timestamp: Unix UTC start (inclusive)
            to_timestamp:   Unix UTC end (inclusive)
            nonce:          Filter by nonce (exact match)
            session_id:     Filter by session_id (v1.6)
            limit:          Max results

        Returns:
            List of index entries (dicts)
        """
        self.connect()

        query = "SELECT * FROM events_index WHERE 1=1"
        params = []

        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        if from_timestamp:
            query += " AND timestamp >= ?"
            params.append(from_timestamp)

        if to_timestamp:
            query += " AND timestamp <= ?"
            params.append(to_timestamp)

        if nonce:
            query += " AND nonce = ?"
            params.append(nonce)

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def search_by_hash_prefix(self, hash_prefix: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search events by partial hash."""
        self.connect()
        cursor = self.conn.execute(
            "SELECT * FROM events_index WHERE event_hash LIKE ? ORDER BY timestamp DESC LIMIT ?",
            (hash_prefix + "%", limit)
        )
        return [dict(row) for row in cursor.fetchall()]

    def find_by_nonce(self, nonce: str) -> Optional[Dict[str, Any]]:
        """Find event by nonce (for replay detection)."""
        self.connect()
        cursor = self.conn.execute(
            "SELECT * FROM events_index WHERE nonce = ?",
            (nonce,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    # ─── Key rotation chain traversal (v1.6) ─────────────────────────────────

    def find_successor(self, agent_id: str) -> Optional[str]:
        """
        Find the successor agent_id after a key rotation.

        Returns the new_agent_id if a key_rotation event exists for agent_id.
        Returns None if no rotation has occurred.

        Example:
            >>> successor = idx.find_successor("agent_id_A")
            >>> # Returns "agent_id_B" if A rotated to B
        """
        self.connect()
        cursor = self.conn.execute(
            """
            SELECT successor_agent_id FROM events_index
            WHERE agent_id = ?
              AND event_type = 'key_rotation'
              AND successor_agent_id IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (agent_id,)
        )
        row = cursor.fetchone()
        return row["successor_agent_id"] if row else None

    def find_predecessor(self, agent_id: str) -> Optional[str]:
        """
        Find the predecessor agent_id before a key rotation.

        Returns the old agent_id that rotated to this agent_id.
        Returns None if this is an original identity (no rotation).

        Example:
            >>> predecessor = idx.find_predecessor("agent_id_B")
            >>> # Returns "agent_id_A" if A rotated to B
        """
        self.connect()
        cursor = self.conn.execute(
            """
            SELECT agent_id FROM events_index
            WHERE successor_agent_id = ?
              AND event_type = 'key_rotation'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (agent_id,)
        )
        row = cursor.fetchone()
        return row["agent_id"] if row else None

    def get_full_identity_chain(self, agent_id: str) -> List[str]:
        """
        Get the complete chain of agent_ids for an identity.

        Traverses both backwards (predecessors) and forwards (successors)
        from the given agent_id to build the full rotation history.

        Returns:
            List of agent_ids in chronological order (oldest first).

        Example:
            >>> chain = idx.get_full_identity_chain("agent_id_B")
            >>> # Returns ["agent_id_A", "agent_id_B", "agent_id_C"]
            >>> # if A → B → C rotation chain exists
        """
        visited = set()
        chain = [agent_id]
        visited.add(agent_id)

        # Walk backwards to find all predecessors
        current = agent_id
        while True:
            predecessor = self.find_predecessor(current)
            if not predecessor or predecessor in visited:
                break
            chain.insert(0, predecessor)
            visited.add(predecessor)
            current = predecessor

        # Walk forwards to find all successors
        current = agent_id
        while True:
            successor = self.find_successor(current)
            if not successor or successor in visited:
                break
            chain.append(successor)
            visited.add(successor)
            current = successor

        return chain

    # ─── Session search (v1.6) ────────────────────────────────────────────────

    def search_by_session(
        self,
        session_id: str,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Get all events belonging to a session.

        Returns events from all agents in the session,
        sorted chronologically.

        Args:
            session_id: Session ID from piqrypt-session
            limit:      Max results

        Returns:
            List of index entries sorted by timestamp ASC
        """
        self.connect()
        cursor = self.conn.execute(
            """
            SELECT * FROM events_index
            WHERE session_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (session_id, limit)
        )
        return [dict(row) for row in cursor.fetchall()]

    # ─── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        self.connect()
        cursor = self.conn.execute(
            """
            SELECT
                COUNT(*) as total,
                MIN(timestamp) as earliest,
                MAX(timestamp) as latest,
                COUNT(DISTINCT agent_id) as agents,
                COUNT(DISTINCT event_type) as event_types,
                COUNT(DISTINCT session_id) as sessions,
                COUNT(successor_agent_id) as rotations
            FROM events_index
            """
        )
        row = cursor.fetchone()
        return {
            "total_events":      row["total"],
            "earliest_timestamp": row["earliest"],
            "latest_timestamp":  row["latest"],
            "agents_count":      row["agents"],
            "event_types_count": row["event_types"],
            "sessions_count":    row["sessions"],
            "rotations_count":   row["rotations"],
        }

    def get_event_types(self) -> List[str]:
        """Get list of all unique event types."""
        self.connect()
        cursor = self.conn.execute(
            "SELECT DISTINCT event_type FROM events_index WHERE event_type IS NOT NULL ORDER BY event_type"
        )
        return [row["event_type"] for row in cursor.fetchall()]

    # ─── Maintenance ──────────────────────────────────────────────────────────

    def rebuild_index(self, events: List[Dict[str, Any]]):
        """Rebuild entire index from scratch."""
        self.connect()
        self.conn.execute("DELETE FROM events_index")
        self.conn.commit()
        self.add_events_batch(events)
        logger.info(f"[PiQrypt] Index rebuilt: {len(events)} events")

    def vacuum(self):
        """Optimize database (reclaim space, rebuild indexes)."""
        self.connect()
        self.conn.execute("VACUUM")
        self.conn.commit()


# ─── Public API ───────────────────────────────────────────────────────────────

def get_index(encrypted: bool = False) -> MemoryIndex:
    """
    Get memory index (Free or Pro).

    Args:
        encrypted: If True, returns Pro encrypted index; else Free index

    Returns:
        MemoryIndex instance (auto-migrates schema if needed)
    """
    from aiss.memory import EVENTS_PLAIN_DIR, EVENTS_ENC_DIR

    if encrypted:
        index_path = EVENTS_ENC_DIR / "index.db"
    else:
        index_path = EVENTS_PLAIN_DIR / "index.db"

    return MemoryIndex(index_path)


__all__ = [
    "MemoryIndex",
    "get_index",
    "SCHEMA",
    "MIGRATION_V2_COLUMNS",
    "MIGRATION_V2_INDEXES",
]
