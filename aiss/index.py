"""
Memory Index System — Sprint 3

Provides fast search over encrypted/plaintext memory using SQLite.

Architecture:
    ~/.piqrypt/events/
    ├── plain/
    │   ├── 2025-01.json
    │   └── index.db         # SQLite index (Free)
    └── encrypted/
        ├── 2025-01.enc
        └── index.db         # SQLite index (Pro)

Index schema:
    CREATE TABLE events_index (
        event_hash TEXT PRIMARY KEY,
        timestamp INTEGER,
        event_type TEXT,
        agent_id TEXT,
        nonce TEXT,
        file_path TEXT,
        offset INTEGER,
        length INTEGER,
        created_at INTEGER
    );
    
    CREATE INDEX idx_timestamp ON events_index(timestamp);
    CREATE INDEX idx_event_type ON events_index(event_type);
    CREATE INDEX idx_agent_id ON events_index(agent_id);

RFC Compliance:
    - Index contains ONLY metadata (no sensitive payloads)
    - Events remain signed + hash-chained in storage files
    - Nonce retention for 7 years (AISS-2 §11.2)
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
    event_hash TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    event_type TEXT,
    agent_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    file_path TEXT NOT NULL,
    offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON events_index(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type ON events_index(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_id ON events_index(agent_id);
CREATE INDEX IF NOT EXISTS idx_nonce ON events_index(nonce);
"""


# ─── Index Manager ────────────────────────────────────────────────────────────

class MemoryIndex:
    """
    SQLite-backed index for fast event search.
    
    Supports:
    - Search by timestamp range
    - Search by event_type
    - Search by agent_id
    - Search by nonce (replay detection)
    - Export selected events
    """

    def __init__(self, index_path: Path):
        """
        Initialize index.
        
        Args:
            index_path: Path to index.db file
        """
        self.index_path = index_path
        self.conn: Optional[sqlite3.Connection] = None

        # Create index if not exists
        if not index_path.exists():
            index_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _init_db(self):
        """Create database schema."""
        conn = sqlite3.connect(str(self.index_path))
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def connect(self):
        """Open connection (reuse if already open)."""
        if self.conn is None:
            self.conn = sqlite3.connect(str(self.index_path))
            self.conn.row_factory = sqlite3.Row  # Dict-like access

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
    ):
        """
        Add event to index.
        
        Args:
            event_hash:  SHA-256 hash of event
            timestamp:   Unix UTC seconds
            event_type:  Event type from payload (e.g., "trade_executed")
            agent_id:    Agent ID
            nonce:       Event nonce (UUIDv4)
            file_path:   Relative path to storage file (e.g., "2025-01.enc")
            offset:      Byte offset in file
            length:      Event size in bytes
        """
        self.connect()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO events_index 
            (event_hash, timestamp, event_type, agent_id, nonce, file_path, offset, length, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_hash, timestamp, event_type, agent_id, nonce, file_path, offset, length, int(time.time()))
        )
        self.conn.commit()

    def add_events_batch(self, events: List[Dict[str, Any]]):
        """
        Batch insert events (faster for migration).
        
        Args:
            events: List of dicts with keys: event_hash, timestamp, event_type, agent_id, nonce, file_path, offset, length
        """
        self.connect()
        rows = [
            (
                e["event_hash"], e["timestamp"], e.get("event_type"), e["agent_id"],
                e["nonce"], e["file_path"], e["offset"], e["length"], int(time.time())
            )
            for e in events
        ]
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO events_index 
            (event_hash, timestamp, event_type, agent_id, nonce, file_path, offset, length, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Search events by criteria.
        
        Args:
            agent_id:       Filter by agent_id
            event_type:     Filter by event_type (exact match)
            from_timestamp: Unix UTC start (inclusive)
            to_timestamp:   Unix UTC end (inclusive)
            nonce:          Filter by nonce (exact match)
            limit:          Max results
        
        Returns:
            List of index entries (dicts with event_hash, timestamp, file_path, offset, length)
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

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def search_by_hash_prefix(self, hash_prefix: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search events by partial hash (e.g., "a3f7e8").
        
        Args:
            hash_prefix: Hash prefix (min 6 chars recommended)
            limit:       Max results
        
        Returns:
            List of matching events
        """
        self.connect()
        cursor = self.conn.execute(
            "SELECT * FROM events_index WHERE event_hash LIKE ? ORDER BY timestamp DESC LIMIT ?",
            (hash_prefix + "%", limit)
        )
        return [dict(row) for row in cursor.fetchall()]

    def find_by_nonce(self, nonce: str) -> Optional[Dict[str, Any]]:
        """
        Find event by nonce (for replay detection).
        
        Args:
            nonce: Event nonce
        
        Returns:
            Index entry or None
        """
        self.connect()
        cursor = self.conn.execute(
            "SELECT * FROM events_index WHERE nonce = ?",
            (nonce,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    # ─── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        Get index statistics.
        
        Returns:
            Dict with total_events, earliest_timestamp, latest_timestamp, agents, event_types
        """
        self.connect()

        cursor = self.conn.execute(
            """
            SELECT 
                COUNT(*) as total,
                MIN(timestamp) as earliest,
                MAX(timestamp) as latest,
                COUNT(DISTINCT agent_id) as agents,
                COUNT(DISTINCT event_type) as event_types
            FROM events_index
            """
        )
        row = cursor.fetchone()

        return {
            "total_events": row["total"],
            "earliest_timestamp": row["earliest"],
            "latest_timestamp": row["latest"],
            "agents_count": row["agents"],
            "event_types_count": row["event_types"],
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
        """
        Rebuild entire index from scratch.
        
        Args:
            events: List of events with metadata
        """
        self.connect()
        self.conn.execute("DELETE FROM events_index")
        self.conn.commit()
        self.add_events_batch(events)
        logger.piqrypt(f"Index rebuilt: {len(events)} events")

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
        encrypted: If True, returns Pro encrypted index; else Free plaintext index
    
    Returns:
        MemoryIndex instance
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
]
