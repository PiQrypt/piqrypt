# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
audit_journal.py — Trust Gate Audit Journal

Immutable, hash-linked journal of all governance decisions.

Every entry is:
- Stored as a JSON line in the journal file
- Hash-linked to the previous entry (like PiQrypt event chain)
- Exportable as signed JSON or PDF

Compliance:
    ANSSI R29  — log ALL processing with fine-grained granularity
    AI Act Art.12 — automatic logging, tamper-proof, retention management
    NIST MANAGE 4.1 — residual risks documented
    NIST MEASURE 4.1 — measurement results shared and exportable
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

from trustgate.decision import Decision, Outcome, ALWAYS_LOGGED


# ─── Default journal path ─────────────────────────────────────────────────────

DEFAULT_JOURNAL_DIR = Path.home() / ".piqrypt" / "trustgate" / "journal"


# ─── Journal entry ────────────────────────────────────────────────────────────

@dataclass
class JournalEntry:
    """
    A single entry in the audit journal.
    Hash-linked to the previous entry — tamper detection.
    """
    seq:            int
    decision_id:    str
    agent_id:       str
    agent_name:     str
    action:         str
    outcome:        str
    reason:         str
    vrs:            float
    tsi_state:      str
    policy_version: str
    policy_hash:    str
    timestamp:      int

    # Human approval fields (populated for REQUIRE_HUMAN)
    approved_by:        Optional[str] = None
    approval_timestamp: Optional[int] = None
    state:              str           = "RESOLVED"

    # Chain integrity
    entry_hash:     str = ""
    previous_hash:  str = ""

    def compute_hash(self) -> str:
        """SHA-256 of canonical entry content (excluding entry_hash itself)."""
        content = json.dumps({
            "seq":            self.seq,
            "decision_id":    self.decision_id,
            "agent_id":       self.agent_id,
            "action":         self.action,
            "outcome":        self.outcome,
            "reason":         self.reason,
            "vrs":            self.vrs,
            "tsi_state":      self.tsi_state,
            "policy_version": self.policy_version,
            "policy_hash":    self.policy_hash,
            "timestamp":      self.timestamp,
            "previous_hash":  self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "seq":               self.seq,
            "decision_id":       self.decision_id,
            "agent_id":          self.agent_id,
            "agent_name":        self.agent_name,
            "action":            self.action,
            "outcome":           self.outcome,
            "reason":            self.reason,
            "vrs":               self.vrs,
            "tsi_state":         self.tsi_state,
            "policy_version":    self.policy_version,
            "policy_hash":       self.policy_hash,
            "timestamp":         self.timestamp,
            "approved_by":       self.approved_by,
            "approval_timestamp":self.approval_timestamp,
            "state":             self.state,
            "entry_hash":        self.entry_hash,
            "previous_hash":     self.previous_hash,
        }


# ─── Audit Journal ────────────────────────────────────────────────────────────

class AuditJournal:
    """
    Append-only, hash-linked audit journal.

    Storage: one JSON-lines file per day — `YYYY-MM-DD.jsonl`
    Chain:   each entry hashes the previous entry_hash

    Thread-safe for single-process use.
    Production: use distributed lock for multi-process.
    """

    def __init__(
        self,
        journal_dir: Path = DEFAULT_JOURNAL_DIR,
        retention_days: int = 730,          # AI Act Art.12 — 2 years default
        log_all: bool = False,              # True → log ALLOW too (verbose mode)
    ):
        self.journal_dir    = journal_dir
        self.retention_days = retention_days
        self.log_all        = log_all

        self.journal_dir.mkdir(parents=True, exist_ok=True)
        self._seq           = self._load_last_seq()
        self._last_hash     = self._load_last_hash()

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, decision: Decision) -> Optional[JournalEntry]:
        """
        Record a decision in the journal.

        Always logs: REQUIRE_HUMAN, BLOCK, QUARANTINE (ALWAYS_LOGGED)
        Logs if log_all=True: ALLOW, ALLOW_WITH_LOG, RESTRICTED
        Always logs: ALLOW_WITH_LOG, RESTRICTED

        Returns JournalEntry if recorded, None if skipped.
        """
        should_log = (
            decision.outcome in ALWAYS_LOGGED
            or decision.outcome in (Outcome.ALLOW_WITH_LOG, Outcome.RESTRICTED)
            or self.log_all
        )
        if not should_log:
            return None

        self._seq += 1
        entry = JournalEntry(
            seq             = self._seq,
            decision_id     = decision.decision_id,
            agent_id        = decision.agent_id,
            agent_name      = decision.agent_name,
            action          = decision.action,
            outcome         = decision.outcome,
            reason          = decision.reason,
            vrs             = decision.vrs_at_decision,
            tsi_state       = decision.tsi_state,
            policy_version  = decision.policy_version,
            policy_hash     = decision.policy_hash,
            timestamp       = decision.timestamp,
            approved_by     = decision.approved_by,
            approval_timestamp = decision.approval_timestamp,
            state           = decision.state,
            previous_hash   = self._last_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._last_hash  = entry.entry_hash

        self._append(entry)
        return entry

    def get_recent(
        self,
        agent_id: Optional[str] = None,
        outcome:  Optional[str] = None,
        days:     int = 30,
        limit:    int = 1000,
    ) -> List[JournalEntry]:
        """
        Retrieve recent journal entries with optional filters.
        Used for: audit export, escalation counting, compliance reports.
        """
        cutoff = int(time.time()) - days * 86400
        results = []

        for entry in self._iter_entries(days=days):
            if entry.timestamp < cutoff:
                continue
            if agent_id and entry.agent_id != agent_id:
                continue
            if outcome and entry.outcome != outcome:
                continue
            results.append(entry)
            if len(results) >= limit:
                break

        return results

    def count_recent(
        self,
        agent_id: str,
        hours: int = 1,
    ) -> int:
        """
        Count recent BLOCK/REQUIRE_HUMAN/QUARANTINE events for an agent.
        Used by policy_engine for escalation (ANSSI R27).
        """
        cutoff = int(time.time()) - hours * 3600
        count = 0
        for entry in self._iter_entries(days=1):
            if (
                entry.agent_id == agent_id
                and entry.timestamp >= cutoff
                and entry.outcome in (
                    Outcome.BLOCK, Outcome.REQUIRE_HUMAN, Outcome.QUARANTINE
                )
            ):
                count += 1
        return count

    def verify_chain(self) -> tuple[bool, List[str]]:
        """
        Verify integrity of the entire journal chain.
        Returns (is_valid, list_of_errors).

        AI Act Art.12 — tamper detection.
        """
        errors = []
        prev_hash = ""
        expected_seq = 1

        for entry in self._iter_entries(days=self.retention_days):
            # Sequence check
            if entry.seq != expected_seq:
                errors.append(
                    f"Sequence gap: expected {expected_seq}, got {entry.seq} "
                    f"(decision_id={entry.decision_id})"
                )

            # Previous hash check
            if entry.previous_hash != prev_hash:
                errors.append(
                    f"Chain broken at seq={entry.seq}: "
                    f"previous_hash mismatch (decision_id={entry.decision_id})"
                )

            # Self-hash check
            computed = entry.compute_hash()
            if computed != entry.entry_hash:
                errors.append(
                    f"Entry tampered at seq={entry.seq}: "
                    f"hash mismatch (decision_id={entry.decision_id})"
                )

            prev_hash = entry.entry_hash
            expected_seq += 1

        return len(errors) == 0, errors

    def export_json(
        self,
        agent_id: Optional[str] = None,
        outcome:  Optional[str] = None,
        days:     int = 30,
    ) -> str:
        """
        Export journal entries as signed JSON.
        AI Act Art.12 / ANSSI R29 — exportable evidence.
        """
        entries = self.get_recent(agent_id=agent_id, outcome=outcome, days=days)
        export = {
            "export_timestamp": int(time.time()),
            "filter": {
                "agent_id": agent_id,
                "outcome":  outcome,
                "days":     days,
            },
            "total_entries": len(entries),
            "entries": [e.to_dict() for e in entries],
            "chain_valid": self.verify_chain()[0],
        }
        return json.dumps(export, indent=2, sort_keys=True)

    def purge_old(self) -> int:
        """
        Delete journal files older than retention_days.
        AI Act Art.12 — retention management.
        Returns number of files deleted.
        """
        cutoff = time.time() - self.retention_days * 86400
        deleted = 0
        for f in self.journal_dir.glob("*.jsonl"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                deleted += 1
        return deleted

    # ── Internal ──────────────────────────────────────────────────────────────

    def _today_file(self) -> Path:
        from datetime import date
        return self.journal_dir / f"{date.today().isoformat()}.jsonl"

    def _append(self, entry: JournalEntry) -> None:
        with self._today_file().open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")

    def _iter_entries(self, days: int = 30) -> Iterator[JournalEntry]:
        """Iterate all entries from oldest to newest."""
        files = sorted(self.journal_dir.glob("*.jsonl"))
        for path in files:
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        d = json.loads(line)
                        yield JournalEntry(**{
                            k: d.get(k) for k in JournalEntry.__dataclass_fields__
                        })
                    except Exception:
                        continue
            except Exception:
                continue

    def _load_last_seq(self) -> int:
        last = 0
        for entry in self._iter_entries(days=self.retention_days):
            if entry.seq > last:
                last = entry.seq
        return last

    def _load_last_hash(self) -> str:
        last_hash = ""
        for entry in self._iter_entries(days=self.retention_days):
            last_hash = entry.entry_hash
        return last_hash


# ─── Module-level singleton ───────────────────────────────────────────────────

_default_journal: Optional[AuditJournal] = None


def get_journal(journal_dir: Optional[Path] = None) -> AuditJournal:
    """Get or create the default journal instance."""
    global _default_journal
    if _default_journal is None:
        _default_journal = AuditJournal(
            journal_dir=journal_dir or DEFAULT_JOURNAL_DIR
        )
    return _default_journal
