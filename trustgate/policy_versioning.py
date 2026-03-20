# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# PROPRIETARY METHOD -- Dual License
# This file contains original algorithmic methods protected by
# e-Soleau deposits DSO2026006483 and DSO2026009143 (INPI France).
#
# Licensed under the Elastic License 2.0 (ELv2) for open/internal use.
# A separate commercial license is required for:
#   - SaaS or managed service deployment to third parties
#   - Proprietary products embedding this method
#   - OEM or white-label use
# Commercial license: contact@piqrypt.com -- Subject: Commercial License Inquiry

"""
policy_versioning.py — Trust Gate Policy Versioning

Every policy change is hashed, recorded, and diffable.
Policy history is an immutable log — never deleted, only appended.

Compliance:
    ANSSI R35  — protect policy file integrity (SHA-256)
    NIST GOVERN 6.2 — policies reviewed and updated with audit trail
    AI Act Art.9  — risk management system version-controlled
    AI Act Art.17 — quality management — corrective action procedures
"""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from trustgate.policy_loader import load_policy


# ─── Default versioning dir ───────────────────────────────────────────────────

DEFAULT_VERSIONS_DIR = Path.home() / ".piqrypt" / "trustgate" / "policy_versions"


# ─── Version record ───────────────────────────────────────────────────────────

@dataclass
class PolicyVersion:
    version_id:   str
    name:         str
    content_hash: str
    activated_at: int
    activated_by: str    # principal_id or "system"
    comment:      str    = ""
    content:      str    = ""   # raw YAML/JSON content

    def to_dict(self) -> dict:
        return {
            "version_id":   self.version_id,
            "name":         self.name,
            "content_hash": self.content_hash,
            "activated_at": self.activated_at,
            "activated_by": self.activated_by,
            "comment":      self.comment,
        }


# ─── Policy Versioning ────────────────────────────────────────────────────────

class PolicyVersioning:
    """
    Manages the version history of a policy.

    Each time a policy is activated, a version record is appended
    to the history log. The content is stored for diff capability.

    ANSSI R35: Hash-verified load at every activation.
    """

    def __init__(self, versions_dir: Path = DEFAULT_VERSIONS_DIR):
        self.versions_dir = versions_dir
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self._history_file = self.versions_dir / "history.jsonl"

    def activate(
        self,
        policy_path: Path,
        activated_by: str = "system",
        comment: str = "",
    ) -> PolicyVersion:
        """
        Activate a policy — hash, record, return version.

        Args:
            policy_path:  Path to the policy file
            activated_by: principal_id who activated (audit trail)
            comment:      Change reason — NIST GOVERN 6.2

        Returns:
            PolicyVersion record
        """
        content = policy_path.read_text(encoding="utf-8")
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Load and validate (will raise if invalid or tampered)
        policy = load_policy(policy_path)

        version = PolicyVersion(
            version_id   = f"{policy.name}@{policy.version}",
            name         = policy.name,
            content_hash = content_hash,
            activated_at = int(time.time()),
            activated_by = activated_by,
            comment      = comment,
            content      = content,
        )

        # Store content snapshot for diff
        snapshot_path = self.versions_dir / f"{content_hash[:12]}.yaml"
        if not snapshot_path.exists():
            snapshot_path.write_text(content, encoding="utf-8")

        # Append to history
        self._append(version)
        return version

    def get_history(self, name: Optional[str] = None) -> List[PolicyVersion]:
        """Return version history, optionally filtered by policy name."""
        history = []
        if not self._history_file.exists():
            return history

        for line in self._history_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                v = PolicyVersion(**d)
                if name is None or v.name == name:
                    history.append(v)
            except Exception:
                continue
        return history

    def get_at(self, timestamp: int, name: str) -> Optional[PolicyVersion]:
        """
        Return the policy version that was active at a given timestamp.
        Used for audit: "what policy was active when decision X was made?"
        """
        history = self.get_history(name=name)
        active = None
        for v in sorted(history, key=lambda x: x.activated_at):
            if v.activated_at <= timestamp:
                active = v
            else:
                break
        return active

    def diff(self, hash_a: str, hash_b: str) -> List[str]:
        """
        Line-diff between two policy versions.
        Returns list of diff lines (unified diff format).
        """
        import difflib

        content_a = self._load_snapshot(hash_a)
        content_b = self._load_snapshot(hash_b)

        if content_a is None or content_b is None:
            return ["[One or both versions not found in snapshot store]"]

        diff = list(difflib.unified_diff(
            content_a.splitlines(keepends=True),
            content_b.splitlines(keepends=True),
            fromfile=f"policy@{hash_a[:12]}",
            tofile=f"policy@{hash_b[:12]}",
        ))
        return diff

    def verify_current(self, policy_path: Path) -> tuple[bool, str]:
        """
        Verify a policy file matches its last recorded version.
        Returns (is_valid, message).
        """
        if not policy_path.exists():
            return False, f"Policy file not found: {policy_path}"

        content = policy_path.read_text(encoding="utf-8")
        current_hash = hashlib.sha256(content.encode()).hexdigest()

        history = self.get_history()
        if not history:
            return True, "No version history — first activation"

        last = sorted(history, key=lambda v: v.activated_at)[-1]

        if current_hash == last.content_hash:
            return True, f"Policy matches version {last.version_id}"
        else:
            return False, (
                f"Policy hash mismatch — file may have been modified outside versioning.\n"
                f"  Recorded hash : {last.content_hash[:16]}...\n"
                f"  Current hash  : {current_hash[:16]}...\n"
                f"  ANSSI R35: use activate() to record changes."
            )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _append(self, version: PolicyVersion) -> None:
        with self._history_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(version.to_dict(), sort_keys=True) + "\n")

    def _load_snapshot(self, content_hash: str) -> Optional[str]:
        snapshot = self.versions_dir / f"{content_hash[:12]}.yaml"
        if snapshot.exists():
            return snapshot.read_text(encoding="utf-8")
        # Try full hash
        for f in self.versions_dir.glob("*.yaml"):
            if f.stem == content_hash[:12]:
                return f.read_text(encoding="utf-8")
        return None
