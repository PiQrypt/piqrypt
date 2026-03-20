# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
human_principal.py — Trust Gate Human Principal

A Human Principal is an AISS identity carried by a human.
Same cryptography as an agent — different role and permissions.

Phase 1 (MVP): SSO token + Trust Gate internal signature
Phase 2 (upgrade): Full Ed25519 keypair per human — Human Principal AISS

The Human Principal signs governance decisions.
His signature is the cryptographic proof of human oversight.

Compliance:
    ANSSI R9   — human approval signature + justification
    ANSSI R30  — privileged access control with clearance levels
    AI Act Art.14 — natural person oversight, always available
    NIST GOVERN 1.2 — accountability structures with named principals
    NIST MANAGE 2.2 — human oversight mechanism

Clearance levels:
    L1 — Operator  : can approve REQUIRE_HUMAN for VRS < 0.75
    L2 — Senior    : can approve REQUIRE_HUMAN for VRS < 0.90
    L3 — Admin     : can approve any decision, modify policies

SSO Phase 1:
    Authentication via external SSO (Azure AD / Okta / Google Workspace)
    Trust Gate issues an internal signed token on successful SSO auth
    Decision signature = Trust Gate signs on behalf of authenticated principal

AISS Phase 2 (future):
    Each principal has a personal Ed25519 keypair in KeyStore
    Decision signature = principal's own private key
    Upgrade path: call upgrade_to_aiss() on existing principal
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, List

# PiQrypt integration
try:
    from aiss.key_store import encrypt_private_key
    from aiss.crypto.ed25519 import generate_keypair, sign
    from aiss.identity import derive_agent_id
    _AISS_AVAILABLE = True
except ImportError:
    _AISS_AVAILABLE = False


# ─── Constants ────────────────────────────────────────────────────────────────

CLEARANCE_LEVELS = ("L1", "L2", "L3")
CLEARANCE_VRS_LIMITS = {
    "L1": 0.75,    # can approve VRS up to 0.75
    "L2": 0.90,    # can approve VRS up to 0.90
    "L3": 1.00,    # can approve anything
}

DEFAULT_PRINCIPALS_DIR = Path.home() / ".piqrypt" / "trustgate" / "principals"

# ─── Exceptions ───────────────────────────────────────────────────────────────

class PrincipalNotFoundError(Exception):
    pass

class InsufficientClearanceError(Exception):
    """Principal clearance too low for this decision. ANSSI R30."""
    pass

class PrincipalLockedError(Exception):
    """Principal session not open — key not in RAM."""
    pass

class SSOAuthenticationError(Exception):
    """SSO authentication failed."""
    pass


# ─── Principal record ─────────────────────────────────────────────────────────

@dataclass
class PrincipalRecord:
    """
    Persistent metadata for a Human Principal.
    Stored as JSON in principals_dir/<name>/principal.json
    """
    principal_id:   str
    name:           str
    email:          str
    clearance:      str        # L1 | L2 | L3
    mode:           str        # "sso" | "aiss"
    created_at:     int
    created_by:     str        # admin principal_id or "bootstrap"
    active:         bool       = True
    last_login:     Optional[int] = None

    # SSO Phase 1
    sso_provider:   Optional[str] = None   # "azure_ad" | "okta" | "google"
    sso_subject:    Optional[str] = None   # external SSO subject/sub claim

    # AISS Phase 2
    aiss_agent_id:  Optional[str] = None   # if upgraded to AISS keypair

    def to_dict(self) -> dict:
        return asdict(self)

    def can_approve_vrs(self, vrs: float) -> bool:
        limit = CLEARANCE_VRS_LIMITS.get(self.clearance, 0.0)
        return vrs <= limit


# ─── SSO Token (Phase 1) ──────────────────────────────────────────────────────

@dataclass
class SSOToken:
    """
    Internal token issued by Trust Gate after SSO authentication.
    Signed by Trust Gate's internal key — not the principal's personal key.

    Phase 1: this token IS the proof of human oversight.
    Phase 2: replaced by principal's personal Ed25519 signature.
    """
    token_id:       str = field(default_factory=lambda: str(uuid.uuid4()))
    principal_id:   str = ""
    principal_name: str = ""
    clearance:      str = "L1"
    issued_at:      int = field(default_factory=lambda: int(time.time()))
    expires_at:     int = 0
    sso_provider:   str = ""
    sso_subject:    str = ""

    # HMAC-SHA256 of token content — signed by Trust Gate
    # In production: replace with Ed25519 using TrustGate's own keypair
    token_hash:     str = ""

    def is_valid(self) -> bool:
        return (
            self.active
            and int(time.time()) < self.expires_at
            and self.token_hash != ""
        )

    @property
    def active(self) -> bool:
        return int(time.time()) < self.expires_at

    def compute_hash(self, secret: bytes) -> str:
        import hmac
        content = json.dumps({
            "token_id":     self.token_id,
            "principal_id": self.principal_id,
            "clearance":    self.clearance,
            "issued_at":    self.issued_at,
            "expires_at":   self.expires_at,
        }, sort_keys=True).encode()
        return hmac.new(secret, content, hashlib.sha256).hexdigest()


# ─── Human Principal ──────────────────────────────────────────────────────────

class HumanPrincipal:
    """
    Human identity for governance approvals.

    Phase 1 (SSO):
        - Authenticated via external SSO
        - Decisions signed by Trust Gate on behalf of principal
        - principal_id + token_id recorded in Decision

    Phase 2 (AISS):
        - Personal Ed25519 keypair in encrypted KeyStore
        - Decisions signed by principal's own private key
        - Cryptographically non-repudiable

    Usage (Phase 1 — SSO):
        principal = HumanPrincipal.load("alice", principals_dir)
        token = principal.authenticate_sso(sso_token_from_provider)
        signature = principal.sign_decision(decision_id, "APPROVE", token, justification="OK")

    Usage (Phase 2 — AISS):
        principal = HumanPrincipal.load("alice", principals_dir)
        with principal.open_session(passphrase="...") as session:
            signature = principal.sign_decision_aiss(decision_id, "APPROVE", session)
    """

    def __init__(
        self,
        record: PrincipalRecord,
        principals_dir: Path = DEFAULT_PRINCIPALS_DIR,
    ):
        self.record         = record
        self.principals_dir = principals_dir
        self._session_open  = False
        self._private_key   = None   # in RAM only during AISS session

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        name: str,
        email: str,
        clearance: str,
        mode: str = "sso",
        created_by: str = "bootstrap",
        sso_provider: Optional[str] = None,
        sso_subject: Optional[str] = None,
        principals_dir: Path = DEFAULT_PRINCIPALS_DIR,
        passphrase: Optional[str] = None,   # required for mode="aiss"
    ) -> "HumanPrincipal":
        """
        Create a new Human Principal.

        Args:
            name:         Unique name (slug format: alice, bob_admin)
            email:        Email address — used in audit records
            clearance:    L1 | L2 | L3
            mode:         "sso" (Phase 1) | "aiss" (Phase 2)
            created_by:   principal_id of the creator (audit trail)
            sso_provider: "azure_ad" | "okta" | "google" (for mode=sso)
            sso_subject:  External SSO subject claim (for mode=sso)
            passphrase:   Required for mode=aiss — encrypts keypair
        """
        if clearance not in CLEARANCE_LEVELS:
            raise ValueError(f"clearance must be one of {CLEARANCE_LEVELS}")
        if mode not in ("sso", "aiss"):
            raise ValueError("mode must be 'sso' or 'aiss'")
        if mode == "aiss" and not passphrase:
            raise ValueError("passphrase required for mode='aiss'")

        principal_id = f"PRINCIPAL-{uuid.uuid4().hex[:12].upper()}"

        record = PrincipalRecord(
            principal_id = principal_id,
            name         = name,
            email        = email,
            clearance    = clearance,
            mode         = mode,
            created_at   = int(time.time()),
            created_by   = created_by,
            sso_provider = sso_provider,
            sso_subject  = sso_subject,
        )

        principal = cls(record, principals_dir)
        principal_dir = principals_dir / name
        principal_dir.mkdir(parents=True, exist_ok=True)

        # Phase 2 — generate keypair if AISS mode
        if mode == "aiss" and _AISS_AVAILABLE:
            priv, pub = generate_keypair()
            agent_id  = derive_agent_id(pub)
            record.aiss_agent_id = agent_id

            # Encrypt keypair using PiQrypt KeyStore
            key_path = principal_dir / "principal.key.enc"
            encrypt_private_key(priv, passphrase=passphrase, path=key_path)

            # Store public key
            (principal_dir / "principal.pub").write_bytes(pub)

        # Persist record
        principal._save_record()
        return principal

    @classmethod
    def load(
        cls,
        name: str,
        principals_dir: Path = DEFAULT_PRINCIPALS_DIR,
    ) -> "HumanPrincipal":
        """Load an existing principal by name."""
        record_path = principals_dir / name / "principal.json"
        if not record_path.exists():
            raise PrincipalNotFoundError(f"Principal '{name}' not found at {record_path}")

        data   = json.loads(record_path.read_text(encoding="utf-8"))
        record = PrincipalRecord(**data)
        return cls(record, principals_dir)

    @classmethod
    def list_all(
        cls,
        principals_dir: Path = DEFAULT_PRINCIPALS_DIR,
    ) -> List["HumanPrincipal"]:
        """List all registered principals."""
        if not principals_dir.exists():
            return []
        principals = []
        for d in sorted(principals_dir.iterdir()):
            if d.is_dir() and (d / "principal.json").exists():
                try:
                    principals.append(cls.load(d.name, principals_dir))
                except Exception:
                    continue
        return principals

    # ── SSO Phase 1 — authentication ──────────────────────────────────────────

    def authenticate_sso(
        self,
        sso_claims: dict,
        ttl_seconds: int = 3600,
        secret: bytes = b"trustgate-internal-secret",
    ) -> SSOToken:
        """
        Phase 1: authenticate principal via SSO claims.

        In production, sso_claims come from the validated JWT from
        Azure AD / Okta / Google Workspace — already verified upstream.

        Returns a Trust Gate internal SSOToken.
        """
        if not self.record.active:
            raise SSOAuthenticationError(f"Principal '{self.record.name}' is inactive")

        # Verify SSO subject matches recorded subject
        if self.record.sso_subject:
            incoming_sub = sso_claims.get("sub", sso_claims.get("oid", ""))
            if incoming_sub and incoming_sub != self.record.sso_subject:
                raise SSOAuthenticationError(
                    f"SSO subject mismatch for '{self.record.name}'"
                )

        now   = int(time.time())
        token = SSOToken(
            principal_id   = self.record.principal_id,
            principal_name = self.record.name,
            clearance      = self.record.clearance,
            issued_at      = now,
            expires_at     = now + ttl_seconds,
            sso_provider   = self.record.sso_provider or "unknown",
            sso_subject    = sso_claims.get("sub", ""),
        )
        token.token_hash = token.compute_hash(secret)

        # Update last_login
        self.record.last_login = now
        self._save_record()

        return token

    # ── Decision signing — Phase 1 (SSO) ─────────────────────────────────────

    def sign_decision_sso(
        self,
        decision_id: str,
        outcome: str,              # "APPROVED" | "REJECTED"
        token: SSOToken,
        justification: str = "",
        secret: bytes = b"trustgate-internal-secret",
    ) -> bytes:
        """
        Phase 1: sign a governance decision using SSO token.

        The "signature" is an HMAC-SHA256 of the decision content,
        using Trust Gate's internal secret. It proves:
        - The decision was made by a specific authenticated principal
        - At a specific time
        - For a specific decision_id

        Returns bytes — stored in Decision.approval_signature

        Compliance: AI Act Art.14 — human oversight documented
        """
        if not token.is_valid():
            raise SSOAuthenticationError("SSO token expired or invalid")
        if token.principal_id != self.record.principal_id:
            raise SSOAuthenticationError("Token does not belong to this principal")

        import hmac
        content = json.dumps({
            "decision_id":   decision_id,
            "outcome":       outcome,
            "principal_id":  self.record.principal_id,
            "clearance":     self.record.clearance,
            "token_id":      token.token_id,
            "timestamp":     int(time.time()),
            "justification": justification,
        }, sort_keys=True).encode()

        signature = hmac.new(secret, content, hashlib.sha256).digest()
        return signature

    # ── Decision signing — Phase 2 (AISS) ────────────────────────────────────

    def open_session(self, passphrase: str) -> "HumanPrincipal":
        """
        Phase 2: open AISS session — load private key into RAM.
        Use as context manager for guaranteed cleanup.
        """
        if self.record.mode != "aiss":
            raise ValueError("open_session() requires mode='aiss'")
        if not _AISS_AVAILABLE:
            raise RuntimeError("AISS not available — install piqrypt core")

        key_path = self.principals_dir / self.record.name / "principal.key.enc"
        from aiss.key_store import decrypt_private_key
        self._private_key = decrypt_private_key(passphrase=passphrase, path=key_path)
        self._session_open = True
        return self

    def lock(self) -> None:
        """Phase 2: close session — erase private key from RAM."""
        if self._private_key:
            if isinstance(self._private_key, bytearray):
                for i in range(len(self._private_key)):
                    self._private_key[i] = 0
            self._private_key = None
        self._session_open = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.lock()

    def sign_decision_aiss(
        self,
        decision_id: str,
        outcome: str,
        justification: str = "",
    ) -> bytes:
        """
        Phase 2: sign a governance decision with principal's own Ed25519 key.
        Cryptographically non-repudiable.

        Compliance: AI Act Art.14 — human oversight, verifiable signature
        """
        if not self._session_open or not self._private_key:
            raise PrincipalLockedError(
                "Session not open. Use open_session() or context manager."
            )

        content = json.dumps({
            "decision_id":   decision_id,
            "outcome":       outcome,
            "principal_id":  self.record.principal_id,
            "clearance":     self.record.clearance,
            "timestamp":     int(time.time()),
            "justification": justification,
        }, sort_keys=True).encode()

        return sign(self._private_key, content)

    # ── Clearance checks ──────────────────────────────────────────────────────

    def can_approve(self, vrs: float) -> bool:
        """
        Check if this principal has sufficient clearance to approve
        a decision with the given VRS score. ANSSI R30.
        """
        if not self.record.active:
            return False
        return self.record.can_approve_vrs(vrs)

    def assert_can_approve(self, vrs: float) -> None:
        """Raise InsufficientClearanceError if principal cannot approve."""
        if not self.can_approve(vrs):
            limit = CLEARANCE_VRS_LIMITS.get(self.record.clearance, 0.0)
            raise InsufficientClearanceError(
                f"Principal '{self.record.name}' (clearance={self.record.clearance}) "
                f"cannot approve decision with VRS={vrs:.3f} "
                f"(limit for {self.record.clearance}={limit}). "
                f"Requires L2 or L3 clearance. — ANSSI R30"
            )

    # ── Admin ─────────────────────────────────────────────────────────────────

    def deactivate(self) -> None:
        """Deactivate principal — all future authentications rejected."""
        self.record.active = False
        self._save_record()

    def reactivate(self) -> None:
        self.record.active = True
        self._save_record()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _save_record(self) -> None:
        principal_dir = self.principals_dir / self.record.name
        principal_dir.mkdir(parents=True, exist_ok=True)
        record_path = principal_dir / "principal.json"
        record_path.write_text(
            json.dumps(self.record.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8"
        )

    def __repr__(self) -> str:
        return (
            f"HumanPrincipal(name={self.record.name!r}, "
            f"clearance={self.record.clearance!r}, "
            f"mode={self.record.mode!r}, "
            f"active={self.record.active})"
        )
