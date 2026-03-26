# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
License System — PiQrypt v1.8.1

Architecture : local-first, offline après activation.

Validation :
  Free     → HMAC local, jamais de réseau
  Pro+     → JWT signé Ed25519 (clé publique embarquée)
             Réseau uniquement au renouvellement (1x/mois ou 1x/an)
             Grace period 72h si réseau indisponible

Format JWT (simplifié, sans dépendance externe) :
  header.payload.signature (base64url)
  Payload : tier, agents_max, events_month, features, issued_at, expires_at, license_id

Tiers :
  free       → 3 agents, 10k events/mois, HMAC offline
  pro        → 50 agents, 500k events/mois, JWT
  team       → 150 agents, 5M events/mois, JWT
  business   → 500 agents, 10M events/mois, JWT
  enterprise → illimité, JWT ou clé offline dédiée

IP : e-Soleau DSO2026006483 (INPI France — 19/02/2026)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Clé publique PiQrypt embarquée (Ed25519) ─────────────────────────────────
# Utilisée pour vérifier les JWT de licence offline.
# La clé privée correspondante ne quitte jamais api.piqrypt.com
# Remplacer par la vraie clé publique avant production.
_PIQRYPT_PUBLIC_KEY_B64 = ("YEBOYGhymhd2EjBcTGPpgSnq8//YCEmCdpnY86SIcP4="
      # Ed25519 public key — v1.7.1 — rotated 2026-03-22
)
# ⚠️  La clé PRIVÉE correspondante est stockée uniquement dans api.piqrypt.com
#     via la variable d'environnement PIQRYPT_LICENSE_SIGNING_KEY.
#     Ne jamais la committer. Rotation : bumper cette constante + redéployer.

# ── Constante HMAC pour Free tier (offline pur) ───────────────────────────────
_FREE_HMAC_SECRET = "piqrypt_free_v1_local_only"

# ── Grace period pour Pro+ si réseau indisponible ─────────────────────────────
GRACE_PERIOD_SECONDS = 72 * 3600  # 72 heures

# ── Répertoire de données ─────────────────────────────────────────────────────
_CONFIG_DIR = Path(os.getenv("PIQRYPT_HOME", str(Path.home() / ".piqrypt")))
_LICENSE_FILE = _CONFIG_DIR / "license.jwt"
_GRACE_FILE = _CONFIG_DIR / "license.grace"

# ── Dev mode : clé publique locale (generate_dev_licenses.py) ─────────────────
# Si dev_keypair.json est présent à la racine du projet OU dans PIQRYPT_HOME,
# la clé publique de dev est utilisée À LA PLACE de la clé de prod.
# Les tokens de dev contiennent "dev": true dans leur payload.
# En production (PIQRYPT_ENV=production), ce fallback est désactivé.
def _load_dev_public_key() -> Optional[str]:
    """Charge la clé publique de dev depuis dev_keypair.json si disponible."""
    if os.getenv("PIQRYPT_ENV", "").lower() == "production":
        return None  # jamais en prod

    candidates = [
        Path.cwd() / "dev_keypair.json",
        Path(__file__).resolve().parents[1] / "dev_keypair.json",  # racine repo
        _CONFIG_DIR / "dev_keypair.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text())
                pub = data.get("public", "")
                if pub:
                    import logging
                    logging.getLogger("piqrypt.license").debug(
                        "[license] DEV mode: using dev keypair from %s", path
                    )
                    return pub
            except Exception:
                pass
    return None

_DEV_PUBLIC_KEY_B64: Optional[str] = _load_dev_public_key()

def _get_active_public_key() -> str:
    """Retourne la clé publique active : dev si disponible, prod sinon."""
    return _DEV_PUBLIC_KEY_B64 or _PIQRYPT_PUBLIC_KEY_B64


# ══════════════════════════════════════════════════════════════════════════════
# TIERS — source unique de vérité pour quotas et features
# ══════════════════════════════════════════════════════════════════════════════

TIERS: Dict[str, Dict[str, Any]] = {
    # ── Free ─────────────────────────────────────────────────────────────────
    "free": {
        "agents_max":           3,
        "events_month":         10_000,
        "price_monthly":        0,
        "price_annual":         0,
        "quantum":              False,
        "tsa_rfc3161":          False,
        "pqz_certified":        False,
        "pqz_memory":           True,
        "vigil":                "full",     # Vigil fully functional (v1.7.1)
        "vigil_alerts_full":    False,      # CRITICAL only
        "vigil_vrs_days":       7,          # 7-day VRS history
        "vigil_bridge_limit":   2,          # max 2 bridge types
        "trustgate":            None,
        "team_workspace":       False,
        "multi_org":            False,
        "siem":                 False,
        "sso":                  False,
        "on_premise":           False,
        "api_rate_limit":       100,
        "support":              "community",
        "validation":           "hmac",
        "cert_simple_once":     True,   # 1 certification Simple offerte à l'activation
        "cert_timestamp_month": 0,
        "cert_pq_month":        0,
    },
    # ── Pro ──────────────────────────────────────────────────────────────────
    "pro": {
        "agents_max":           50,
        "events_month":         500_000,
        "price_monthly":        None,       # annual only
        "price_annual":         390,        # 290 early-bird
        "quantum":              True,
        "tsa_rfc3161":          True,
        "pqz_certified":        True,
        "pqz_memory":           True,
        "vigil":                "full",
        "vigil_alerts_full":    True,
        "vigil_vrs_days":       90,
        "vigil_bridge_limit":   None,       # unlimited
        "trustgate":            "manual",
        "team_workspace":       False,
        "multi_org":            False,
        "siem":                 False,
        "sso":                  False,
        "on_premise":           False,
        "api_rate_limit":       1_000,
        "support":              "email_48h",
        "validation":           "jwt",
        "cert_simple_month":    10,
        "cert_timestamp_month": 0,
        "cert_pq_month":        0,
    },
    # ── Startup ──────────────────────────────────────────────────────────────
    "startup": {
        "agents_max":           50,
        "events_month":         1_000_000,
        "price_monthly":        None,
        "price_annual":         990,
        "quantum":              True,
        "tsa_rfc3161":          True,
        "pqz_certified":        True,
        "pqz_memory":           True,
        "vigil":                "full",
        "vigil_alerts_full":    True,
        "vigil_vrs_days":       90,
        "vigil_bridge_limit":   None,
        "trustgate":            "manual",
        "team_workspace":       True,
        "multi_org":            False,
        "siem":                 False,
        "sso":                  False,
        "on_premise":           False,
        "api_rate_limit":       5_000,
        "support":              "email_24h",
        "validation":           "jwt",
        "cert_simple_month":    0,
        "cert_timestamp_month": 5,
        "cert_pq_month":        0,
    },
    # ── Team ─────────────────────────────────────────────────────────────────
    "team": {
        "agents_max":           150,
        "events_month":         5_000_000,
        "price_monthly":        None,
        "price_annual":         2_990,
        "quantum":              True,
        "tsa_rfc3161":          True,
        "pqz_certified":        True,
        "pqz_memory":           True,
        "vigil":                "full",
        "vigil_alerts_full":    True,
        "vigil_vrs_days":       90,
        "vigil_bridge_limit":   None,
        "trustgate":            "manual",
        "team_workspace":       True,
        "multi_org":            False,
        "siem":                 False,
        "sso":                  False,
        "on_premise":           False,
        "api_rate_limit":       10_000,
        "support":              "priority",
        "validation":           "jwt",
        "cert_simple_month":    0,
        "cert_timestamp_month": 10,
        "cert_pq_month":        0,
    },
    # ── Business ─────────────────────────────────────────────────────────────
    "business": {
        "agents_max":           500,
        "events_month":         20_000_000,
        "price_monthly":        None,
        "price_annual":         14_990,
        "quantum":              True,
        "tsa_rfc3161":          True,
        "pqz_certified":        True,
        "pqz_memory":           True,
        "vigil":                "full",
        "vigil_alerts_full":    True,
        "vigil_vrs_days":       90,
        "vigil_bridge_limit":   None,
        "trustgate":            "full",
        "team_workspace":       True,
        "multi_org":            True,
        "siem":                 True,
        "sso":                  False,
        "on_premise":           "option",
        "api_rate_limit":       100_000,
        "support":              "dedicated",
        "validation":           "jwt",
        "cert_simple_month":    0,
        "cert_timestamp_month": 0,
        "cert_pq_month":        5,
    },
    # ── Enterprise ───────────────────────────────────────────────────────────
    "enterprise": {
        "agents_max":           None,       # unlimited
        "events_month":         None,       # unlimited
        "price_monthly":        None,       # custom
        "price_annual":         None,       # custom
        "quantum":              True,
        "tsa_rfc3161":          True,
        "pqz_certified":        True,
        "pqz_memory":           True,
        "vigil":                "full",
        "vigil_alerts_full":    True,
        "vigil_vrs_days":       None,       # unlimited
        "vigil_bridge_limit":   None,
        "trustgate":            "full",
        "team_workspace":       True,
        "multi_org":            True,
        "siem":                 True,
        "sso":                  True,
        "on_premise":           True,
        "api_rate_limit":       None,       # unlimited
        "support":              "sla_dedicated",
        "validation":           "jwt",
        "cert_simple_month":    None,       # custom
        "cert_timestamp_month": None,
        "cert_pq_month":        None,
    },
}

# Ordre des tiers pour comparaisons
TIER_ORDER: List[str] = ["free", "pro", "startup", "team", "business", "enterprise"]


# ══════════════════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ══════════════════════════════════════════════════════════════════════════════

class LicenseError(Exception):
    """Erreur de licence."""
    pass


class FeatureNotAvailableError(LicenseError):
    """Feature non disponible sur ce tier."""

    def __init__(self, feature: str, current_tier: str, required_tier: str):
        self.feature = feature
        self.current_tier = current_tier
        self.required_tier = required_tier
        super().__init__(
            f"'{feature}' requires tier '{required_tier}' or higher.\n"
            f"Current tier: '{current_tier}'\n"
            f"Upgrade: https://piqrypt.com/pricing"
        )


class QuotaExceededError(LicenseError):
    """Quota dépassé."""

    def __init__(self, resource: str, used: int, limit: int, tier: str):
        self.resource = resource
        self.used = used
        self.limit = limit
        self.tier = tier
        super().__init__(
            f"Quota exceeded: {resource} ({used}/{limit} used, tier '{tier}').\n"
            f"Upgrade: https://piqrypt.com/pricing"
        )


class LicenseExpiredError(LicenseError):
    """Licence expirée."""
    pass


class LicenseInvalidError(LicenseError):
    """Licence invalide ou corrompue."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# JWT OFFLINE — vérification Ed25519 sans dépendance externe
# ══════════════════════════════════════════════════════════════════════════════

def _b64url_decode(s: str) -> bytes:
    """Décode base64url sans padding."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    """Encode base64url sans padding."""
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


def _verify_jwt_ed25519(token: str, public_key_b64: str) -> Dict[str, Any]:
    """
    Vérifie un JWT signé Ed25519 (algorithme EdDSA).
    Retourne le payload décodé si valide, lève LicenseInvalidError sinon.

    Local-first : zéro appel réseau, zéro dépendance externe.
    Utilise PyNaCl (déjà dans les dépendances de piqrypt).
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise LicenseInvalidError("Invalid JWT format")

        header_b64, payload_b64, sig_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode()
        signature = _b64url_decode(sig_b64)

        # Vérification Ed25519 via PyNaCl
        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError  # noqa: F401
            public_key_bytes = base64.b64decode(public_key_b64)
            vk = VerifyKey(public_key_bytes)
            vk.verify(message, signature)
        except ImportError:
            # Fallback : cryptography library
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            public_key_bytes = base64.b64decode(public_key_b64)
            # Raw Ed25519 public key (32 bytes)
            pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            try:
                pk.verify(signature, message)
            except InvalidSignature:
                raise LicenseInvalidError("JWT signature verification failed")

        # Décoder le payload
        payload = json.loads(_b64url_decode(payload_b64))
        return payload

    except LicenseInvalidError:
        raise
    except Exception as e:
        raise LicenseInvalidError(f"JWT verification error: {e}")


def _verify_hmac_free(token: str) -> Dict[str, Any]:
    """
    Vérifie un token Free tier (HMAC-SHA256 local).
    Format : free.<license_id>.<hmac8>
    """
    try:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "free":
            raise LicenseInvalidError("Invalid Free token format")

        license_id = parts[1]
        provided_hmac = parts[2]

        expected = hmac.new(
            _FREE_HMAC_SECRET.encode(),
            f"free:{license_id}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        if not hmac.compare_digest(provided_hmac, expected):
            raise LicenseInvalidError("Free token HMAC mismatch")

        return {
            "tier": "free",
            "license_id": license_id,
            "agents_max": TIERS["free"]["agents_max"],
            "events_month": TIERS["free"]["events_month"],
            "expires_at": None,  # Free = pas d'expiration
        }
    except LicenseInvalidError:
        raise
    except Exception as e:
        raise LicenseInvalidError(f"Free token error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE LICENSE
# ══════════════════════════════════════════════════════════════════════════════

class License:
    """
    Objet de licence PiQrypt — source unique de vérité pour features et quotas.

    Usage :
        lic = License()
        lic.require("quantum")            # lève FeatureNotAvailableError si absent
        lic.check_quota("agents", 45)     # lève QuotaExceededError si dépassé
        lic.tier                          # "free" | "pro" | "team" | "business" | "enterprise"
        lic.features                      # dict complet des features du tier
    """

    def __init__(self):
        self._payload: Optional[Dict[str, Any]] = None
        self._tier: str = "free"
        self._loaded_at: float = 0.0
        self._load()

    # ── Chargement ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Charge et vérifie la licence depuis env var ou fichier."""

        # Priorité 1 : variable d'environnement
        token = (
            os.getenv("PIQRYPT_LICENSE_KEY") or
            os.getenv("AISS2_LICENSE_KEY")  # compat legacy
        )

        # Priorité 2 : fichier
        if not token and _LICENSE_FILE.exists():
            try:
                token = _LICENSE_FILE.read_text().strip()
            except OSError:
                pass

        if not token:
            self._tier = "free"
            self._payload = self._default_free_payload()
            return

        try:
            payload = self._verify_token(token)
            self._payload = payload
            self._tier = payload.get("tier", "free")
            self._loaded_at = time.time()

            # Vérifier expiration
            expires_at = payload.get("expires_at")
            if expires_at and time.time() > expires_at:
                self._handle_expired(expires_at)

        except LicenseInvalidError:
            # Token invalide → Free tier, ne pas planter
            self._tier = "free"
            self._payload = self._default_free_payload()

    def _verify_token(self, token: str) -> Dict[str, Any]:
        """Dispatch vers la méthode de vérification appropriée."""
        if token.startswith("free."):
            return _verify_hmac_free(token)
        else:
            # JWT Ed25519 — Pro et au-dessus
            # En dev: utilise la clé de dev_keypair.json si présente
            payload = _verify_jwt_ed25519(token, _get_active_public_key())
            # Vérifier que les tokens de dev ne passent pas en prod
            if payload.get("dev") and os.getenv("PIQRYPT_ENV", "").lower() == "production":
                raise LicenseInvalidError(
                    "Dev tokens are not valid in production. "
                    "Set PIQRYPT_ENV=production to enforce this check."
                )
            return payload

    def _handle_expired(self, expires_at: float) -> None:
        """
        Gestion de l'expiration avec grace period (72h).
        Après grace period → retour au Free tier (jamais de blocage brutal).
        """
        grace_end = expires_at + GRACE_PERIOD_SECONDS
        if time.time() < grace_end:
            # Dans la grace period : conserver le tier avec warning
            remaining_h = int((grace_end - time.time()) / 3600)
            import warnings
            warnings.warn(
                f"PiQrypt licence expired. Grace period: {remaining_h}h remaining.\n"
                f"Renew at: https://piqrypt.com/account",
                UserWarning,
                stacklevel=4,
            )
            # Sauvegarder timestamp grace pour suivi
            try:
                _GRACE_FILE.write_text(str(expires_at))
            except OSError:
                pass
        else:
            # Grace period terminée → Free tier
            self._tier = "free"
            self._payload = self._default_free_payload()

    def _default_free_payload(self) -> Dict[str, Any]:
        return {
            "tier": "free",
            "license_id": "free_local",
            "agents_max": TIERS["free"]["agents_max"],
            "events_month": TIERS["free"]["events_month"],
            "expires_at": None,
        }

    # ── Propriétés ──────────────────────────────────────────────────────────

    @property
    def tier(self) -> str:
        return self._tier

    @property
    def features(self) -> Dict[str, Any]:
        return TIERS.get(self._tier, TIERS["free"]).copy()

    @property
    def license_id(self) -> str:
        return (self._payload or {}).get("license_id", "free_local")

    @property
    def expires_at(self) -> Optional[datetime]:
        ts = (self._payload or {}).get("expires_at")
        if ts:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        return None

    @property
    def agents_max(self) -> Optional[int]:
        """None = illimité (Enterprise)."""
        return TIERS.get(self._tier, TIERS["free"])["agents_max"]

    @property
    def events_month(self) -> Optional[int]:
        """None = illimité (Enterprise)."""
        return TIERS.get(self._tier, TIERS["free"])["events_month"]

    # ── Vérifications ────────────────────────────────────────────────────────

    def has_feature(self, feature: str) -> bool:
        """
        Vérifie si une feature est disponible sur le tier actuel.

        Features : quantum, tsa_rfc3161, pqz_certified, pqz_memory,
                   vigil (none/readonly/full), trustgate (none/manual/full),
                   multi_org, siem, sso, on_premise
        """
        tier_cfg = TIERS.get(self._tier, TIERS["free"])
        value = tier_cfg.get(feature)

        # Booléen simple
        if isinstance(value, bool):
            return value

        # None = absent
        if value is None or value == "none":
            return False

        # Chaîne non vide = présent
        if isinstance(value, str):
            return True

        return bool(value)

    def get_feature_level(self, feature: str) -> Any:
        """Retourne le niveau d'une feature (ex: trustgate → 'manual'|'full'|None)."""
        return TIERS.get(self._tier, TIERS["free"]).get(feature)

    def require(self, feature: str, min_tier: Optional[str] = None) -> None:
        """
        Lève FeatureNotAvailableError si la feature est absente.

        Args:
            feature:  Nom de la feature (cf. TIERS)
            min_tier: Tier minimum requis (calculé automatiquement si None)

        Example:
            lic.require("quantum")        # lève si pas Pro+
            lic.require("trustgate")      # lève si Free
            lic.require("sso")            # lève si pas Enterprise
        """
        if self.has_feature(feature):
            return

        # Calculer le tier minimum requis pour cette feature
        if min_tier is None:
            for t in TIER_ORDER:
                if TIERS[t].get(feature):
                    min_tier = t
                    break
            min_tier = min_tier or "enterprise"

        raise FeatureNotAvailableError(feature, self._tier, min_tier)

    def require_trustgate(self, level: str = "manual") -> None:
        """
        Vérifie que TrustGate est disponible au niveau requis.

        Args:
            level: "manual" | "full"
        """
        current = self.get_feature_level("trustgate")
        level_order = {None: 0, "manual": 1, "full": 2}

        if level_order.get(current, 0) < level_order.get(level, 1):
            required_tier = next(
                (t for t in TIER_ORDER
                 if level_order.get(TIERS[t].get("trustgate"), 0) >= level_order[level]),
                "enterprise"
            )
            raise FeatureNotAvailableError(
                f"trustgate:{level}", self._tier, required_tier
            )

    def check_quota(self, resource: str, current_count: int,
                    warn_at: float = 0.8) -> None:
        """
        Vérifie un quota. Alerte à 80%, bloque à 100%.
        Jamais d'upgrade automatique — alerte uniquement.

        Args:
            resource:      "agents" | "events_month"
            current_count: Valeur actuelle
            warn_at:       Seuil d'alerte (0.0–1.0, défaut 80%)

        Raises:
            QuotaExceededError: Si current_count >= limite
        """
        limit_key = "agents_max" if resource == "agents" else resource
        limit = TIERS.get(self._tier, TIERS["free"]).get(limit_key)

        # illimité (Enterprise)
        if limit is None:
            return

        if current_count >= limit:
            raise QuotaExceededError(resource, current_count, limit, self._tier)

        if current_count >= limit * warn_at:
            import warnings
            pct = int(current_count / limit * 100)
            warnings.warn(
                f"PiQrypt quota warning: {resource} at {pct}% ({current_count}/{limit}, "
                f"tier '{self._tier}'). Consider upgrading: https://piqrypt.com/pricing",
                UserWarning,
                stacklevel=3,
            )

    def is_tier_or_above(self, min_tier: str) -> bool:
        """Vérifie si le tier actuel est >= min_tier."""
        try:
            return TIER_ORDER.index(self._tier) >= TIER_ORDER.index(min_tier)
        except ValueError:
            return False

    # ── Activation ──────────────────────────────────────────────────────────

    def activate(self, token: str) -> bool:
        """
        Active une licence depuis un token JWT (Pro+) ou Free token.

        Args:
            token: JWT Ed25519 (Pro+) ou token Free (free.<id>.<hmac>)

        Returns:
            True si activation réussie
        """
        try:
            payload = self._verify_token(token)

            # Vérifier expiration
            expires_at = payload.get("expires_at")
            if expires_at and time.time() > expires_at:
                raise LicenseExpiredError(
                    "This license token has expired. "
                    "Please renew at https://piqrypt.com/account"
                )

            # Sauvegarder
            _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            _LICENSE_FILE.write_text(token)

            # Recharger
            self._payload = payload
            self._tier = payload.get("tier", "free")
            self._loaded_at = time.time()

            return True

        except (LicenseExpiredError, LicenseInvalidError):
            raise
        except Exception as e:
            raise LicenseInvalidError(f"Activation failed: {e}")

    def deactivate(self) -> None:
        """Désactive la licence — retour au Free tier."""
        if _LICENSE_FILE.exists():
            _LICENSE_FILE.unlink()
        if _GRACE_FILE.exists():
            _GRACE_FILE.unlink()
        self._tier = "free"
        self._payload = self._default_free_payload()
        self._loaded_at = 0.0

    # ── Info ─────────────────────────────────────────────────────────────────

    def info(self) -> Dict[str, Any]:
        """Retourne un résumé complet de la licence."""
        tier_cfg = TIERS.get(self._tier, TIERS["free"])
        return {
            "tier":          self._tier,
            "license_id":    self.license_id,
            "agents_max":    self.agents_max,
            "events_month":  self.events_month,
            "expires_at":    self.expires_at.isoformat() if self.expires_at else None,
            "features":      {k: v for k, v in tier_cfg.items()
                              if k not in ("price_monthly", "price_annual", "validation")},
            "validation":    tier_cfg.get("validation"),
            "local_first":   True,  # Toujours — zéro réseau sauf renouvellement
        }

    def __repr__(self) -> str:
        return f"License(tier={self._tier!r}, id={self.license_id!r})"


# ══════════════════════════════════════════════════════════════════════════════
# INSTANCE GLOBALE + API PUBLIQUE
# ══════════════════════════════════════════════════════════════════════════════

_license = License()


def get_license() -> License:
    """Retourne l'instance de licence globale."""
    return _license


def get_tier() -> str:
    """Retourne le tier actuel : free | pro | team | business | enterprise"""
    return _license.tier


def is_paid() -> bool:
    """True si tier Pro ou supérieur."""
    return _license.is_tier_or_above("pro")


def require(feature: str) -> None:
    """Lève FeatureNotAvailableError si feature absente."""
    _license.require(feature)


def require_pro(feature_name: str = "This feature"):
    """
    Décorateur de compatibilité v1.6 — require Pro minimum.

    Usage :
        @require_pro("Trusted timestamps")
        def stamp_with_tsa(...): ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not _license.is_tier_or_above("pro"):
                raise FeatureNotAvailableError(feature_name, _license.tier, "pro")
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        wrapper.__doc__  = func.__doc__
        return wrapper
    return decorator


def activate_license(token: str) -> bool:
    """Active une licence."""
    return _license.activate(token)


def deactivate_license() -> None:
    """Désactive la licence."""
    _license.deactivate()


def get_license_info() -> Dict[str, Any]:
    """Retourne les infos de licence."""
    return _license.info()


def check_quota(resource: str, current_count: int) -> None:
    """Vérifie un quota (agents ou events_month)."""
    _license.check_quota(resource, current_count)


# ── Public API ────────────────────────────────────────────────────────────────
__all__ = [
    # Classes
    "License",
    "TIERS",
    "TIER_ORDER",
    # Exceptions
    "LicenseError",
    "FeatureNotAvailableError",
    "QuotaExceededError",
    "LicenseExpiredError",
    "LicenseInvalidError",
    # Fonctions
    "get_license",
    "get_tier",
    "is_paid",
    "require",
    "require_pro",
    "activate_license",
    "deactivate_license",
    "get_license_info",
    "check_quota",
]


# Aliases de compatibilite v1.6 -> v1.7
def is_pro() -> bool:
    """Alias - use is_paid() in v1.7+"""
    return is_paid()


def is_oss() -> bool:
    """True if Free tier."""
    return _license.tier == "free"


