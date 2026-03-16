"""
auth_middleware.py — PiQrypt Authentication & Feature Gating
=============================================================

Partagé par vigil_server.py et trustgate_server.py.

Usage :
    from auth_middleware import AuthMiddleware, require_auth, require_tier

Authentification :
    Bearer token via env var VIGIL_TOKEN ou TRUSTGATE_TOKEN.
    Si la variable n'est pas définie → warning au démarrage, accès refusé.
    Le token est vérifié sur toutes les routes sauf /health et /api/ping.

Feature gating par tier (source : aiss/license.py → TIERS) :
    Free       → Vigil lecture seule, TrustGate absent
    Pro        → Vigil complet, TrustGate manuel
    Team       → Vigil complet, TrustGate manuel
    Business   → Vigil complet + SIEM, TrustGate complet
    Enterprise → Tout, illimité

Routes publiques (pas d'auth requise) :
    /health
    /api/ping
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("piqrypt.auth")

# Timestamp de démarrage du serveur — exposé dans tier_info pour l'uptime dashboard
_SERVER_START_TS: float = time.time()

# ── Routes exemptées d'authentification ──────────────────────────────────────
PUBLIC_ROUTES = {"/health", "/api/ping"}

# ── Feature gating par service ────────────────────────────────────────────────
# Vigil
#
# Politique Free (v1.7.1) :
#   - record        : True  → les bridges fonctionnent dès Free (adoption)
#   - alerts        : True  → alertes CRITICAL uniquement (voir _api_alerts)
#   - export_pdf    : True  → PDF basique non certifié (rapport local)
#   - export_pqz    : False → archives certifiées Pro+
#   - full_vrs      : False → historique VRS 7j Free / 90j Pro+
#   - bridge_limit  : 2     → 2 bridges max en Free (anti abus prod)
#
VIGIL_TIER_FEATURES = {
    "free": {
        "record":       True,   # bridges → Vigil fonctionnel en Free
        "alerts":       True,   # CRITICAL seulement (filtré dans _api_alerts)
        "export_pdf":   True,   # rapport local non certifié
        "export_pqz":   False,  # archives certifiées → Pro+
        "full_vrs":     False,  # historique 7j seulement
        "bridge_limit": 2,      # 2 bridges max
    },
    "pro": {
        "record":       True,
        "alerts":       True,   # tous niveaux + filtres
        "export_pdf":   True,
        "export_pqz":   True,   # .pqz cert + memory
        "full_vrs":     True,   # historique 90j
        "bridge_limit": None,   # illimité
    },
    "startup": {
        "record":       True,
        "alerts":       True,
        "export_pdf":   True,
        "export_pqz":   True,
        "full_vrs":     True,   # historique 90j
        "bridge_limit": None,   # illimité
    },
    "team": {
        "record":       True,
        "alerts":       True,
        "export_pdf":   True,
        "export_pqz":   True,
        "full_vrs":     True,
        "bridge_limit": None,
    },
    "business": {
        "record":       True,
        "alerts":       True,
        "export_pdf":   True,
        "export_pqz":   True,
        "full_vrs":     True,
        "bridge_limit": None,
    },
    "enterprise": {
        "record":       True,
        "alerts":       True,
        "export_pdf":   True,
        "export_pqz":   True,
        "full_vrs":     True,
        "bridge_limit": None,
    },
}

# TrustGate — None = absent, "manual" = file d'attente humaine, "full" = politiques automatiques
TRUSTGATE_TIER_LEVEL = {
    "free":       None,
    "pro":        "manual",
    "startup":    "manual",
    "team":       "manual",
    "business":   "full",
    "enterprise": "full",
}

# Message affiché quand une feature est bloquée par le tier
UPGRADE_MSG = {
    "vigil_export_pqz": (
        "Les exports .pqz certifiés nécessitent le tier Pro ou supérieur. "
        "Le rapport PDF local est disponible gratuitement. "
        "Passez à Pro pour les archives certifiées (pqz-cert, pqz-memory). "
        "https://piqrypt.com/pricing"
    ),
    "vigil_readonly": (
        "Vigil est en mode lecture seule sur le tier Free. "
        "Passez à Pro pour les exports, alertes et enregistrement en temps réel. "
        "https://piqrypt.com/pricing"
    ),
    "trustgate_unavailable": (
        "TrustGate n'est pas disponible sur le tier Free. "
        "Disponible à partir du tier Pro (validation manuelle) "
        "et Business (politiques automatiques). "
        "https://piqrypt.com/pricing"
    ),
    "trustgate_manual_only": (
        "TrustGate est en mode manuel sur ce tier (Pro/Team). "
        "Les politiques automatiques sont disponibles à partir du tier Business. "
        "https://piqrypt.com/pricing"
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# AUTH MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

class AuthMiddleware:
    """
    Middleware d'authentification et de feature gating pour Vigil et TrustGate.

    Usage dans un BaseHTTPRequestHandler :

        class MyHandler(BaseHTTPRequestHandler):
            _auth = AuthMiddleware("VIGIL_TOKEN", service="vigil")

            def do_GET(self):
                if not self._auth.check(self):
                    return  # 401 déjà envoyé
                if not self._auth.check_feature(self, "exports"):
                    return  # 403 déjà envoyé
                # ... logique normale
    """

    def __init__(self, env_var: str, service: str = "vigil"):
        """
        Args:
            env_var: Nom de la variable d'environnement contenant le token
                     (ex: "VIGIL_TOKEN", "TRUSTGATE_TOKEN")
            service: "vigil" | "trustgate" — détermine le feature gating
        """
        self.env_var  = env_var
        self.service  = service
        self.token    = os.getenv(env_var, "").strip()
        self._tier_cache: Optional[str] = None

        if not self.token:
            log.warning(
                "⚠️  %s non défini — toutes les requêtes seront refusées (401). "
                "Définissez la variable d'environnement avant de démarrer le serveur. "
                "Exemple : export %s=votre_token_secret",
                env_var, env_var
            )
        else:
            log.info("✅ Auth activée via %s (%d caractères)", env_var, len(self.token))

    # ── Tier courant ──────────────────────────────────────────────────────────

    def _get_tier(self) -> str:
        """Récupère le tier depuis license.py — avec cache en mémoire."""
        if self._tier_cache is not None:
            return self._tier_cache
        try:
            # Import relatif depuis la racine du projet
            import sys
            from pathlib import Path
            root = Path(__file__).resolve().parent
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from aiss.license import get_tier
            self._tier_cache = get_tier()
        except Exception:
            try:
                from aiss.license import get_tier
                self._tier_cache = get_tier()
            except Exception:
                self._tier_cache = "free"
        return self._tier_cache

    def invalidate_tier_cache(self) -> None:
        """Force le rechargement du tier (après activation d'une licence)."""
        self._tier_cache = None
        # Forcer le rechargement du module license pour prendre en compte
        # un nouveau token activé sans redémarrer le serveur.
        try:
            import importlib
            import aiss.license as _lic_mod
            importlib.reload(_lic_mod)
            log.info("[auth] License module reloaded — tier cache cleared")
        except Exception as e:
            log.debug("[auth] Could not reload license module: %s", e)

    # ── Vérification token ────────────────────────────────────────────────────

    def _extract_token(self, handler: Any) -> Optional[str]:
        """Extrait le Bearer token depuis les headers Authorization."""
        auth_header = handler.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        # Fallback : query param ?token=... (pour les navigateurs sans JS)
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(handler.path).query)
        tokens = qs.get("token", [])
        return tokens[0] if tokens else None

    def _is_public_route(self, path: str) -> bool:
        """True si la route est exemptée d'authentification."""
        clean = path.split("?")[0].rstrip("/") or "/"
        return clean in PUBLIC_ROUTES

    def check(self, handler: Any) -> bool:
        """
        Vérifie l'authentification.
        Envoie 401 automatiquement si échec.

        Returns:
            True si authentifié (ou route publique), False sinon.
        """
        from urllib.parse import urlparse
        path = urlparse(handler.path).path.rstrip("/") or "/"

        # Routes publiques — pas d'auth
        if self._is_public_route(path):
            return True

        # Token non configuré → toujours refuser
        if not self.token:
            self._send_401(handler, "Token de service non configuré. "
                           f"Définissez {self.env_var} et redémarrez le serveur.")
            return False

        # Vérification du token fourni
        provided = self._extract_token(handler)
        if not provided:
            self._send_401(handler, "Authorization: Bearer <token> requis.")
            return False

        if provided != self.token:
            self._send_401(handler, "Token invalide.")
            log.warning("[auth] Token invalide depuis %s", handler.client_address[0])
            return False

        return True

    # ── Feature gating ────────────────────────────────────────────────────────

    def check_feature(self, handler: Any, feature: str) -> bool:
        """
        Vérifie qu'une feature est disponible sur le tier actuel.
        Envoie 403 automatiquement si bloquée.

        Args:
            handler: BaseHTTPRequestHandler
            feature: Nom de la feature à vérifier
                     Vigil      : "exports" | "alerts" | "record" | "full_vrs"
                     TrustGate  : "manual" | "full"

        Returns:
            True si disponible, False sinon.
        """
        tier = self._get_tier()

        if self.service == "vigil":
            features = VIGIL_TIER_FEATURES.get(tier, VIGIL_TIER_FEATURES["free"])
            value = features.get(feature, False)
            # bridge_limit is an int (None = unlimited) — not a bool feature
            if feature == "bridge_limit":
                return True  # limit checked separately via get_bridge_limit()
            if not value:
                msg = UPGRADE_MSG.get(
                    f"vigil_{feature}",
                    UPGRADE_MSG["vigil_readonly"]
                )
                self._send_403(handler, msg)
                return False

        elif self.service == "trustgate":
            level = TRUSTGATE_TIER_LEVEL.get(tier)
            level_order = {None: 0, "manual": 1, "full": 2}
            required = level_order.get(feature, 1)
            available = level_order.get(level, 0)
            if available < required:
                if level is None:
                    msg = UPGRADE_MSG["trustgate_unavailable"]
                elif feature == "full" and level == "manual":
                    msg = UPGRADE_MSG["trustgate_manual_only"]
                else:
                    msg = UPGRADE_MSG["trustgate_unavailable"]
                self._send_403(handler, msg)
                return False

        return True

    def get_bridge_limit(self) -> Optional[int]:
        """Retourne la limite de bridges pour le tier actuel. None = illimité."""
        tier = self._get_tier()
        features = VIGIL_TIER_FEATURES.get(tier, VIGIL_TIER_FEATURES["free"])
        return features.get("bridge_limit")

    def get_vrs_history_days(self) -> int:
        """Retourne le nombre de jours d'historique VRS autorisé. 7 en Free, 90 en Pro+."""
        tier = self._get_tier()
        features = VIGIL_TIER_FEATURES.get(tier, VIGIL_TIER_FEATURES["free"])
        return 90 if features.get("full_vrs") else 7

    def is_trustgate_available(self) -> bool:
        """True si TrustGate est disponible (Pro tier ou supérieur)."""
        tier = self._get_tier()
        return TRUSTGATE_TIER_LEVEL.get(tier) is not None

    def trustgate_level(self) -> Optional[str]:
        """Retourne le niveau TrustGate : None | 'manual' | 'full'."""
        return TRUSTGATE_TIER_LEVEL.get(self._get_tier())

    def vigil_features(self) -> Dict[str, bool]:
        """Retourne le dict complet des features Vigil pour le tier actuel."""
        tier = self._get_tier()
        return VIGIL_TIER_FEATURES.get(tier, VIGIL_TIER_FEATURES["free"]).copy()

    def tier_info(self) -> Dict[str, Any]:
        """Retourne les infos de tier pour les réponses API."""
        tier = self._get_tier()
        vf   = self.vigil_features()
        info: Dict[str, Any] = {
            "tier":                tier,
            "vigil_features":      vf,
            "trustgate_level":     self.trustgate_level(),
            "trustgate_available": self.is_trustgate_available(),
            "vrs_history_days":    self.get_vrs_history_days(),
            "bridge_limit":        self.get_bridge_limit(),
            "server_start":        _SERVER_START_TS,
        }
        # Injecter les infos de licence si disponibles
        try:
            from aiss.license import get_license_info, TIERS
            lic_info = get_license_info()
            info["license_status"]  = lic_info.get("status", "unknown")
            info["license_expires"] = lic_info.get("expires_at")
            info["agents_max"]      = TIERS.get(tier, TIERS["free"])["agents_max"]
            info["events_month"]    = TIERS.get(tier, TIERS["free"])["events_month"]
        except Exception:
            info["license_status"] = "free"
        return info

    # ── Réponses d'erreur ─────────────────────────────────────────────────────

    def _send_401(self, handler: Any, message: str) -> None:
        body = _json_error(401, "Unauthorized", message).encode()
        handler.send_response(401)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("WWW-Authenticate", f'Bearer realm="PiQrypt"')
        handler.end_headers()
        handler.wfile.write(body)

    def _send_403(self, handler: Any, message: str) -> None:
        body = _json_error(403, "Forbidden", message).encode()
        handler.send_response(403)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _json_error(code: int, error: str, message: str) -> str:
    import json
    return json.dumps({
        "error":   error,
        "code":    code,
        "message": message,
        "docs":    "https://docs.piqrypt.com/auth",
    }, indent=2)


# ── Fonctions utilitaires standalone ─────────────────────────────────────────

def validate_token_env(env_var: str, service_name: str) -> str:
    """
    Valide et retourne le token depuis l'env var.
    Lève EnvironmentError si absent — à appeler au démarrage du serveur.
    """
    token = os.getenv(env_var, "").strip()
    if not token:
        raise EnvironmentError(
            f"\n{'='*60}\n"
            f"⚠️  {service_name} : token d'authentification non configuré.\n\n"
            f"  export {env_var}=votre_token_secret\n\n"
            f"Générez un token sécurisé :\n"
            f"  python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
            f"{'='*60}"
        )
    return token


def generate_token_hint() -> str:
    """Génère et affiche un token sécurisé pour la configuration initiale."""
    import secrets
    token = secrets.token_urlsafe(32)
    return (
        f"\n{'='*60}\n"
        f"Token généré (à définir dans vos variables d'environnement) :\n\n"
        f"  {token}\n\n"
        f"Commandes :\n"
        f"  export VIGIL_TOKEN={token}\n"
        f"  export TRUSTGATE_TOKEN={token}\n"
        f"{'='*60}"
    )


__all__ = [
    "AuthMiddleware",
    "VIGIL_TIER_FEATURES",
    "TRUSTGATE_TIER_LEVEL",
    "UPGRADE_MSG",
    "validate_token_env",
    "generate_token_hint",
]
