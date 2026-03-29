# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
vigil_server.py — PiQrypt Vigil HTTP Server
============================================

Serves the Vigil dashboard and exposes live API endpoints
backed by anomaly_monitor.py and a2c_detector.py.

Port: 8421 (default)

Endpoints:
  GET  /                          → vigil dashboard HTML
  GET  /api/summary               → installation summary (all agents)
  GET  /api/agent/<name>          → full VRS + history for one agent
  GET  /api/alerts                → alert journal (with filters)
  GET  /api/agent/<name>/export/pqz-cert    → certified .pqz archive
  GET  /api/agent/<name>/export/pqz-memory  → memory .pqz archive
  GET  /api/agent/<name>/export/pdf         → PDF audit report
  POST /api/agent/<name>/record   → inject event (from bridge)
  POST /api/agent/<name>/delete   → delete agent directory
  GET  /health                    → server health check
  GET  /api/credits               → certification credits (trust-server)

Usage:
  piqrypt vigil start             # starts on port 8421
  python vigil_server.py          # direct launch
  python vigil_server.py --port 9000 --host 0.0.0.0
"""

import argparse
import json
import logging
import os
import re
import sys
import threading
import time
import shutil
import signal
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

# ── Resolution automatique du path ────────────────────────────────────────────
# Fonctionne depuis n'importe quel repertoire de lancement :
#   python vigil_server.py              (depuis piqrypt/vigil/)
#   python -m vigil.vigil_server        (depuis piqrypt/)
#   PYTHONPATH=.. python vigil_server.py
#
# Ajoute la racine du projet (parent de vigil/) au sys.path
# pour que les imports aiss.* fonctionnent.
_VIGIL_DIR   = Path(__file__).resolve().parent   # piqrypt/vigil/
_PROJECT_DIR = _VIGIL_DIR.parent                  # piqrypt/
for _p in [str(_PROJECT_DIR), str(_VIGIL_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ── Auth middleware ───────────────────────────────────────────────────────────
try:
    from auth_middleware import AuthMiddleware, generate_token_hint  # noqa: F401
except ImportError:
    # Fallback 1 : racine projet
    sys.path.insert(0, str(_PROJECT_DIR))
    try:
        from auth_middleware import AuthMiddleware
    except ImportError:
        # Fallback 2 : pip install — auth_middleware est dans cli/
        sys.path.insert(0, str(_PROJECT_DIR / "cli"))
        from auth_middleware import AuthMiddleware

# ── PiQrypt imports ────────────────────────────────────────────────────────────
try:
    # Tentative 1 : modules dans aiss/ (structure normale du projet)
    try:
        from aiss.anomaly_monitor import (
            get_installation_summary, compute_vrs,
            get_agent_alerts, get_vrs_history,
            record, activate_tsi_hook,
        )
        from aiss.a2c_detector import (  # noqa: F401
            detect_concentration, detect_entropy_drop,
            detect_synchronization, detect_silence_break,
            compute_a2c_risk_batch,
        )
    except ImportError:
        # Tentative 2 : modules a plat dans le dossier parent
        from anomaly_monitor import (
            get_installation_summary, compute_vrs,
            get_agent_alerts, get_vrs_history,
            record, activate_tsi_hook,
        )
        from a2c_detector import (  # noqa: F401
            detect_concentration, detect_entropy_drop,
            detect_synchronization, detect_silence_break,
            compute_a2c_risk_batch,
        )
    BACKEND_AVAILABLE = True
except ImportError as _e:
    BACKEND_AVAILABLE = False
    logging.warning("Backend non disponible (%s) — mode DEMO actif", _e)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [VIGIL] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("vigil_server")

# ── Config ─────────────────────────────────────────────────────────────────────
DEFAULT_PORT   = 8421
DEFAULT_HOST   = "127.0.0.1"
DASHBOARD_FILE = Path(__file__).parent / "vigil_v4_final.html"
PIQRYPT_DIR    = Path.home() / ".piqrypt"

# TrustGate endpoint — Vigil lui forward les états agents après chaque record
TRUSTGATE_URL  = os.getenv("TRUSTGATE_URL", "http://127.0.0.1:8422")
TRUSTGATE_TOKEN = os.getenv("TRUSTGATE_TOKEN", "")

# Trust-server PiQrypt — certification upload/redeem
TRUST_SERVER_URL = os.getenv(
    "PIQRYPT_TRUST_SERVER_URL",
    "https://trust-server-ucjb.onrender.com"
)

# ── Auth instance (partagée par tous les handlers) ────────────────────────────
_AUTH = AuthMiddleware("VIGIL_TOKEN", service="vigil")


# ── TrustGate push (fire-and-forget, thread séparé) ──────────────────────────
def _push_to_trustgate(
    agent_name: str,
    vrs: float,
    alerts: list,
    a2c_score: float = 0.0,
) -> None:
    """
    Pousse l'état d'un agent vers TrustGate après chaque record.
    Exécuté dans un thread daemon — n'impacte pas la réponse Vigil.
    Silencieux si TrustGate n'est pas disponible.
    """
    import urllib.request
    import urllib.error

    if not TRUSTGATE_TOKEN:
        return  # TrustGate non configuré

    # Déterminer le niveau d'alerte courant
    severities = [a.get("severity", "").upper() for a in (alerts or [])]
    if "CRITICAL" in severities:
        alert_level = "critical"
    elif "HIGH" in severities or "ALERT" in severities:
        alert_level = "high"
    elif "MEDIUM" in severities or "WATCH" in severities:
        alert_level = "medium"
    else:
        alert_level = "none"

    payload = json.dumps({
        "agent_id":    agent_name,
        "agent_name":  agent_name,
        "vrs":         round(vrs, 4),
        "trust_score": round(vrs, 4),
        "tsi_state":   (
            "CRITICAL" if vrs < 0.3 else "ALERT" if vrs < 0.6
            else "WATCH" if vrs < 0.8 else "STABLE"
        ),
        "a2c_score":   round(a2c_score, 4),
        "alert_level": alert_level,
        "source":      "vigil",
        "timestamp":   _ts(),
    }).encode()

    def _do_push():
        try:
            req = urllib.request.Request(
                f"{TRUSTGATE_URL}/api/vigil/agent-state",
                data=payload,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {TRUSTGATE_TOKEN}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass  # success — TrustGate a reçu l'état
        except Exception:
            pass  # TrustGate absent ou erreur — on ignore silencieusement

    t = threading.Thread(target=_do_push, daemon=True)
    t.start()


def _push_to_trustgate_critical(
    agent_name: str,
    vrs: float,
) -> None:
    """
    Variante de _push_to_trustgate pour les incidents de sécurité de chaîne
    (fork détecté). Force tsi_state=CRITICAL et alert_level=critical
    indépendamment du score VRS, afin que TrustGate déclenche un BLOCK
    immédiat sans passer par les seuils de la policy.
    """
    import urllib.request
    import urllib.error

    if not TRUSTGATE_TOKEN:
        return

    payload = json.dumps({
        "agent_id":    agent_name,
        "agent_name":  agent_name,
        "vrs":         round(vrs, 4),
        "trust_score": round(vrs, 4),
        "tsi_state":   "CRITICAL",   # forcé — fork sur la chaîne
        "a2c_score":   0.0,
        "alert_level": "critical",   # forcé — contourne les seuils VRS
        "fork_detected": True,
        "source":      "vigil",
        "timestamp":   _ts(),
    }).encode()

    def _do_push_critical():
        try:
            req = urllib.request.Request(
                f"{TRUSTGATE_URL}/api/vigil/agent-state",
                data=payload,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {TRUSTGATE_TOKEN}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
        except Exception:
            pass

    t = threading.Thread(target=_do_push_critical, daemon=True)
    t.start()


# ── CORS + JSON helpers ────────────────────────────────────────────────────────
CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

def _json(obj: Any, indent: int = 0) -> bytes:
    return json.dumps(obj, default=str, indent=indent or None).encode()

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Demo data (used when backend not available) ────────────────────────────────
def _demo_summary() -> Dict:
    now = time.time()
    return {
        "installation_state": "WATCH",
        "global_vrs": 0.28,
        "total_agents": 4,
        "critical_count": 0,
        "alert_count": 1,
        "watch_count": 1,
        "safe_count": 2,
        "computed_at": _ts(),
        "demo_mode": True,
        "agents": [
            {
                "name": "trading_bot_A", "id": "7f3a9bK2mN8pQ4rS", "tier": "Pro",
                "vrs": 0.61, "state": "ALERT", "ts": 0.72, "tsi": "UNSTABLE",
                "a2c": 0.44, "chain_label": "FORKED IDENTITY",
                "last_seen": now - 90, "alerts": 3,
            },
            {
                "name": "sentiment_bot", "id": "9mK4pQ2rN8fL7vD", "tier": "Pro",
                "vrs": 0.31, "state": "WATCH", "ts": 0.85, "tsi": "WATCH",
                "a2c": 0.21, "chain_label": "CANONICAL CHAIN",
                "last_seen": now - 240, "alerts": 1,
            },
            {
                "name": "risk_engine", "id": "3xR7tY9pM5nK2wQ", "tier": "Pro",
                "vrs": 0.08, "state": "SAFE", "ts": 0.96, "tsi": "STABLE",
                "a2c": 0.04, "chain_label": "CANONICAL CHAIN",
                "last_seen": now - 30, "alerts": 0,
            },
            {
                "name": "data_scraper", "id": "5bN2vX8jQ4hT6kM", "tier": "Free",
                "vrs": 0.12, "state": "SAFE", "ts": 0.91, "tsi": "STABLE",
                "a2c": 0.06, "chain_label": "ROTATION INCONSISTENT",
                "last_seen": now - 720, "alerts": 0,
            },
        ],
        "active_alerts": [
            {
                "agent": "trading_bot_A", "severity": "HIGH", "type": "tsi_drift",
                "message": "TSI drift UNSTABLE — z-score 3.4σ", "timestamp": now - 300,
            },
            {
                "agent": "trading_bot_A", "severity": "HIGH", "type": "a2c_concentration",
                "message": "A2C: 81% traffic concentration → sentiment_bot",
                "timestamp": now - 3600,
            },
            {
                "agent": "trading_bot_A", "severity": "MEDIUM", "type": "chain_fork",
                "message": "Fork detected at event #2847 — unresolved",
                "timestamp": now - 7200,
            },
            {
                "agent": "sentiment_bot", "severity": "MEDIUM", "type": "a2c_sync",
                "message": "Temporal sync 0.94 with trading_bot_A (±5s)",
                "timestamp": now - 1800,
            },
        ],
    }


# ── Request handler ────────────────────────────────────────────────────────────
class VIGILHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # suppress default httpd logs
        log.info("  %s %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: bytes, content_type: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, obj: Any):
        self._send(code, _json(obj, indent=2), "application/json; charset=utf-8")

    def _send_error(self, code: int, message: str):
        self._send_json(code, {"error": message, "code": code, "timestamp": _ts()})

    # ── OPTIONS preflight ──────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    # ── GET ────────────────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        qs     = parse_qs(parsed.query)

        # ── Tier info (publique — pas d'auth requise) ──
        if path == "/api/tier":
            self._send_json(200, _AUTH.tier_info())
            return

        # ── Features (publique — pour l'UI) ──
        if path == "/api/features":
            vf = _AUTH.vigil_features()
            self._send_json(200, {
                "tier":              _AUTH._get_tier(),
                "record":            vf.get("record", False),
                "alerts":            vf.get("alerts", False),
                "alerts_full":       vf.get("full_vrs", False),  # True = all severities
                "export_pdf":        vf.get("export_pdf", False),
                "export_pqz":        vf.get("export_pqz", False),
                "full_vrs":          vf.get("full_vrs", False),
                "vrs_history_days":  _AUTH.get_vrs_history_days(),
                "bridge_limit":      _AUTH.get_bridge_limit(),    # None = unlimited
                "trustgate_level":   _AUTH.trustgate_level(),
            })
            return

        # ── Auth ──
        if not _AUTH.check(self):
            return

        # ── Dashboard ──
        if path in ("/", "/dashboard"):
            self._serve_dashboard()
            return

        # ── Health ──
        if path == "/api/debug":
            self._api_debug()
            return

        if path == "/health":
            self._send_json(200, {
                "status": "ok",
                "backend": BACKEND_AVAILABLE,
                "demo_mode": not BACKEND_AVAILABLE,
                "timestamp": _ts(),
                "version": "1.8.4",
                "auth": "enabled" if _AUTH.token else "misconfigured",
                "tier_info": _AUTH.tier_info(),
            })
            return

        # ── API: summary ──
        if path == "/api/summary":
            self._api_summary(qs)
            return

        # ── API: alerts ──
        if path == "/api/alerts":
            self._api_alerts(qs)
            return

        # ── API: agent detail ──
        parts = path.split("/")  # ['', 'api', 'agent', '<name>', ...]
        if len(parts) >= 4 and parts[1] == "api" and parts[2] == "agent":
            name = parts[3]
            if len(parts) == 4:
                self._api_agent(name, qs)
            elif len(parts) == 5 and parts[4] == "identity":
                self._api_download_identity(name)
            elif len(parts) == 6 and parts[4] == "export":
                self._api_export(name, parts[5])
            else:
                self._send_error(404, f"Unknown endpoint: {path}")
            return

        # ── API: credits ──
        if path == "/api/credits":
            self._api_credits()
            return

        self._send_error(404, f"Not found: {path}")

    # ── POST ───────────────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        parts  = path.split("/")

        # ── Auth + feature gating ──
        if not _AUTH.check(self):
            return
        if not _AUTH.check_feature(self, "record"):
            return

        # POST /api/agent/<name>/record
        if len(parts) == 5 and parts[1:3] == ["api", "agent"] and parts[4] == "record":
            name = parts[3]
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                event = json.loads(body)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON body")
                return
            self._api_record(name, event)
            return

        # POST /api/agent/create
        if path == "/api/agent/create":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON")
                return
            self._api_create_agent(payload)
            return

        # POST /api/certify  — forward to api.piqrypt.com certification service
        if path == "/api/certify":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON")
                return
            self._api_certify(payload)
            return

        # POST /api/agent/<name>/delete
        if len(parts) == 5 and parts[1:3] == ["api", "agent"] and parts[4] == "delete":
            name = parts[3]
            length = int(self.headers.get("Content-Length", 0))
            body_raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(body_raw)
            except Exception:
                body = {}
            confirmed = body.get("confirmed", False)
            self._api_delete_agent(name, confirmed=confirmed)
            return

        self._send_error(404, f"Not found: {path}")

    # ── Handlers ──────────────────────────────────────────────────────────────
    def _serve_dashboard(self):
        # Try vigil_v4_final.html first, then fallback to vigil_dashboard.html
        for candidate in [DASHBOARD_FILE, Path(__file__).parent / "vigil_dashboard.html"]:
            if candidate.exists():
                html = candidate.read_text(encoding="utf-8")
                # Inject auth token — remplace le placeholder par un script inline.
                # Le token n'est jamais écrit dans le fichier HTML sur disque.
                token_val = _AUTH.token if _AUTH.token else "__NO_TOKEN__"
                token_script = (
                    f'<script>window.VIGIL_TOKEN="{token_val}";</script>'
                )
                html = html.replace("<!-- VIGIL_TOKEN_PLACEHOLDER -->", token_script, 1)
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
                return
        # Minimal fallback
        fallback = (
            "<!DOCTYPE html><html><head><title>Vigil</title></head>"
            "<body style='background:#06080b;color:#c5d8ec;font-family:monospace;padding:40px'>"
            "<h1 style='color:#00c8e0'>VIGIL</h1>"
            "<p>Dashboard file not found. Place vigil_v4_final.html next to vigil_server.py</p>"
            "<p><a href='/api/summary' style='color:#00c8e0'>/api/summary</a> &middot; "
            "<a href='/health' style='color:#00c8e0'>/health</a></p>"
            "</body></html>"
        ).encode("utf-8")
        self._send(200, fallback, "text/html; charset=utf-8")

    def _api_summary(self, qs: Dict):
        agent_subset = qs.get("agents", [None])[0]
        subset = agent_subset.split(",") if agent_subset else None
        use_cache = False  # toujours fresh

        if BACKEND_AVAILABLE:
            try:
                data = get_installation_summary(agent_subset=subset, use_cache=use_cache)
                agents = data.get("agents", [])
                log.info(
                    "[summary] %d agents, global_vrs=%.3f", len(agents), data.get("global_vrs", 0)
                )

                # Collecter TOUTES les alertes MEDIUM+ (pas seulement CRITICAL)
                all_alerts = list(data.get("active_alerts", []))
                seen = set()
                for a in agents:
                    name = a.get("agent_name", "")
                    log.info("  [agent] %s vrs=%.3f state=%s err=%s",
                             name, a.get("vrs", 0), a.get("state", "?"), a.get("error", "ok"))
                    try:
                        agent_alerts = get_agent_alerts(name, limit=10)
                        for al in agent_alerts:
                            sev = (al.get("severity") or "").upper()
                            if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                                key = f"{name}:{al.get('type','')}:{al.get('timestamp','')}"
                                if key not in seen:
                                    seen.add(key)
                                    al.setdefault("agent_name", name)
                                    al.setdefault("agent", name)
                                    all_alerts.append(al)
                    except Exception:
                        pass

                data["active_alerts"] = all_alerts
                log.info("  [alerts] %d alertes MEDIUM+", len(all_alerts))
                data["tier_info"] = _AUTH.tier_info()

                # ── Ajouter les peers externes depuis peers.json ──────
                peers_file = PIQRYPT_DIR / "peers.json"
                if peers_file.exists():
                    try:
                        peers_data = json.loads(peers_file.read_text(encoding="utf-8"))
                        internal_ids = {a.get("agent_id") for a in agents}
                        internal_names = {a.get("agent_name") for a in agents}
                        ext_agents = []
                        for pid, pinfo in peers_data.items():
                            ident = pinfo.get("identity", {})
                            pname = ident.get("agent_name") or ident.get("name") or pid
                            # Exclure les agents internes
                            if pid in internal_ids or pname in internal_names:
                                continue
                            ext_agents.append({
                                "agent_name":    pname,
                                "agent_id":      pid,
                                "vrs":           0.0,
                                "state":         "SAFE",
                                "ts_score":      1.0,
                                "tsi_state":     "STABLE",
                                "a2c_risk":      0.0,
                                "alert_count":   0,
                                "a2c_peers":     [],
                                "event_count":   0,
                                "is_external":   True,
                                "external_type": ident.get("external_type", "service"),
                            })
                        data["agents"] = agents + ext_agents
                        log.info("  [peers] %d agents externes injectes", len(ext_agents))
                    except Exception as _pe:
                        log.warning("peers.json read error: %s", _pe)

                self._send_json(200, data)
            except Exception as e:
                log.error("get_installation_summary failed: %s", e, exc_info=True)
                self._send_json(200, {**_demo_summary(), "error": str(e), "demo_fallback": True})
        else:
            self._send_json(200, _demo_summary())

    def _api_debug(self):
        """GET /api/debug — diagnostic pipeline complet."""
        out = {"backend": BACKEND_AVAILABLE, "agents": [], "errors": []}
        try:
            from aiss.agent_registry import list_agents
            reg_agents = list_agents()
            out["registry_count"] = len(reg_agents)
            out["registry_names"] = [a["name"] for a in reg_agents]
        except Exception as e:
            out["errors"].append(f"list_agents: {e}")
            reg_agents = []

        # Scan disk directly
        disk_agents = []
        agents_dir = PIQRYPT_DIR / "agents"
        if agents_dir.exists():
            for d in agents_dir.iterdir():
                if (d / "identity.json").exists():
                    plain = d / "events" / "plain"
                    n = sum(1 for _ in plain.glob("*.json")) if plain.exists() else 0
                    disk_agents.append({"name": d.name, "event_files": n})
        out["disk_agents"] = disk_agents

        for ag in reg_agents[:6]:
            name = ag["name"]
            aid  = ag.get("agent_id", name)
            entry = {"name": name, "agent_id": aid[:16]}
            try:
                from aiss.memory import load_events
                evts = load_events(agent_name=name, agent_id=aid)
                entry["events_loaded"] = len(evts)
            except Exception as e:
                entry["load_events_error"] = str(e)
            try:
                r = compute_vrs(name, agent_id=aid, persist=False)
                entry["vrs"] = round(r.get("vrs", 0), 4)
                entry["state"] = r.get("state")
                entry["vrs_error"] = r.get("error")
                comps = r.get("components", {})
                ts_c  = comps.get("trust_score", {})
                a2c_c = comps.get("a2c", {})
                tsi_c = comps.get("tsi", {})
                entry["ts_score"]  = round(ts_c.get("score",  1.0), 4)
                entry["a2c_risk"]  = round(a2c_c.get("risk",  0.0), 4)
                entry["tsi_state"] = tsi_c.get("state", "?")
            except Exception as e:
                entry["compute_vrs_error"] = str(e)
            # Test A2C directement sur les events chargés
            try:
                from aiss.a2c_detector import detect_concentration
                evts2 = entry.get("events_loaded", 0)
                if evts2 > 0:
                    from aiss.memory import load_events as _le
                    raw_evts = _le(agent_name=name, agent_id=aid)
                    conc = detect_concentration(raw_evts)
                    entry["a2c_concentration"] = {
                        "score": round(conc.get("score", 0), 4),
                        "severity": conc.get("severity", "?"),
                        "detail": conc.get("detail", {}).get("note", ""),
                    }
            except Exception as e2:
                entry["a2c_error"] = str(e2)
            out["agents"].append(entry)

        self._send_json(200, out)

    def _api_agent(self, name: str, qs: Dict):
        days = int(qs.get("days", ["30"])[0])
        # Enforce VRS history limit by tier: 7 days Free / 90 days Pro+
        max_days = _AUTH.get_vrs_history_days()
        if days > max_days:
            days = max_days

        if BACKEND_AVAILABLE:
            try:
                # Load events from local store
                # Structure reelle : ~/.piqrypt/agents/<name>/events/plain/*.json
                events = []
                agent_dir = PIQRYPT_DIR / "agents" / name
                plain_dir = agent_dir / "events" / "plain"
                if plain_dir.exists():
                    for fpath in sorted(plain_dir.glob("*.json")):
                        try:
                            with open(fpath) as f:
                                data = json.load(f)
                                if isinstance(data, list):
                                    events.extend(data)
                                elif isinstance(data, dict):
                                    events.append(data)
                        except Exception:
                            pass
                # Fallback : events.json a plat (ancien format)
                elif (agent_dir / "events.json").exists():
                    with open(agent_dir / "events.json") as f:
                        events = json.load(f)

                vrs_data  = compute_vrs(name, name, events, persist=False)
                history   = get_vrs_history(name, days=days)
                alerts    = get_agent_alerts(name, limit=50)

                self._send_json(200, {
                    "name":    name,
                    "vrs":     vrs_data,
                    "history": history,
                    "alerts":  alerts,
                    "computed_at": _ts(),
                })
            except Exception as e:
                log.error("compute_vrs(%s) failed: %s", name, e)
                self._send_error(500, f"Backend error: {e}")
        else:
            # Demo: return a plausible agent payload
            import random
            now = time.time()
            vrs_val = {"trading_bot_A": 0.61, "sentiment_bot": 0.31,
                       "risk_engine": 0.08, "data_scraper": 0.12}.get(name, 0.15)
            self._send_json(200, {
                "name": name,
                "demo_mode": True,
                "vrs": {
                    "vrs": vrs_val,
                    "state": "ALERT" if vrs_val > 0.5 else "WATCH" if vrs_val > 0.25 else "SAFE",
                },
                "history": [
                    {
                        "timestamp": now - i * 86400,
                        "vrs": max(0, min(1, vrs_val + random.uniform(-.08, .08))),
                        "state": "SAFE",
                    }
                    for i in range(days, -1, -1)
                ],
                "alerts": [],
                "computed_at": _ts(),
            })

    def _api_alerts(self, qs: Dict):
        # Available on all tiers (v1.7.1).
        # Free → CRITICAL only (upgrade prompt in response).
        # Pro+ → all severities + filters.
        full_alerts = _AUTH.vigil_features().get("full_vrs", False)
        severity    = qs.get("severity",  [None])[0]
        agent_name  = qs.get("agent",     [None])[0]
        limit       = int(qs.get("limit", ["100"])[0])

        # Free: force CRITICAL regardless of client request
        if not full_alerts:
            severity = "CRITICAL"

        if BACKEND_AVAILABLE:
            try:
                alerts = get_agent_alerts(
                    agent_name=agent_name or "*",
                    severity_filter=severity,
                    limit=limit,
                )
                self._send_json(200, {
                    "alerts": alerts,
                    "count": len(alerts),
                    "timestamp": _ts(),
                    "tier_limited": not full_alerts,  # UI hint: upgrade for MEDIUM/LOW
                })
            except Exception as e:
                log.error("get_agent_alerts failed: %s", e)
                self._send_json(200, {
                    "alerts": _demo_summary()["active_alerts"],
                    "demo_fallback": True,
                })
        else:
            alerts = _demo_summary()["active_alerts"]
            if severity:
                alerts = [a for a in alerts if a.get("severity") == severity]
            if agent_name:
                alerts = [a for a in alerts if a.get("agent") == agent_name]
            self._send_json(200, {
                "alerts": alerts[:limit],
                "count": len(alerts),
                "demo_mode": True,
                "tier_limited": not full_alerts,
                "timestamp": _ts(),
            })

    def _api_export(self, name: str, export_type: str):
        """
        Export handler.
        pqz-cert   → returns the certified .pqz archive bytes   [Pro+]
        pqz-memory → returns the memory .pqz archive bytes      [Pro+]
        pdf        → returns a local PDF report (non-certified)  [Free+]
        """
        # PDF is available on all tiers (local, non-certified)
        if export_type == "pdf":
            if not _AUTH.check_feature(self, "export_pdf"):
                return
        else:
            # .pqz exports require Pro+
            if not _AUTH.check_feature(self, "export_pqz"):
                return
        if export_type == "pqz-cert":
            archive_dir = PIQRYPT_DIR / "agents" / name / "archive"
            path = archive_dir / f"{name}_certified.pqz"
            if not path.exists():
                path = archive_dir / f"{name}_memory.pqz"
            if path.exists():
                data = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type",        "application/octet-stream")
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{path.name}"'
                )
                self.send_header("Content-Length",      str(len(data)))
                for k, v in CORS_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send_error(
                    404,
                    f"No archive for '{name}'. Export memory first.",
                )

        elif export_type == "pqz-memory":
            archive_path = PIQRYPT_DIR / "agents" / name / "archive" / f"{name}_memory.pqz"

            if not archive_path.exists():
                if not BACKEND_AVAILABLE:
                    self._send_error(503, "Backend non disponible — export impossible")
                    return

                # Lire les événements directement depuis le disque
                plain_dir = PIQRYPT_DIR / "agents" / name / "events" / "plain"
                events = []
                if plain_dir.exists():
                    for fpath in sorted(plain_dir.glob("*.json")):
                        try:
                            data = json.loads(fpath.read_text())
                            if isinstance(data, list):
                                events.extend(data)
                            elif isinstance(data, dict):
                                events.append(data)
                        except Exception:
                            pass

                if not events:
                    self._send_error(
                        404,
                        f"No events found for agent '{name}'. "
                        f"Start a demo or connect a bridge first.",
                    )
                    return

                try:
                    from aiss.archive import create_archive

                    identity_path = PIQRYPT_DIR / "agents" / name / "identity.json"
                    identity = {}
                    if identity_path.exists():
                        try:
                            raw = json.loads(identity_path.read_text())
                            identity = raw.get("identity", raw)
                        except Exception:
                            pass

                    archive_path.parent.mkdir(parents=True, exist_ok=True)
                    create_archive(
                        events=events,
                        agent_identity=identity,
                        output_path=str(archive_path),
                        passphrase=None,
                        label=f"{name}_memory",
                    )
                    log.info(
                        "[Vigil] Memory archive generated on-demand: %s (%d events)",
                        archive_path, len(events),
                    )
                except Exception as e:
                    log.error("[Vigil] Memory archive generation failed for '%s': %s", name, e)
                    self._send_error(500, f"Archive generation failed: {e}")
                    return

            data = archive_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{name}_memory.pqz"')
            self.send_header("Content-Length", str(len(data)))
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        elif export_type == "pdf":
            # Generate minimal text-based PDF report
            # In production: use reportlab or weasyprint
            pdf_content = self._generate_pdf_report(name)
            self.send_response(200)
            self.send_header("Content-Type",        "application/pdf")
            self.send_header(
                "Content-Disposition", f'attachment; filename="{name}_audit_report.pdf"'
            )
            self.send_header("Content-Length",      str(len(pdf_content)))
            self.send_header("X-Vigil-Warning",     "local-export-not-certified")
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(pdf_content)

        else:
            self._send_error(
                400, f"Unknown export type: {export_type}. Use: pqz-cert, pqz-memory, pdf"
            )

    def _api_download_identity(self, name: str):
        """GET /api/agent/<n>/identity — télécharge identity.json."""
        identity_path = PIQRYPT_DIR / "agents" / name / "identity.json"
        if not identity_path.exists():
            self._send_error(404, f"Identity not found for agent '{name}'")
            return
        data = identity_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{name}_identity.json"')
        self.send_header("Content-Length", str(len(data)))
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _api_create_agent(self, payload: Dict):
        """POST /api/agent/create — crée une identité agent."""
        agent_name_raw = payload.get("name", "").strip()
        # Sanitiser : même logique que aiss/agent_registry._safe_name
        agent_name = re.sub(r'[^\w\-]', '_', agent_name_raw)[:64]
        agent_name = agent_name.strip('_') or 'agent'
        passphrase = payload.get("passphrase") or None
        tier       = payload.get("tier", "free")
        bridge     = payload.get("bridge", "")

        if not agent_name:
            self._send_error(400, "name is required")
            return
        if not BACKEND_AVAILABLE:
            self._send_error(503, "Backend non disponible — mode DEMO")
            return

        # ── Bridge limit enforcement (Free tier: 2 bridges max) ──────────────
        bridge_limit = _AUTH.get_bridge_limit()
        if bridge_limit is not None and bridge:
            try:
                # Count distinct bridge types already registered
                agents_dir = PIQRYPT_DIR / "agents"
                registered_bridges = set()
                if agents_dir.exists():
                    for agent_dir in agents_dir.iterdir():
                        meta_file = agent_dir / "identity.json"
                        if meta_file.exists():
                            try:
                                meta = json.loads(meta_file.read_text())
                                b = (meta.get("metadata") or {}).get("bridge", "")
                                if b:
                                    registered_bridges.add(b)
                            except Exception:
                                pass
                if bridge not in registered_bridges and len(registered_bridges) >= bridge_limit:
                    self._send_json(403, {
                        "error": "bridge_limit_reached",
                        "message": (
                            f"Free tier allows {bridge_limit} bridge types. "
                            f"Currently registered: {sorted(registered_bridges)}. "
                            f"Upgrade to Pro for unlimited bridges. "
                            f"https://piqrypt.com/pricing"
                        ),
                        "registered_bridges": sorted(registered_bridges),
                        "limit": bridge_limit,
                    })
                    return
            except Exception as e:
                log.warning("[Vigil] bridge_limit check failed (non-blocking): %s", e)
        try:
            from aiss.identity import create_agent_identity
            result = create_agent_identity(
                agent_name=agent_name,
                passphrase=passphrase,
                tier=tier,
                metadata={"bridge": bridge} if bridge else None,
            )
            log.info("[Vigil] Agent '%s' créé — %s...", agent_name, result["agent_id"][:16])
            self._send_json(200, {
                "status":             "ok",
                "agent_name":         result["agent_name"],
                "agent_name_display": agent_name_raw,
                "agent_id":           result["agent_id"],
                "encrypted":          result["encrypted"],
                "tier":               result["tier"],
                "key_path":           result["key_path"],
                "created_at":         result["created_at"],
            })
        except Exception as e:
            log.error("[Vigil] create_agent failed: %s", e)
            self._send_error(500, str(e))

    def _api_delete_agent(self, name: str, confirmed: bool = False):
        """
        POST /api/agent/<n>/delete
        body: {"confirmed": false} → étape 1 : backup mémoire + confirm_required
        body: {"confirmed": true}  → étape 2 : suppression effective
        """
        agent_dir = PIQRYPT_DIR / "agents" / name
        if not agent_dir.exists():
            self._send_json(404, {"error": f"Agent '{name}' not found"})
            return

        # ── Étape 1 : proposer backup mémoire ────────────────────────────────
        if not confirmed:
            memory_path = None
            events_count = 0

            # Lire les événements directement depuis le disque (plus fiable)
            plain_dir = agent_dir / "events" / "plain"
            events = []
            if plain_dir.exists():
                for fpath in sorted(plain_dir.glob("*.json")):
                    try:
                        data = json.loads(fpath.read_text())
                        if isinstance(data, list):
                            events.extend(data)
                        elif isinstance(data, dict):
                            events.append(data)
                    except Exception:
                        pass

            events_count = len(events)

            if events_count > 0 and BACKEND_AVAILABLE:
                try:
                    from aiss.archive import create_archive

                    identity_path = agent_dir / "identity.json"
                    identity = {}
                    if identity_path.exists():
                        try:
                            raw = json.loads(identity_path.read_text())
                            identity = raw.get("identity", raw)
                        except Exception:
                            pass

                    archive_dir = agent_dir / "archive"
                    archive_dir.mkdir(parents=True, exist_ok=True)
                    out = archive_dir / f"{name}_memory.pqz"

                    create_archive(
                        events=events,
                        agent_identity=identity,
                        output_path=str(out),
                        passphrase=None,
                        label=f"{name}_memory_before_delete",
                    )
                    memory_path = str(out)
                    log.info("[Vigil] Memory backup before delete: %s", out)
                except Exception as e:
                    log.warning("[Vigil] Memory backup failed (non-blocking): %s", e)
                    memory_path = None

            self._send_json(200, {
                "status":          "confirm_required",
                "agent":           name,
                "memory_exported": memory_path is not None,
                "memory_path":     memory_path,
                "events_count":    events_count,
                "message":         "Send confirmed=true to proceed with deletion",
            })
            return  # ← toujours return ici

        # ── Étape 2 : suppression effective ──────────────────────────────────
        try:
            # Supprimer du registre (non-bloquant — le répertoire peut exister sans entry)
            if BACKEND_AVAILABLE:
                try:
                    from aiss.agent_registry import unregister_agent
                    unregister_agent(name, delete_files=False)
                except Exception as e:
                    log.debug("[Vigil] unregister_agent: %s (non-bloquant)", e)

            # Toujours supprimer le répertoire physique
            if agent_dir.exists():
                shutil.rmtree(agent_dir, ignore_errors=True)
                log.info("[Vigil] Agent '%s' directory removed", name)

            self._send_json(200, {"status": "deleted", "agent": name})
        except Exception as e:
            log.error("[Vigil] delete_agent(%s) failed: %s", name, e)
            self._send_json(500, {"error": str(e)})

    def _api_record(self, name: str, event: Dict):
        """Receive a stamped event from a bridge and feed it to Vigil."""
        if BACKEND_AVAILABLE:
            try:
                record(event)
                # Push agent state to TrustGate (fire-and-forget)
                try:
                    vrs_data  = compute_vrs(name)
                    vrs_score = vrs_data.get("vrs", 0.5) if isinstance(vrs_data, dict) else 0.5
                    alerts    = get_agent_alerts(name, limit=5)

                    # ── Fork detection → force CRITICAL in TrustGate ──────────
                    # A fork on the agent's chain is a security incident that must
                    # bypass VRS thresholds and land directly as CRITICAL in
                    # TrustGate, regardless of the computed VRS score.
                    fork_detected = False
                    try:
                        from aiss.memory import load_events as _load_events
                        from aiss.fork import find_forks
                        chain_events = _load_events(agent_name=name)
                        if chain_events and find_forks(chain_events):
                            fork_detected = True
                            log.warning(
                                "[Vigil] FORK detected on agent '%s' — forcing CRITICAL push to TrustGate",
                                name,
                            )
                    except Exception as fork_err:
                        log.debug("[Vigil] fork check failed for '%s': %s", name, fork_err)

                    if fork_detected:
                        _push_to_trustgate_critical(name, vrs_score)
                    else:
                        _push_to_trustgate(name, vrs_score, alerts)
                    # ─────────────────────────────────────────────────────────
                except Exception:
                    pass
                self._send_json(200, {"status": "recorded", "agent": name, "timestamp": _ts()})
            except Exception as e:
                log.error("record(%s) failed: %s", name, e)
                self._send_error(500, f"Record failed: {e}")
        else:
            # Mode DEMO — push a simulated VRS to TrustGate
            import random
            profile  = event.get("profile", "safe")
            base_vrs = {"safe": 0.85, "watch": 0.55, "alert": 0.35, "critical": 0.15}
            vrs      = round(base_vrs.get(profile, 0.5) + random.uniform(-0.05, 0.05), 3)
            _push_to_trustgate(name, vrs, [])
            log.info("  [DEMO] record event for %s: %s", name, event.get("event_type", "?"))
            self._send_json(200, {"status": "ok", "demo_mode": True, "timestamp": _ts()})

    def _api_certify(self, payload: Dict):
        """
        POST /api/certify — Two-step certification via trust-server.

        Flow:
            a. Read local .pqz file for the agent
            b. POST {TRUST_SERVER_URL}/api/certification/upload (multipart)
               → { upload_token }
            c. POST {TRUST_SERVER_URL}/api/certification/redeem
               { upload_token, cert_type, email }
               → { cert_id, registry_url }
            d. Return cert_id + registry_url

        Request body:
            { "agent": "name", "cert_type": "simple|timestamp|pq_bundle",
              "email": "optional" }

        Response:
            { "cert_id": "CERT-...", "registry_url": "https://...",
              "cert_type": "...", "agent": "..." }

        Errors:
            400 — agent/cert_type invalide
            404 — aucun .pqz trouvé pour cet agent
            402 — crédits insuffisants
            503 — trust-server injoignable
        """
        import urllib.request
        import urllib.error
        import uuid

        agent     = payload.get("agent", "").strip()
        cert_type = payload.get("cert_type", "simple")
        email     = payload.get("email", "")

        if not agent:
            self._send_error(400, "agent is required")
            return

        valid_types = ("simple", "timestamp", "pq_bundle")
        if cert_type not in valid_types:
            self._send_error(400, f"cert_type must be one of: {valid_types}")
            return

        # ── a. Locate local .pqz file ──────────────────────────────────────
        agent_archive_dir = PIQRYPT_DIR / "agents" / agent / "archive"
        pqz_path = None
        for name_candidate in [f"{agent}_memory.pqz", f"{agent}_certified.pqz", f"{agent}.pqz"]:
            candidate = agent_archive_dir / name_candidate
            if candidate.exists():
                pqz_path = candidate
                break

        # Fallback : générer à la demande si aucune archive trouvée
        if not pqz_path:
            plain_dir = PIQRYPT_DIR / "agents" / agent / "events" / "plain"
            events = []
            if plain_dir.exists():
                for fpath in sorted(plain_dir.glob("*.json")):
                    try:
                        data = json.loads(fpath.read_text())
                        events.extend(data if isinstance(data, list) else [data])
                    except Exception:
                        pass
            if events and BACKEND_AVAILABLE:
                try:
                    from aiss.archive import create_archive
                    identity_path = PIQRYPT_DIR / "agents" / agent / "identity.json"
                    identity = {}
                    if identity_path.exists():
                        raw = json.loads(identity_path.read_text())
                        identity = raw.get("identity", raw)
                    agent_archive_dir.mkdir(parents=True, exist_ok=True)
                    out = agent_archive_dir / f"{agent}_memory.pqz"
                    create_archive(
                        events=events,
                        agent_identity=identity,
                        output_path=str(out),
                        passphrase=None,
                    )
                    pqz_path = out
                except Exception as e:
                    log.warning("[Vigil] on-demand archive for certify failed: %s", e)

        if not pqz_path:
            self._send_error(
                404,
                f"No archive found for agent '{agent}'. Export memory first.",
            )
            return

        try:
            pqz_data = pqz_path.read_bytes()
            boundary = uuid.uuid4().hex

            # ── b. Upload .pqz (multipart/form-data) ──────────────────────
            part_head = (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="file";'
                f' filename="{pqz_path.name}"\r\n'
                f'Content-Type: application/octet-stream\r\n\r\n'
            ).encode()
            part_tail = f'\r\n--{boundary}--\r\n'.encode()
            body_bytes = part_head + pqz_data + part_tail

            upload_req = urllib.request.Request(
                f"{TRUST_SERVER_URL}/api/certification/upload",
                data=body_bytes,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "User-Agent":   "PiQrypt-Vigil/1.7.1",
                },
                method="POST",
            )
            with urllib.request.urlopen(upload_req, timeout=30) as resp:
                upload_result = json.loads(resp.read().decode())

            upload_token = upload_result.get("upload_token")
            if not upload_token:
                self._send_error(500, "trust-server did not return upload_token")
                return

            log.info("[Vigil] Upload OK agent='%s' token=%s…", agent, upload_token[:12])

            # ── c. Redeem credit ───────────────────────────────────────────
            redeem_req = urllib.request.Request(
                f"{TRUST_SERVER_URL}/api/certification/redeem",
                data=json.dumps({
                    "upload_token": upload_token,
                    "cert_type":    cert_type,
                    "email":        email,
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   "PiQrypt-Vigil/1.7.1",
                },
                method="POST",
            )
            with urllib.request.urlopen(redeem_req, timeout=30) as resp:
                redeem_result = json.loads(resp.read().decode())

            cert_id      = redeem_result.get("cert_id", "")
            registry_url = redeem_result.get("registry_url", "")

            log.info("[Vigil] Certification issued: %s (%s) agent='%s'",
                     cert_id, cert_type, agent)

            # ── d. Return result ───────────────────────────────────────────
            self._send_json(200, {
                "cert_id":      cert_id,
                "registry_url": registry_url,
                "cert_type":    cert_type,
                "agent":        agent,
            })

        except urllib.error.HTTPError as e:
            body = e.read().decode() if e.fp else "{}"
            try:
                err = json.loads(body)
            except Exception:
                err = {"message": body}
            log.warning("[Vigil] Trust-server error %d: %s", e.code, err)
            self._send_json(e.code, {
                "error":   "certification_failed",
                "code":    e.code,
                "message": err.get("message", f"HTTP {e.code}"),
                "detail":  err,
            })

        except urllib.error.URLError as e:
            log.warning("[Vigil] Trust-server unreachable: %s", e.reason)
            self._send_json(503, {
                "error":    "certification_offline",
                "message":  (
                    f"{TRUST_SERVER_URL} is unreachable. "
                    "Check your network connection and try again."
                ),
                "agent":    agent,
                "cert_type": cert_type,
                "pending":  True,
            })

        except Exception as e:
            log.error("[Vigil] _api_certify unexpected error: %s", e)
            self._send_error(500, str(e))

    def _api_credits(self):
        """
        GET /api/credits — Fetch available certification credits from trust-server.
        Sends the local license JWT as Bearer token so the trust-server can
        identify the license and return the correct credit balances.
        """
        import urllib.request
        import urllib.error

        try:
            # Lire le JWT de licence depuis ~/.piqrypt/license.jwt
            license_jwt = None
            license_file = Path.home() / ".piqrypt" / "license.jwt"
            if license_file.exists():
                try:
                    license_jwt = license_file.read_text().strip()
                except Exception:
                    pass

            headers = {"User-Agent": "PiQrypt-Vigil/1.7.1"}
            if license_jwt:
                headers["Authorization"] = f"Bearer {license_jwt}"

            req = urllib.request.Request(
                f"{TRUST_SERVER_URL}/api/certification/credits",
                headers=headers,
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                # Normaliser la réponse du trust-server vers le format Vigil
                # Trust-server : {license_id, credits: {simple: {total, used, remaining}}}
                # Vigil attend  : {simple: {available}, timestamp: {available}, pq_bundle: {available}}
                credits = data.get("credits", data)
                normalized = {}
                for ct, info in credits.items():
                    if isinstance(info, dict):
                        normalized[ct] = {
                            "available": info.get("remaining", info.get("available", 0))
                        }
                    else:
                        normalized[ct] = {"available": info}
                self._send_json(200, normalized)

        except urllib.error.HTTPError as e:
            if e.code == 401:
                # Pas de licence active — retourner zéro crédits (comportement normal Free)
                self._send_json(200, {
                    "simple":    {"available": 0},
                    "timestamp": {"available": 0},
                    "pq_bundle": {"available": 0},
                })
            else:
                log.warning("[Vigil] Credits HTTP error %d", e.code)
                self._send_json(503, {
                    "error":   "trust_server_error",
                    "message": f"HTTP {e.code}",
                })

        except urllib.error.URLError as e:
            log.warning("[Vigil] Credits unreachable: %s", e.reason)
            self._send_json(503, {
                "error":   "trust_server_offline",
                "message": f"{TRUST_SERVER_URL} unreachable",
            })

        except Exception as e:
            log.error("[Vigil] _api_credits error: %s", e)
            self._send_error(500, str(e))

    def _generate_pdf_report(self, name: str) -> bytes:
        """
        Generate a minimal but valid PDF report.
        Note: This is a text/ASCII PDF — production should use reportlab.
        Header clearly states: LOCAL EXPORT — NOT CERTIFIED BY PIQRYPT
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Try to get real data
        vrs_val, state = 0.0, "UNKNOWN"
        if BACKEND_AVAILABLE:
            try:
                # Charger les evenements (structure reelle : events/plain/*.json)
                events = []
                agent_dir2 = PIQRYPT_DIR / "agents" / name
                plain_dir2 = agent_dir2 / "events" / "plain"
                if plain_dir2.exists():
                    for fpath in sorted(plain_dir2.glob("*.json")):
                        try:
                            data = json.loads(fpath.read_text())
                            events.extend(data if isinstance(data, list) else [data])
                        except Exception:
                            pass
                elif (agent_dir2 / "events.json").exists():
                    events = json.loads((agent_dir2 / "events.json").read_text())
                vrs_data = compute_vrs(name, name, events, persist=False)
                vrs_val  = vrs_data.get("vrs", 0.0)
                state    = vrs_data.get("state", "UNKNOWN")
            except Exception:
                pass

        content_lines = [
            "VIGIL AUDIT REPORT",
            "PiQrypt v1.8.6 — AISS v1.1",
            "",
            "!!! NOTICE: LOCAL EXPORT — NOT CERTIFIED BY PIQRYPT !!!",
            "This PDF is a local readable report only. It has no legal",
            "or cryptographic value. For certified export use .pqz format.",
            "",
            f"Generated : {now_str}",
            f"Agent     : {name}",
            f"VRS Score : {vrs_val:.3f}",
            f"State     : {state}",
            "",
            f"For certified audit trail: piqrypt archive --agent {name}",
            f"For memory export:         piqrypt archive --agent {name} --memory",
        ]

        # Minimal valid PDF structure
        body = "\n".join(content_lines)
        pdf = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {len(body) + 60} >>
stream
BT /F1 10 Tf 50 750 Td 14 TL
"""
        for line in content_lines:
            escaped = line.replace("(", "\\(").replace(")", "\\)")
            pdf += f"({escaped}) Tj T*\n"
        pdf += """ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>
endobj
xref
0 6
trailer
<< /Size 6 /Root 1 0 R >>
startxref
0
%%EOF"""
        return pdf.encode("ascii", errors="replace")


# ── Server lifecycle ───────────────────────────────────────────────────────────
class VIGILServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = True):
        self._server = HTTPServer((self.host, self.port), VIGILHandler)
        log.info("━" * 56)
        log.info("  VIGIL Server v1.8.4")
        _token = os.environ.get("VIGIL_TOKEN", "")
        _url = f"http://{self.host}:{self.port}/?token={_token}" if _token else f"http://{self.host}:{self.port}"
        log.info("  Dashboard → %s", _url)
        log.info("  API       → http://%s:%d/api/summary", self.host, self.port)
        log.info("  Backend   → %s", "LIVE" if BACKEND_AVAILABLE else "DEMO MODE")

        # ── License boot check ────────────────────────────────────────────────
        tier_inf = _AUTH.tier_info()
        tier     = tier_inf["tier"]
        lic_status = tier_inf.get("license_status", "free")
        lic_exp    = tier_inf.get("license_expires")
        vf         = tier_inf.get("vigil_features", {})

        log.info(
            "  Auth      → %s",
            "✅ ENABLED" if _AUTH.token else "⚠️  MISCONFIGURED — set VIGIL_TOKEN",
        )
        log.info("  Tier      → %s  [%s]", tier.upper(), lic_status.upper())
        if lic_exp:
            log.info("  Expires   → %s", lic_exp)
        log.info("  TrustGate → %s", tier_inf["trustgate_level"] or "unavailable (upgrade to Pro)")
        log.info(
            "  Features  → record=%s  alerts=%s  export_pdf=%s  export_pqz=%s  full_vrs=%s  bridges=%s",  # noqa: E501
            "✅" if vf.get("record")      else "🔒",
            "✅" if vf.get("alerts")      else "🔒",
            "✅" if vf.get("export_pdf")  else "🔒",
            "✅" if vf.get("export_pqz")  else "🔒",
            "✅" if vf.get("full_vrs")    else "🔒 (7d max)",
            str(vf.get("bridge_limit") or "∞"),
        )

        if tier == "free":
            log.info("  ℹ️  VIGIL Free tier — fully functional dashboard.")
            log.info("      Bridges: %d max · Alerts: CRITICAL only · History: 7 days",
                     vf.get("bridge_limit", 2))
            log.info("      Upgrade to Pro for .pqz exports, full alerts, 90-day history.")
            log.info("      https://piqrypt.com/pricing")
        elif lic_status == "demo":
            log.warning("  ⚠️  VIGIL running in DEMO mode — no valid license token.")
            log.warning("      Features are restricted. Activate: piqrypt license activate <token>")

        log.info("━" * 56)
        if not _AUTH.token:
            import secrets
            suggested = secrets.token_urlsafe(32)
            log.warning("  Générez un token : export VIGIL_TOKEN=%s", suggested)

        if BACKEND_AVAILABLE:
            try:
                activate_tsi_hook()
                log.info("  TSI hook  → activated")
            except Exception as e:
                log.warning("  TSI hook  → failed: %s", e)

        # ── Sync périodique vers TrustGate (toutes les 10s) ──────────────────
        # Doit être lancé AVANT serve_forever() qui bloque.
        if TRUSTGATE_TOKEN:
            def _sync_loop():
                while True:
                    time.sleep(10)
                    try:
                        if BACKEND_AVAILABLE:
                            summary = get_installation_summary()
                            agents  = summary.get("agents", [])
                        else:
                            agents_dir = PIQRYPT_DIR / "agents"
                            agents = []
                            if agents_dir.exists():
                                for agent_dir in agents_dir.iterdir():
                                    identity = agent_dir / "identity.json"
                                    if identity.exists():
                                        try:
                                            data = json.loads(identity.read_text())
                                            agents.append({
                                                "name":  data.get("agent_name", agent_dir.name),
                                                "vrs":   0.5,
                                                "alerts": [],
                                            })
                                        except Exception:
                                            pass
                        for agent in agents:
                            aname = (
                                agent.get("agent_name")
                                or agent.get("name")
                                or agent.get("agent_id", "")
                            )
                            if not aname:
                                continue
                            vrs  = agent.get("vrs", 0.5)
                            a2c  = agent.get("a2c_risk", 0.0)

                            # ── Fork check dans le sync périodique ───────────
                            # Sans ce check, le heartbeat 10s écraserait un
                            # CRITICAL fork-triggered avec un WATCH ordinaire.
                            sync_fork = False
                            if BACKEND_AVAILABLE:
                                try:
                                    from aiss.memory import load_events as _le
                                    from aiss.fork import find_forks as _ff
                                    _evts = _le(agent_name=aname)
                                    if _evts and _ff(_evts):
                                        sync_fork = True
                                except Exception:
                                    pass

                            if sync_fork:
                                _push_to_trustgate_critical(aname, vrs)
                            else:
                                _push_to_trustgate(aname, vrs, agent.get("alerts", []), a2c)
                            # ─────────────────────────────────────────────────
                    except Exception:
                        pass
            threading.Thread(target=_sync_loop, daemon=True, name="vigil-tg-sync").start()
            log.info("  TrustGate sync → active (10s interval → %s)", TRUSTGATE_URL)

        if blocking:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self):
        if self._server:
            log.info("Stopping VIGIL server…")
            self._server.shutdown()
            self._server = None
        log.info("VIGIL server stopped.")

    def is_running(self) -> bool:
        return self._server is not None


# ── CLI ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Vigil HTTP Server — PiQrypt v1.8.6")
    parser.add_argument("--host",  default=DEFAULT_HOST,  help=f"Bind host (default: {DEFAULT_HOST})")  # noqa: E501
    parser.add_argument("--port",  default=DEFAULT_PORT,  type=int, help=f"Port (default: {DEFAULT_PORT})")  # noqa: E501
    parser.add_argument("--debug", action="store_true",   help="Verbose logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    server = VIGILServer(host=args.host, port=args.port)

    # Graceful shutdown on SIGTERM/SIGINT
    def _shutdown(sig, frame):
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    server.start(blocking=True)


if __name__ == "__main__":
    main()
