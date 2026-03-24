# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Licensed under the Elastic License 2.0 (ELv2).
# You may not provide this software as a hosted or managed service
# to third parties without a commercial license.
# Commercial license: contact@piqrypt.com

"""
trustgate_server.py — Trust Gate HTTP API Server

Single-file HTTP server — Python stdlib only, zero external dependencies.
Port: 8422 (default)

Bridges all Trust Gate modules into a unified REST API:
    - Policy Engine  — evaluate actions
    - Decision Queue — REQUIRE_HUMAN flow
    - Human Principal — SSO authentication
    - Audit Journal  — compliance export
    - Vigil bridge   — sync agent states

Compliance:
    ANSSI R29  — all API calls logged via audit_journal
    ANSSI R30  — all admin endpoints require principal auth
    AI Act Art.14 — /decisions/<id>/approve|reject always available
    NIST MANAGE 2.2 — human oversight accessible via API

Endpoints:

    System
    GET  /health
    GET  /api/status

    Policy
    GET  /api/policy
    POST /api/policy/simulate

    Evaluation
    POST /api/evaluate

    Decisions (REQUIRE_HUMAN queue)
    GET  /api/decisions
    GET  /api/decisions/<id>
    POST /api/decisions/<id>/approve
    POST /api/decisions/<id>/reject

    Principals
    GET  /api/principals
    POST /api/principals
    GET  /api/principals/<name>
    POST /api/principals/<name>/authenticate

    Audit
    GET  /api/audit
    GET  /api/audit/export

    Vigil bridge
    POST /api/vigil/agent-state
"""

import argparse
import json
import logging
import signal
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

# ── Auth middleware ───────────────────────────────────────────────────────────
import sys as _sys
_TG_DIR = Path(__file__).resolve().parent
_ROOT   = _TG_DIR.parent
for _p in [str(_ROOT), str(_TG_DIR)]:
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
try:
    from auth_middleware import AuthMiddleware
except ImportError:
    try:
        _sys.path.insert(0, str(_ROOT / "cli"))
        from auth_middleware import AuthMiddleware
    except ImportError:
        raise ImportError(
            "auth_middleware.py introuvable. "
            "Placez-le dans piqrypt/ ou piqrypt/cli/."
        )

# ── Trust Gate imports ────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from trustgate.decision import Decision, EvaluationContext, Outcome  # noqa: E402
from trustgate.policy_loader import (  # noqa: E402
    load_policy, Policy, ThresholdPolicy, RolePolicy,
    NetworkPolicy, NotificationPolicy, EscalationPolicy,
)
from trustgate.policy_engine import evaluate as engine_evaluate, simulate as engine_simulate  # noqa: E402
from trustgate.policy_versioning import PolicyVersioning  # noqa: E402
from trustgate.audit_journal import AuditJournal  # noqa: E402
from trustgate.decision_queue import DecisionQueue  # noqa: E402
from trustgate.human_principal import (  # noqa: E402
    HumanPrincipal, SSOToken, PrincipalNotFoundError,
    InsufficientClearanceError, DEFAULT_PRINCIPALS_DIR,
)
from trustgate.notifier import Notifier, ConsoleChannel  # noqa: E402

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "[%(asctime)s] %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("trustgate_server")

# ── Default paths ─────────────────────────────────────────────────────────────
DEFAULT_POLICY_PATH   = Path.home() / ".piqrypt" / "trustgate" / "policy.yaml"
DEFAULT_JOURNAL_DIR   = Path.home() / ".piqrypt" / "trustgate" / "journal"
DEFAULT_QUEUE_DIR     = Path.home() / ".piqrypt" / "trustgate" / "queue"
DEFAULT_VERSIONS_DIR  = Path.home() / ".piqrypt" / "trustgate" / "policy_versions"
DEFAULT_PORT          = 8422
DEFAULT_HOST          = "127.0.0.1"

# ── Auth instance ─────────────────────────────────────────────────────────────
_AUTH = AuthMiddleware("TRUSTGATE_TOKEN", service="trustgate")


# ─── TrustGate Server ─────────────────────────────────────────────────────────

class TrustGateServer:
    """
    Trust Gate HTTP API Server.

    Manages all module instances and serves the REST API.
    """

    def __init__(
        self,
        host:           str  = DEFAULT_HOST,
        port:           int  = DEFAULT_PORT,
        policy_path:    Path = DEFAULT_POLICY_PATH,
        journal_dir:    Path = DEFAULT_JOURNAL_DIR,
        queue_dir:      Path = DEFAULT_QUEUE_DIR,
        versions_dir:   Path = DEFAULT_VERSIONS_DIR,
        principals_dir: Path = DEFAULT_PRINCIPALS_DIR,
        demo_mode:      bool = False,
    ):
        self.host           = host
        self.port           = port
        self.policy_path    = policy_path
        self.principals_dir = principals_dir
        self.demo_mode      = demo_mode
        self._server        = None
        self._started       = threading.Event()

        # ── Initialize modules ────────────────────────────────────────────────
        self.journal     = AuditJournal(journal_dir=journal_dir)
        self.queue       = DecisionQueue(
            queue_dir=queue_dir,
            audit_journal=self.journal,
        )
        self.versioning  = PolicyVersioning(versions_dir=versions_dir)
        self.notifier    = Notifier(channels=[ConsoleChannel()])

        # ── Load policy ───────────────────────────────────────────────────────
        self.policy: Optional[Policy] = None
        self._agents: dict = {}  # registre agents Vigil
        self._load_policy_safe()

        # ── Wire decision queue → notifier ────────────────────────────────────
        def _on_enqueue_notify(decision: Decision):
            if decision.outcome == Outcome.REQUIRE_HUMAN:
                principals = self._get_notifiable_principals()
                if principals:
                    self.notifier.push(decision, principals)

        # (called manually after enqueue in handler)
        self._notify_on_enqueue = _on_enqueue_notify

        # ── Demo mode: flush stale queue/journal + create default principal ──
        if self.demo_mode:
            # Create default admin principal if none exists
            try:
                existing = HumanPrincipal.list_all(principals_dir=self.principals_dir)
                if not existing:
                    HumanPrincipal.create(
                        name="admin",
                        email="admin@trustgate.local",
                        clearance="L3",
                        mode="sso",
                        created_by="bootstrap",
                        principals_dir=self.principals_dir,
                    )
                    log.info("Demo mode — principal 'admin' (L3) created automatically")
                    # Also create operator-level principal for L1/L2 testing
                    HumanPrincipal.create(
                        name="operator",
                        email="operator@trustgate.local",
                        clearance="L2",
                        mode="sso",
                        created_by="bootstrap",
                        principals_dir=self.principals_dir,
                    )
                    log.info("Demo mode — principal 'operator' (L2) created automatically")
            except Exception as e:
                log.warning(f"Could not create demo principal: {e}")

        if self.demo_mode:
            try:
                import shutil
                if queue_dir.exists():
                    shutil.rmtree(queue_dir)
                    queue_dir.mkdir(parents=True, exist_ok=True)
                    self.queue = DecisionQueue(queue_dir=queue_dir, audit_journal=self.journal)
                if journal_dir.exists():
                    shutil.rmtree(journal_dir)
                    journal_dir.mkdir(parents=True, exist_ok=True)
                    self.journal = AuditJournal(journal_dir=journal_dir)
                log.info("Demo mode — queue and journal flushed on startup")
            except Exception as e:
                log.warning(f"Demo flush failed: {e}")

        log.info(
            f"Trust Gate Server initialized — "
            f"policy={'loaded' if self.policy else 'missing'} "
            f"demo_mode={demo_mode}"
        )

    # ── Policy management ─────────────────────────────────────────────────────

    def _load_policy_safe(self) -> bool:
        try:
            if self.policy_path.exists():
                self.policy = load_policy(self.policy_path)
                log.info(f"Policy loaded: {self.policy.to_version_id()}")
                return True
            else:
                log.warning(f"Policy file not found: {self.policy_path}")
                if self.demo_mode:
                    self.policy = self._make_demo_policy()
                    return False
                # ── Fallback 1 : policy.yaml dans le même répertoire que le serveur ──
                # Couvre le cas où le fichier est dans le repo mais pas dans ~/.piqrypt
                local_policy = Path(__file__).parent / "policy.yaml"
                for candidate in [local_policy, Path(__file__).parent / "profiles" / "nist_balanced.yaml"]:
                    if candidate.exists():
                        try:
                            self.policy = load_policy(candidate)
                            log.info("[TrustGate] Loaded policy from: %s", candidate.name)
                            return True
                        except Exception as _e:
                            log.warning("[TrustGate] Could not load %s: %s", candidate.name, _e)
                return False
        except Exception as e:
            log.error(f"Policy load failed: {e}")
            if self.demo_mode:
                self.policy = self._make_demo_policy()
            return False

    def _make_demo_policy(self) -> Policy:
        """Demo policy for testing without a policy.yaml file."""
        # Uses ThresholdPolicy, RolePolicy etc imported at module level
        p = Policy()
        p.name         = "demo"
        p.version      = "demo"
        p.content_hash = "demo"
        p.thresholds   = ThresholdPolicy(vrs_require_human=0.35, vrs_block=0.45)
        p.roles        = {
            "operator": RolePolicy(
                allowed_tools=["read_db", "write_db", "http_get", "search",
                               "vigil_threshold_exceeded"],  # Vigil bridge action
                blocked_tools=["shell"],
            ),
            "trusted": RolePolicy(allowed_tools=["*"], blocked_tools=["shell"]),
            "read_only": RolePolicy(allowed_tools=["read_db", "search"], blocked_tools=[]),
            "vigil": RolePolicy(allowed_tools=["vigil_threshold_exceeded"], blocked_tools=[]),
        }
        p.escalation        = EscalationPolicy()
        p.network           = NetworkPolicy(allowed_domains=[], block_external=False)
        p.notification      = NotificationPolicy(timeout_seconds=300, on_timeout="REJECT")
        p.dangerous_patterns = [r"rm\s+-rf", r"DROP\s+TABLE", r"curl.*\|.*bash"]
        log.info("Using DEMO policy")
        return p

    def _get_notifiable_principals(self) -> list:
        try:
            return HumanPrincipal.list_all(principals_dir=self.principals_dir)
        except Exception:
            return []

    # ── Server lifecycle ──────────────────────────────────────────────────────

    def start(self) -> None:
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self._started.set()
        log.info(f"Trust Gate listening on http://{self.host}:{self.port}")
        self._server.serve_forever()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            log.info("Trust Gate stopped")

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._started.is_set()

    # ── Request handler factory ───────────────────────────────────────────────

    def _make_handler(self):
        server_instance = self

        class Handler(BaseHTTPRequestHandler):

            def do_GET(self):
                server_instance._handle(self, "GET")

            def do_POST(self):
                server_instance._handle(self, "POST")

            def do_OPTIONS(self):
                # CORS preflight — required for browser fetch() from file://
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Access-Control-Max-Age", "86400")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, fmt, *args):
                pass   # suppress default access log — we use our own

        return Handler

    def _handle(self, req, method: str) -> None:
        parsed = urlparse(req.path)
        path   = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        # ── Auth ────────────────────────────────────────────────────────────
        # OPTIONS est un preflight CORS — pas de données exposées, pas d'auth requise
        if method == "OPTIONS":
            self._send(req, 204, {})
            return
        if not _AUTH.check(req):
            return

        try:
            body = self._read_body(req)
            response, status = self._route(method, path, body, params)
            self._send(req, status, response)
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass  # client disconnected before response — normal for Vigil timeout
        except Exception as e:
            log.error(f"Unhandled error on {method} {path}: {traceback.format_exc()}")
            try:
                self._send(req, 500, {"error": str(e)})
            except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
                pass

    def _route(self, method: str, path: str, body: dict, params: dict):
        """Route requests to handlers."""

        # ── System ────────────────────────────────────────────────────────────
        # ── Root redirect → console ───────────────────────────────────────────
        if path == "/" and method == "GET":
            return {"__redirect__": "/console"}, 302

        if path == "/api/tier" and method == "GET":
            return _AUTH.tier_info(), 200

        if path == "/health" and method == "GET":
            return self._handle_health()

        if path == "/api/status" and method == "GET":
            return self._handle_status()

        # ── Policy ────────────────────────────────────────────────────────────
        if path == "/api/policy" and method == "GET":
            return self._handle_get_policy()

        if path == "/api/policy" and method == "POST":
            return self._handle_save_policy(body)

        if path == "/api/policy/simulate" and method == "POST":
            return self._handle_simulate(body)

        # ── Evaluation ────────────────────────────────────────────────────────
        if path == "/api/evaluate" and method == "POST":
            return self._handle_evaluate(body)

        # ── Decisions ─────────────────────────────────────────────────────────
        if path == "/api/decisions" and method == "GET":
            return self._handle_list_decisions(params)

        parts = path.split("/")
        # /api/decisions/<id>
        if len(parts) == 4 and parts[1] == "api" and parts[2] == "decisions":
            decision_id = parts[3]
            if method == "GET":
                return self._handle_get_decision(decision_id)

        # /api/decisions/<id>/approve or /reject
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "decisions":
            decision_id = parts[3]
            action      = parts[4]
            if method == "POST" and action in ("approve", "reject"):
                return self._handle_decision_action(decision_id, action, body)

        # ── Principals ────────────────────────────────────────────────────────
        if path == "/api/principals" and method == "GET":
            return self._handle_list_principals()

        if path == "/api/principals" and method == "POST":
            return self._handle_create_principal(body)

        if len(parts) == 4 and parts[1] == "api" and parts[2] == "principals":
            name = parts[3]
            if method == "GET":
                return self._handle_get_principal(name)

        if (len(parts) == 5 and parts[1] == "api" and parts[2] == "principals"
                and parts[4] == "authenticate"):
            name = parts[3]
            if method == "POST":
                return self._handle_authenticate(name, body)

        # ── Audit ─────────────────────────────────────────────────────────────
        if path == "/api/audit" and method == "GET":
            return self._handle_audit(params)

        if path == "/api/audit/export" and method == "GET":
            return self._handle_audit_export(params)

        # ── Vigil bridge ──────────────────────────────────────────────────────
        if path == "/api/vigil/agent-state" and method == "POST":
            return self._handle_vigil_agent_state(body)

        if path == "/api/reset" and method == "POST":
            self._agents.clear()
            log.info("[TrustGate] agents registry cleared")
            return {"ok": True, "cleared": True}, 200

        # ── Console HTML ────────────────────────────────────────────────────────
        if path == "/api/profiles" and method == "GET":
            return self._handle_list_profiles()

        if path == "/api/agents" and method == "GET":
            return self._handle_list_agents()

        if path in ("/console", "/console/") and method == "GET":
            return self._handle_console()

        # ── 404 ───────────────────────────────────────────────────────────────
        return {"error": f"Not found: {method} {path}"}, 404

    # ── Handlers ─────────────────────────────────────────────────────────────

    def _handle_list_profiles(self):
        """GET /api/profiles — liste les profils de conformité disponibles."""
        profiles_dir = Path(__file__).parent / "profiles"
        profiles = []
        descriptions = {
            "anssi_strict":    "ANSSI 2024 — Secteur public français, OIV, infra critique",
            "nist_balanced":   "NIST AI RMF 1.0 — Entreprise US, risque modéré",
            "ai_act_high_risk":"EU AI Act — Finance, santé, RH, justice",
        }
        for yaml_file in sorted(profiles_dir.glob("*.yaml")):
            name = yaml_file.stem
            try:
                content = yaml_file.read_text(encoding="utf-8")
                profiles.append({
                    "name":        name,
                    "description": descriptions.get(name, name),
                    "content":     content,
                })
            except Exception as e:
                log.warning("[TrustGate] Could not read profile %s: %s", name, e)
        return {"profiles": profiles, "count": len(profiles)}, 200

    def _handle_list_agents(self):
        """GET /api/agents — registre de tous les agents connus de Vigil."""
        now = int(time.time())
        # Nettoyer les agents expirés (TTL 120s)
        expired = [
            aid for aid, a in self._agents.items()
            if (now - a.get("updated_at", 0)) > 120
        ]
        for aid in expired:
            del self._agents[aid]
        # Retourner les agents restants
        agents = list(self._agents.values())
        for a in agents:
            a["active"] = (now - a.get("updated_at", 0)) < 60
        return {"total": len(agents), "agents": agents}, 200

    def _handle_health(self):
        return {
            "status":       "ok",
            "policy":       self.policy.to_version_id() if self.policy else None,
            "demo_mode":    self.demo_mode,
            "pending":      self.queue.count_pending(),
            "timestamp":    int(time.time()),
        }, 200

    def _handle_status(self):
        return {
            "service":       "trust_gate",
            "version":       "1.0.0",
            "host":          self.host,
            "port":          self.port,
            "policy":        self.policy.to_version_id() if self.policy else None,
            "demo_mode":     self.demo_mode,
            "pending_decisions": self.queue.count_pending(),
            "principals":    len(HumanPrincipal.list_all(self.principals_dir)),
            "timestamp":     int(time.time()),
        }, 200

    def _handle_get_policy(self):
        if self.policy is None:
            default_path = (
                Path(__file__).parent / "profiles" / "nist_balanced.yaml"
            )
            if default_path.exists():
                try:
                    from trustgate.policy_loader import load_policy
                    self.policy = load_policy(default_path)
                    log.info("[TrustGate] Loaded default policy: nist_balanced")
                except Exception as e:
                    log.warning(
                        "[TrustGate] Could not load default policy: %s", e
                    )
        if not self.policy:
            return {"error": "No policy loaded"}, 503
        return {
            "name":             self.policy.name,
            "version":          self.policy.version,
            "version_id":       self.policy.to_version_id(),
            "content_hash":     self.policy.content_hash,
            "profile":          self.policy.profile,
            "thresholds": {
                "vrs_require_human": self.policy.thresholds.vrs_require_human,
                "vrs_block":         self.policy.thresholds.vrs_block,
            },
            "roles":            list(self.policy.roles.keys()),
            "dangerous_patterns_count": len(self.policy.dangerous_patterns),
        }, 200

    def _handle_save_policy(self, body: dict):
        """POST /api/policy — save and reload policy from YAML content."""
        import os
        import yaml as _yaml
        import tempfile  # noqa: F401 — kept for future use

        yaml_content = body.get("yaml", "")
        if not yaml_content:
            return {"error": "yaml content required"}, 400
        try:
            parsed = _yaml.safe_load(yaml_content)
            if not isinstance(parsed, dict):
                return {"error": "invalid policy YAML"}, 400
            _env = os.getenv("TRUSTGATE_POLICY_FILE")
            policy_file = Path(_env) if _env else Path(__file__).parent / "policy.yaml"
            policy_file.parent.mkdir(parents=True, exist_ok=True)
            with open(policy_file, "w", encoding="utf-8") as f:
                f.write(yaml_content)
            from trustgate.policy_loader import load_policy
            self.policy = load_policy(policy_file)
            log.info("[TrustGate] Policy saved and reloaded: %s", policy_file)
            return {"ok": True, "file": policy_file}, 200
        except Exception as e:
            log.error("[TrustGate] save_policy failed: %s", e)
            return {"error": str(e)}, 500

    def _handle_simulate(self, body: dict):
        """
        POST /api/policy/simulate
        Accepte un champ optionnel "yaml" pour simuler un profil
        non encore activé — ANSSI R22 / Policy Editor preview.
        """
        try:
            # Si un yaml est fourni, on crée une policy temporaire
            yaml_content = body.get("yaml", "")
            if yaml_content:
                import tempfile, os
                from trustgate.policy_loader import load_policy
                tmp = Path(tempfile.mktemp(suffix=".yaml"))
                try:
                    tmp.write_text(yaml_content, encoding="utf-8")
                    policy = load_policy(tmp)
                finally:
                    if tmp.exists(): tmp.unlink()
            else:
                if not self.policy:
                    return {"error": "No policy loaded"}, 503
                policy = self.policy
            ctx    = self._parse_context(body)
            result = engine_simulate(ctx, policy)
            return result, 200
        except (KeyError, ValueError) as e:
            return {"error": f"Invalid context: {e}"}, 400
        except Exception as e:
            return {"error": str(e)}, 500

    def _handle_evaluate(self, body: dict):
        """
        Evaluate an action request.
        If outcome is REQUIRE_HUMAN — enqueue and notify.

        ANSSI R29: all evaluations logged.
        """
        if not self.policy:
            return {"error": "No policy loaded"}, 503
        try:
            ctx      = self._parse_context(body)
            decision = engine_evaluate(ctx, self.policy)

            # Log to journal
            self.journal.record(decision)

            # Enqueue if REQUIRE_HUMAN
            if decision.outcome == Outcome.REQUIRE_HUMAN:
                self.queue.enqueue(decision)
                self._notify_on_enqueue(decision)

            return {
                "decision_id":   decision.decision_id,
                "outcome":       decision.outcome,
                "reason":        decision.reason,
                "blocked":       decision.is_blocking(),
                "pending":       decision.is_pending(),
                "policy_version":decision.policy_version,
                "policy_hash":   decision.policy_hash,
                "timeout_at":    decision.timeout_at,
            }, 200

        except (KeyError, ValueError) as e:
            return {"error": f"Invalid context: {e}"}, 400

    def _handle_list_decisions(self, params: dict):
        agent_id = params.get("agent_id", [None])[0]
        pending  = self.queue.get_pending(agent_id=agent_id)
        return {
            "total":     len(pending),
            "decisions": [self._decision_summary(d) for d in pending],
        }, 200

    def _handle_get_decision(self, decision_id: str):
        d = self.queue.get_decision(decision_id)
        if not d:
            return {"error": f"Decision {decision_id} not found"}, 404
        return d.to_audit_dict(), 200

    def _handle_decision_action(self, decision_id: str, action: str, body: dict):
        """
        Approve or reject a REQUIRE_HUMAN decision.
        AI Act Art.14 — human oversight always available.
        """
        principal_name = body.get("principal_name")
        token_id       = body.get("token_id")
        justification  = body.get("justification", "")

        if not principal_name:
            return {"error": "principal_name required"}, 400

        try:
            principal = HumanPrincipal.load(
                principal_name,
                principals_dir=self.principals_dir,
            )
        except PrincipalNotFoundError:
            return {"error": f"Principal '{principal_name}' not found"}, 404

        # Reconstruct SSO token from token_id (Phase 1 — simplified)
        # In production: verify token from session store
        token = SSOToken(
            token_id       = token_id or "direct-api",
            principal_id   = principal.record.principal_id,
            principal_name = principal.record.name,
            clearance      = principal.record.clearance,
            issued_at      = int(time.time()) - 60,
            expires_at     = int(time.time()) + 3600,
        )
        token.token_hash = token.compute_hash(b"trustgate-internal-secret")

        try:
            if action == "approve":
                resolved = self.queue.approve(
                    decision_id      = decision_id,
                    principal        = principal,
                    token_or_session = token,
                    justification    = justification,
                )
            else:
                resolved = self.queue.reject(
                    decision_id      = decision_id,
                    principal        = principal,
                    token_or_session = token,
                    justification    = justification,
                )

            return {
                "decision_id":       resolved.decision_id,
                "outcome":           resolved.outcome,
                "state":             resolved.state,
                "approved_by":       resolved.approved_by,
                "approval_timestamp":resolved.approval_timestamp,
                "justification":     resolved.justification,
            }, 200

        except InsufficientClearanceError as e:
            return {"error": str(e)}, 403
        except Exception as e:
            return {"error": str(e)}, 400

    def _handle_list_principals(self):
        principals = HumanPrincipal.list_all(principals_dir=self.principals_dir)
        return {
            "total":      len(principals),
            "principals": [self._principal_summary(p) for p in principals],
        }, 200

    def _handle_create_principal(self, body: dict):
        try:
            name      = body["name"]
            email     = body["email"]
            clearance = body.get("clearance", "L1")
            mode      = body.get("mode", "sso")

            p = HumanPrincipal.create(
                name           = name,
                email          = email,
                clearance      = clearance,
                mode           = mode,
                sso_provider   = body.get("sso_provider"),
                sso_subject    = body.get("sso_subject"),
                principals_dir = self.principals_dir,
            )
            return self._principal_summary(p), 201

        except (KeyError, ValueError) as e:
            return {"error": str(e)}, 400
        except Exception as e:
            return {"error": str(e)}, 500

    def _handle_get_principal(self, name: str):
        try:
            p = HumanPrincipal.load(name, principals_dir=self.principals_dir)
            return self._principal_summary(p), 200
        except PrincipalNotFoundError:
            return {"error": f"Principal '{name}' not found"}, 404

    def _handle_authenticate(self, name: str, body: dict):
        """
        Phase 1 SSO authentication.
        Returns a Trust Gate internal token.
        """
        try:
            p     = HumanPrincipal.load(name, principals_dir=self.principals_dir)
            token = p.authenticate_sso(
                sso_claims  = body.get("sso_claims", {}),
                ttl_seconds = body.get("ttl_seconds", 3600),
            )
            return {
                "token_id":     token.token_id,
                "principal_id": token.principal_id,
                "clearance":    token.clearance,
                "issued_at":    token.issued_at,
                "expires_at":   token.expires_at,
                "valid":        token.is_valid(),
            }, 200
        except PrincipalNotFoundError:
            return {"error": f"Principal '{name}' not found"}, 404
        except Exception as e:
            return {"error": str(e)}, 401

    def _handle_audit(self, params: dict):
        agent_id = params.get("agent_id", [None])[0]
        outcome  = params.get("outcome", [None])[0]
        days     = int(params.get("days", ["30"])[0])
        limit    = int(params.get("limit", ["100"])[0])

        entries = self.journal.get_recent(
            agent_id=agent_id, outcome=outcome, days=days, limit=limit
        )
        chain_valid, _ = self.journal.verify_chain()

        return {
            "total":       len(entries),
            "chain_valid": chain_valid,
            "filter": {
                "agent_id": agent_id,
                "outcome":  outcome,
                "days":     days,
            },
            "entries": [e.to_dict() for e in entries],
        }, 200

    def _handle_audit_export(self, params: dict):
        """
        Export signed audit journal.
        ANSSI R29 / AI Act Art.12 — exportable compliance evidence.
        """
        agent_id = params.get("agent_id", [None])[0]
        outcome  = params.get("outcome", [None])[0]
        days     = int(params.get("days", ["30"])[0])

        export_json = self.journal.export_json(
            agent_id=agent_id, outcome=outcome, days=days
        )
        return json.loads(export_json), 200

    def _handle_vigil_agent_state(self, body: dict):
        """
        Vigil bridge — receive agent state update from Vigil.
        Stores agent in registry. Triggers evaluation if policy loaded
        and VRS crosses threshold.
        """
        agent_id   = body.get("agent_id", "")
        agent_name = body.get("agent_name", agent_id)
        vrs        = float(body.get("vrs", 0.0))
        tsi_state  = body.get("tsi_state", "STABLE")
        a2c_score  = float(body.get("a2c_score", 0.0))

        # Toujours enregistrer l agent dans le registre
        import time as _time
        self._agents[agent_id] = {
            "agent_id":   agent_id,
            "agent_name": agent_name,
            "vrs":        round(vrs, 4),
            "tsi_state":  tsi_state,
            "a2c_score":  round(a2c_score, 4),
            "updated_at": int(_time.time()),
        }

        if not self.policy:
            return {"outcome": "MONITOR", "vrs": vrs, "registered": True}, 200

        # Force évaluation si tsi_state CRITICAL ou ALERT (même si VRS sous seuil)
        if tsi_state in ("CRITICAL", "ALERT") and not (
            vrs >= self.policy.thresholds.vrs_require_human
        ):
            ctx = EvaluationContext(
                agent_id    = agent_id,
                agent_name  = agent_name,
                role        = body.get("role", "operator"),
                action      = "vigil_threshold_exceeded",
                payload     = {
                    "source": "vigil", "vrs": vrs,
                    "tsi_state": tsi_state, "forced": True,
                },
                vrs         = vrs,
                tsi_state   = tsi_state,
                a2c_score   = a2c_score,
                trust_score = body.get("trust_score", 0.0),
            )
            try:
                decision = engine_evaluate(ctx, self.policy)
                self.journal.record(decision)
                if decision.outcome == Outcome.REQUIRE_HUMAN:
                    self.queue.enqueue(decision)
                    self._notify_on_enqueue(decision)
                log.info(
                    "[TrustGate] tsi_state=%s forced eval → %s agent=%s",
                    tsi_state, decision.outcome, agent_name,
                )
            except Exception as e:
                log.warning("[TrustGate] forced eval failed: %s", e)

        # If VRS is above require_human threshold — auto-evaluate
        if vrs >= self.policy.thresholds.vrs_require_human:
            ctx = EvaluationContext(
                agent_id    = agent_id,
                agent_name  = agent_name,
                role        = body.get("role", "operator"),
                action      = "vigil_threshold_exceeded",
                payload     = {"source": "vigil", "vrs": vrs},
                vrs         = vrs,
                tsi_state   = tsi_state,
                a2c_score   = a2c_score,
                trust_score = body.get("trust_score", 0.0),
            )
            decision = engine_evaluate(ctx, self.policy)
            self.journal.record(decision)

            if decision.outcome == Outcome.REQUIRE_HUMAN:
                self.queue.enqueue(decision)
                self._notify_on_enqueue(decision)

            return {
                "decision_id": decision.decision_id,
                "outcome": (
                    decision.outcome.value if hasattr(decision.outcome, "value")
                    else str(decision.outcome).replace("Outcome.", "")
                ),
                "reason":      decision.reason,
            }, 200

        return {"outcome": "MONITOR", "vrs": vrs}, 200

    # ── Serialization helpers ─────────────────────────────────────────────────

    def _parse_context(self, body: dict) -> EvaluationContext:
        return EvaluationContext(
            agent_id      = body["agent_id"],
            agent_name    = body.get("agent_name", body["agent_id"]),
            role          = body.get("role", "operator"),
            action        = body["action"],
            payload       = body.get("payload", {}),
            vrs           = float(body.get("vrs", 0.0)),
            tsi_state     = body.get("tsi_state", "STABLE"),
            a2c_score     = float(body.get("a2c_score", 0.0)),
            trust_score   = float(body.get("trust_score", 1.0)),
            target_domain = body.get("target_domain"),
        )

    def _decision_summary(self, d: Decision) -> dict:
        return {
            "decision_id":  d.decision_id,
            "agent_id":     d.agent_id,
            "agent_name":   d.agent_name,
            "action":       d.action,
            "outcome":      d.outcome,
            "state":        d.state,
            "vrs":          d.vrs_at_decision,
            "tsi_state":    d.tsi_state,
            "reason":       d.reason,
            "timestamp":    d.timestamp,
            "timeout_at":   d.timeout_at,
        }

    def _principal_summary(self, p: HumanPrincipal) -> dict:
        return {
            "principal_id": p.record.principal_id,
            "name":         p.record.name,
            "email":        p.record.email,
            "clearance":    p.record.clearance,
            "mode":         p.record.mode,
            "active":       p.record.active,
            "last_login":   p.record.last_login,
        }

    # ── HTTP utilities ────────────────────────────────────────────────────────

    def _handle_console(self):
        """Serve Trust Gate Console HTML directly from the server.
        Avoids CORS issues when opened via file:// on Windows."""
        import pathlib
        console_path = pathlib.Path(__file__).parent / "console" / "trustgate_console.html"
        if not console_path.exists():
            return {
                "error": "Console not found — place trustgate_console.html in trustgate/console/"
            }, 404
        # Return as special tuple with content-type override
        return {"__html_file__": str(console_path)}, 200

    def _read_body(self, req) -> dict:
        length = int(req.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = req.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _send(self, req, status: int, data: dict) -> None:
        # Special case: redirect
        if isinstance(data, dict) and "__redirect__" in data:
            req.send_response(302)
            req.send_header("Location", data["__redirect__"])
            req.end_headers()
            return

        # Special case: serve a raw HTML file (for /console)
        if isinstance(data, dict) and "__html_file__" in data:
            html_path = data["__html_file__"]
            try:
                body = open(html_path, "rb").read()
                req.send_response(200)
                req.send_header("Content-Type", "text/html; charset=utf-8")
                req.send_header("Content-Length", str(len(body)))
                req.send_header("Access-Control-Allow-Origin", "*")
                req.end_headers()
                req.wfile.write(body)
            except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
                pass  # client disconnected — normal for browser tab close / Vigil timeout
            except Exception as e:
                log.debug(f"_send html error: {e}")
            return
        try:
            body = json.dumps(data, indent=2, default=str).encode("utf-8")
            req.send_response(status)
            req.send_header("Content-Type", "application/json")
            req.send_header("Content-Length", str(len(body)))
            req.send_header("X-TrustGate-Version", "1.0.0")
            req.send_header("Access-Control-Allow-Origin", "*")
            req.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            req.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            req.end_headers()
            req.wfile.write(body)
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass  # client disconnected (Vigil timeout, browser close) — not an error
        except Exception as e:
            log.debug(f"_send error (status={status}): {e}")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Trust Gate HTTP Server")
    parser.add_argument("--host",   default=DEFAULT_HOST,  help="Bind host")
    parser.add_argument("--port",   default=DEFAULT_PORT,  type=int, help="Port")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY_PATH), help="Policy YAML path")
    parser.add_argument(
        "--demo", action="store_true", help="Demo mode (no policy file required)"
    )
    args = parser.parse_args()

    server = TrustGateServer(
        host        = args.host,
        port        = args.port,
        policy_path = Path(args.policy),
        demo_mode   = args.demo,
    )

    def _shutdown(sig, frame):
        log.info("Shutting down Trust Gate...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    _tier_inf  = _AUTH.tier_info()
    _tg_level  = _tier_inf["trustgate_level"]
    _tier      = _tier_inf["tier"]
    _lic_status = _tier_inf.get("license_status", "free")
    _lic_exp    = _tier_inf.get("license_expires")

    print(f"\n{'━'*56}")
    print("  Trust Gate HTTP Server v1.7.0")
    print(f"  Listening on http://{args.host}:{args.port}")
    print(f"  Policy     : {args.policy}")
    print(f"  Demo mode  : {args.demo}")
    print(f"  Auth       : {'✅ ENABLED' if _AUTH.token else '⚠️  WARNING — set TRUSTGATE_TOKEN'}")
    print(f"  Tier       : {_tier.upper()}  [{_lic_status.upper()}]")
    if _lic_exp:
        print(f"  Expires    : {_lic_exp}")
    print(f"  Level      : {_tg_level or '🔒 UNAVAILABLE on Free — upgrade to Pro'}")

    # ── License gate — bloquer le démarrage de TrustGate en Free ─────────────
    if _tg_level is None:
        print("\n  ⚠️  TRUSTGATE IS LOCKED on Free tier.")
        print("     TrustGate requires Pro tier or above.")
        print("     Activate a license: piqrypt license activate <token>")
        print("     Or visit: https://piqrypt.com/pricing")
        if not args.demo:
            print("\n  Starting in DEMO mode (no enforcement).")
            args.demo = True  # Force demo si pas de licence valide
    elif _tg_level == "manual":
        print("  Mode       : Manual approval queue — automatic policies require Business tier")
    elif _tg_level == "full":
        print("  Mode       : Full automatic policies ✅")

    if _lic_status == "demo":
        print("\n  ⚠️  No valid license token — running in DEMO mode.")
        print("     Activate: piqrypt license activate <token>")

    if not _AUTH.token:
        import secrets as _sec
        print(f"  Generate   : export TRUSTGATE_TOKEN={_sec.token_urlsafe(32)}")
    print(f"{'━'*56}")
    print("  Press Ctrl+C to stop\n")

    server.start()


if __name__ == "__main__":
    main()
