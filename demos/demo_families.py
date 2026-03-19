"""
demo_families.py - PiQrypt Families Demo
==========================================
3 familles d'utilisateurs réelles — 9 agents — tier Free :

  [Nexus Labs]   DevOps/Infra — Ollama + LangGraph + CodeLlama
                   nexus_cicd      : bursts CI/CD, fork sur merge simultané (RFC §6)
                   nexus_monitor   : Prometheus scraper, temporal_sync Ollama
                   nexus_reviewer  : revue de code, concentration A2C

  [PixelFlow]    Créateur digital — CrewAI + Claude Haiku
                   pixelflow_content  : 3 sessions/jour, TSI drift
                   pixelflow_seo      : concentration 88% sur content
                   pixelflow_scheduler: même Haiku → temporal_sync

  [AlphaCore]    Quant Trading — AutoGen + GPT-4o + vLLM
                   alphacore_analyst  : bursts marché 9h/17h30
                   alphacore_executor : jitter ≤1s → temporal_sync CRITICAL
                   alphacore_risk     : triangle A2C fermé

Usage:
    python demos/demo_families.py                  # 1 cycle
    python demos/demo_families.py --loop           # boucle toutes les 20s
    python demos/demo_families.py --loop --fast    # boucle toutes les 5s
    python demos/demo_families.py --reset          # efface les agents
    python demos/demo_families.py --status         # état sans modifier
    python demos/demo_families.py --families       # scénarios Nexus+AlphaCore+PixelFlow
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _c in [_HERE, _HERE.parent]:
    if (_c / "aiss").is_dir():
        sys.path.insert(0, str(_c))
        break

PIQRYPT_DIR = Path.home() / ".piqrypt"
AGENTS_DIR  = PIQRYPT_DIR / "agents"

def _col(code, t): return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t
def GREEN(t):   return _col("92", t)
def YELLOW(t):  return _col("93", t)
def RED(t):     return _col("91", t)
def CYAN(t):    return _col("96", t)
def MAGENTA(t): return _col("95", t)
def BOLD(t):    return _col("1",  t)
def DIM(t):     return _col("2",  t)

# ── 9 agents — 3 familles uniquement ─────────────────────────────────────────
DEMO_AGENTS = [
    # Nexus Labs — DevOps/Infra — Ollama + LangGraph
    {"name": "nexus_cicd",          "profile": "alert",  "tier": "free",
     "role": "CI/CD Orchestrator",  "family": "nexus",
     "stack": "Ollama/CodeLlama + LangGraph", "signal": "fork_on_merge"},
    {"name": "nexus_monitor",       "profile": "watch",  "tier": "free",
     "role": "Infra Monitor",       "family": "nexus",
     "stack": "Ollama/Mistral + Prometheus",  "signal": "temporal_sync"},
    {"name": "nexus_reviewer",      "profile": "watch",  "tier": "free",
     "role": "Code Reviewer",       "family": "nexus",
     "stack": "Ollama/CodeLlama + LangChain", "signal": "a2c_concentration"},

    # PixelFlow Agency — Créateur digital — CrewAI + Claude Haiku
    {"name": "pixelflow_content",   "profile": "watch",  "tier": "free",
     "role": "Content Creator",     "family": "pixelflow",
     "stack": "CrewAI + Claude Haiku", "signal": "tsi_drift"},
    {"name": "pixelflow_seo",       "profile": "safe",   "tier": "free",
     "role": "SEO Analyst",         "family": "pixelflow",
     "stack": "CrewAI + Claude Haiku", "signal": "a2c_peers"},
    {"name": "pixelflow_scheduler", "profile": "alert",  "tier": "free",
     "role": "Social Scheduler",    "family": "pixelflow",
     "stack": "CrewAI + Claude Haiku", "signal": "temporal_sync"},

    # AlphaCore Trading — Quant — AutoGen + GPT-4o
    {"name": "alphacore_analyst",   "profile": "watch",  "tier": "free",
     "role": "Market Analyst",      "family": "alphacore",
     "stack": "AutoGen + GPT-4o",   "signal": "session_burst"},
    {"name": "alphacore_executor",  "profile": "alert",  "tier": "free",
     "role": "Order Executor",      "family": "alphacore",
     "stack": "AutoGen + GPT-4o + vLLM", "signal": "temporal_sync_critical"},
    {"name": "alphacore_risk",      "profile": "watch",  "tier": "free",
     "role": "Risk Controller",     "family": "alphacore",
     "stack": "AutoGen + GPT-4o",   "signal": "a2c_triangle"},
]

EXTERNAL_PEERS = [
    # Nexus Labs
    "github_webhook", "gitlab_ci", "sonarqube_api", "prometheus_scraper",
    "k8s_api_server", "vault_secrets", "docker_registry",
    # PixelFlow
    "anthropic_api", "openai_api", "google_search_console",
    "instagram_api", "twitter_api", "analytics_ga4",
    # AlphaCore
    "bloomberg_terminal", "binance_ws", "polygon_io",
    "redis_session", "postgres_state", "risk_db",
]

INTERACTION_MAP = {
    "nexus_cicd":          ["nexus_monitor",       "nexus_reviewer",      "github_webhook",    "k8s_api_server",  "docker_registry"],
    "nexus_monitor":       ["nexus_cicd",           "prometheus_scraper",  "k8s_api_server",   "vault_secrets"],
    "nexus_reviewer":      ["nexus_cicd",           "sonarqube_api",       "gitlab_ci",         "nexus_monitor"],
    "pixelflow_content":   ["pixelflow_scheduler",  "pixelflow_seo",       "anthropic_api",    "openai_api"],
    "pixelflow_seo":       ["pixelflow_content",    "google_search_console","analytics_ga4",   "pixelflow_scheduler"],
    "pixelflow_scheduler": ["pixelflow_content",    "instagram_api",       "twitter_api",       "pixelflow_seo"],
    "alphacore_analyst":   ["alphacore_executor",   "alphacore_risk",      "bloomberg_terminal","polygon_io"],
    "alphacore_executor":  ["alphacore_analyst",    "alphacore_risk",      "binance_ws",        "redis_session"],
    "alphacore_risk":      ["alphacore_analyst",    "alphacore_executor",  "risk_db",           "postgres_state"],
}

FAMILY_EVENT_TYPES = {
    "nexus": [
        "pipeline_trigger", "build_start", "build_success", "build_fail",
        "deploy_staging", "deploy_prod", "key_rotation", "secret_rotation",
        "merge_event", "code_review", "scan_complete", "alert_infra",
    ],
    "pixelflow": [
        "content_draft", "content_publish", "seo_analysis", "keyword_report",
        "schedule_post", "post_published", "engagement_report", "a2a_message",
        "api_call_anthropic", "api_call_openai", "analytics_pull",
    ],
    "alphacore": [
        "market_open", "market_close", "signal_generated", "order_submitted",
        "order_filled", "order_rejected", "risk_check", "position_update",
        "pnl_report", "compliance_stamp", "a2a_message", "session_heartbeat",
    ],
}

EVENTS_PER_CYCLE = {"safe": 40, "watch": 65, "alert": 120, "critical": 160}

SUB_CYCLES = 4
SUB_DELAY  = 1.2

# ── Profils des peers externes ────────────────────────────────────────────────
# volume_per_cycle : nb d'events vers ce peer par cycle
# latency_ms       : (min, max) latence simulée dans le payload
# pattern          : "steady" | "burst" (pics push/deploy) | "burst_open" (ouverture marché) | "scheduled" (3x/jour)
# event_type       : type d'event réaliste pour ce peer
EXTERNAL_PEER_PROFILES = {
    # Nexus Labs
    "github_webhook":     {"volume": 8,  "latency_ms": (80,   200),  "pattern": "burst",      "event_type": "pipeline_trigger"},
    "gitlab_ci":          {"volume": 4,  "latency_ms": (100,  300),  "pattern": "burst",      "event_type": "build_start"},
    "sonarqube_api":      {"volume": 3,  "latency_ms": (500,  1500), "pattern": "steady",     "event_type": "scan_complete"},
    "prometheus_scraper": {"volume": 12, "latency_ms": (10,   50),   "pattern": "steady",     "event_type": "metric_scrape"},
    "k8s_api_server":     {"volume": 6,  "latency_ms": (20,   80),   "pattern": "steady",     "event_type": "deploy_staging"},
    "vault_secrets":      {"volume": 2,  "latency_ms": (30,   100),  "pattern": "steady",     "event_type": "secret_rotation"},
    "docker_registry":    {"volume": 5,  "latency_ms": (200,  800),  "pattern": "burst",      "event_type": "deploy_prod"},
    # PixelFlow
    "anthropic_api":      {"volume": 10, "latency_ms": (800,  3000), "pattern": "scheduled",  "event_type": "api_call_anthropic"},
    "openai_api":         {"volume": 6,  "latency_ms": (600,  2500), "pattern": "scheduled",  "event_type": "api_call_openai"},
    "google_search_console": {"volume": 4, "latency_ms": (300, 900), "pattern": "scheduled",  "event_type": "seo_analysis"},
    "instagram_api":      {"volume": 5,  "latency_ms": (200,  600),  "pattern": "scheduled",  "event_type": "post_published"},
    "twitter_api":        {"volume": 5,  "latency_ms": (150,  500),  "pattern": "scheduled",  "event_type": "post_published"},
    "analytics_ga4":      {"volume": 3,  "latency_ms": (400,  1200), "pattern": "scheduled",  "event_type": "analytics_pull"},
    # AlphaCore
    "bloomberg_terminal": {"volume": 8,  "latency_ms": (5,    30),   "pattern": "burst_open", "event_type": "signal_generated"},
    "binance_ws":         {"volume": 20, "latency_ms": (1,    10),   "pattern": "burst_open", "event_type": "order_submitted"},
    "polygon_io":         {"volume": 6,  "latency_ms": (10,   50),   "pattern": "burst_open", "event_type": "signal_generated"},
    "redis_session":      {"volume": 15, "latency_ms": (1,    5),    "pattern": "steady",     "event_type": "session_heartbeat"},
    "postgres_state":     {"volume": 4,  "latency_ms": (5,    20),   "pattern": "steady",     "event_type": "position_update"},
    "risk_db":            {"volume": 3,  "latency_ms": (10,   40),   "pattern": "steady",     "event_type": "risk_check"},
}

FAMILIES = {
    "nexus":     {"label": "Nexus Labs (DevOps/Infra)",    "color": "CYAN"},
    "pixelflow": {"label": "PixelFlow Agency (Digital)",   "color": "MAGENTA"},
    "alphacore": {"label": "AlphaCore Trading (Quant)",    "color": "YELLOW"},
}

ALERT_TEMPLATES = {
    "alert": [
        {"type": "trust_drift",       "severity": "MEDIUM",   "msg": "Trust score degraded — suspicious peer interactions"},
        {"type": "rate_exceeded",     "severity": "HIGH",     "msg": "Message rate exceeded threshold (450/min vs limit 200)"},
        {"type": "unauthorized_peer", "severity": "HIGH",     "msg": "Interaction with non-registered peer detected"},
        {"type": "policy_breach",     "severity": "MEDIUM",   "msg": "Policy rule #7 violated: unverified data source"},
    ],
    "critical": [
        {"type": "injection_attempt", "severity": "CRITICAL", "msg": "Prompt injection attempt detected in payload"},
        {"type": "chain_fork",        "severity": "CRITICAL", "msg": "Event chain fork detected — possible replay attack"},
        {"type": "replay_attack",     "severity": "CRITICAL", "msg": "Duplicate nonce detected — replay attack blocked"},
        {"type": "signature_fail",    "severity": "CRITICAL", "msg": "Ed25519 signature verification failed"},
    ],
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(agent_id, peer_id, ts=None, tsa=False, previous_hash=None, event_type=None):
    import hashlib as _hl
    nonce = os.urandom(8).hex()
    ts    = ts or int(time.time())
    etype = event_type or "a2a_message"
    raw   = f"{agent_id}:{peer_id}:{ts}:{nonce}:{previous_hash or ''}"
    return {
        "agent_id":      agent_id,
        "peer_id":       peer_id,
        "event_type":    etype,
        "timestamp":     ts,
        "nonce":         nonce,
        "signature":     os.urandom(16).hex(),
        "tsa":           tsa,
        "previous_hash": previous_hash or "",
        "hash":          _hl.sha256(raw.encode()).hexdigest(),
        "payload":       {"event_type": etype, "peer_id": peer_id, "volume": random.randint(1, 10)},
    }

def _generate_external_events(agent_id, agent_name, all_ids):
    """
    Génère des events réalistes vers les peers externes de cet agent.
    Chaque peer a son propre pattern de volume et de latence.
    """
    now        = int(time.time())
    peer_names = INTERACTION_MAP.get(agent_name, [])
    evts       = []

    for peer_name in peer_names:
        prof = EXTERNAL_PEER_PROFILES.get(peer_name)
        if not prof:
            continue  # peer interne, géré par _generate_events

        peer_id  = peer_name  # peer externe = pas d'agent_id, juste le nom
        volume   = prof["volume"]
        lat_min, lat_max = prof["latency_ms"]
        pattern  = prof["pattern"]
        etype    = prof["event_type"]

        for _ in range(volume):
            # Timestamp selon pattern
            if pattern == "steady":
                ts = now - random.randint(0, 3600 * 8)
            elif pattern == "burst":
                # Pics autour de 2-3 moments dans la journée (push, deploy)
                burst_anchor = now - random.choice([3600, 7200, 14400])
                ts = burst_anchor + random.randint(-300, 300)
            elif pattern == "burst_open":
                # Ouverture/clôture marché — 9h et 17h30
                open_ts  = now - 8 * 3600
                close_ts = now - int(0.5 * 3600)
                anchor   = random.choice([open_ts, close_ts])
                ts = anchor + random.randint(-120, 120)
            elif pattern == "scheduled":
                # 3 sessions fixes dans la journée
                session_ts = now - random.choice([8*3600, 4*3600, 3600])
                ts = session_ts + random.randint(-600, 600)
            else:
                ts = now - random.randint(0, 3600 * 6)

            latency = random.randint(lat_min, lat_max)
            ev = _make_event(agent_id, peer_id, ts=ts, event_type=etype)
            ev["payload"]["external"]    = True
            ev["payload"]["peer_name"]   = peer_name
            ev["payload"]["latency_ms"]  = latency
            ev["payload"]["status"]      = random.choice(["200", "200", "200", "429", "503"]) \
                                           if pattern == "scheduled" else "200"
            evts.append(ev)

    return evts

def _family_event_type(name):
    ag     = next((a for a in DEMO_AGENTS if a["name"] == name), {})
    family = ag.get("family", "nexus")
    return random.choice(FAMILY_EVENT_TYPES.get(family, ["a2a_message"]))

def _write_events(agent_name, events):
    plain_dir = AGENTS_DIR / agent_name / "events" / "plain"
    plain_dir.mkdir(parents=True, exist_ok=True)
    by_month = {}
    for ev in events:
        month = time.strftime("%Y-%m", time.localtime(ev["timestamp"]))
        by_month.setdefault(month, []).append(ev)
    stored = 0
    for month, evts in by_month.items():
        fpath    = plain_dir / f"{month}.json"
        existing = []
        if fpath.exists():
            try:
                existing = json.loads(fpath.read_text(encoding="utf-8"))
                seen     = {e.get("nonce") for e in existing}
                evts     = [e for e in evts if e.get("nonce") not in seen]
            except Exception:
                existing = []
        if evts:
            existing.extend(evts)
            fpath.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            stored += len(evts)
    return stored

def _write_tsi_history(agent_id, profile):
    tsi_dir = PIQRYPT_DIR / "tsi"
    tsi_dir.mkdir(parents=True, exist_ok=True)
    safe_id = agent_id.replace("/", "_").replace("\\", "_")[:64]
    fpath   = tsi_dir / f"{safe_id}.json"
    now     = int(time.time())
    snaps   = []
    if profile == "safe":
        for i in range(30, -1, -1):
            snaps.append({"timestamp": now - i * 86400, "score": round(0.92 + random.uniform(-0.02, 0.02), 4)})
        last_state = "STABLE"
    elif profile == "watch":
        for i in range(30, -1, -1):
            drift = 0 if i > 5 else (5 - i) * 0.018
            snaps.append({"timestamp": now - i * 86400, "score": round(0.80 - drift + random.uniform(-0.02, 0.02), 4)})
        last_state = "WATCH"
    elif profile == "alert":
        for i in range(30, 1, -1):
            snaps.append({"timestamp": now - i * 86400, "score": round(0.82 + random.uniform(-0.005, 0.005), 4)})
        snaps.append({"timestamp": now - 86400, "score": round(0.80 + random.uniform(-0.005, 0.005), 4)})
        snaps.append({"timestamp": now - 3600,  "score": 0.35})
        snaps.append({"timestamp": now,          "score": 0.33})
        last_state = "UNSTABLE"
    else:
        last_state = "STABLE"
    fpath.write_text(json.dumps({
        "snapshots":      snaps,
        "last_state":     last_state,
        "unstable_since": (now - 50 * 3600) if profile == "alert" else None,
    }, indent=2), encoding="utf-8")
    return last_state

def _inject_alerts(name, agent_id, profile):
    if profile not in ("alert", "critical"):
        return 0
    alerts_path = AGENTS_DIR / name / "vigil" / "alerts.json"
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if alerts_path.exists():
        try: existing = json.loads(alerts_path.read_text(encoding="utf-8"))
        except: pass
    new_alerts = []
    for _ in range(random.randint(1, 3)):
        t = random.choice(ALERT_TEMPLATES[profile])
        new_alerts.append({
            "type": t["type"], "severity": t["severity"],
            "agent_name": name, "agent_id": agent_id,
            "message": t["msg"],
            "timestamp": int(time.time()) - random.randint(60, 1800),
            "details": f"agent={name} profile={profile}",
        })
    existing.extend(new_alerts)
    existing = sorted(existing, key=lambda x: x.get("timestamp", 0))[-100:]
    alerts_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return len(new_alerts)

def _inject_peers(ids):
    import hashlib
    peers_path = PIQRYPT_DIR / "peers.json"
    peers = {}

    # Peers internes — agents de la démo
    for name, aid in ids.items():
        ag = next(a for a in DEMO_AGENTS if a["name"] == name)
        peers[aid] = {
            "identity": {"version": "AISS-1.0", "agent_id": aid,
                         "agent_name": name,          # <-- nom lisible pour le graphe
                         "public_key": hashlib.sha256(aid.encode()).hexdigest()[:44],
                         "algorithm": "Ed25519", "capabilities": ["stamp", "verify"]},
            "agent_name":        name,                # <-- doublon de surface
            "first_seen":        int(time.time()) - 86400,
            "last_seen":         int(time.time()) - random.randint(10, 300),
            "interaction_count": random.randint(50, 800),
            "trust_score":       {"safe": 0.95, "watch": 0.65, "alert": 0.35, "critical": 0.10}[ag["profile"]],
            "external":          False,
            "family":            ag.get("family", ""),
        }

    # Peers externes — enregistrés avec leur nom comme peer_id
    active_ext = set()
    for name in ids:
        for peer_name in INTERACTION_MAP.get(name, []):
            if peer_name in EXTERNAL_PEER_PROFILES:
                active_ext.add(peer_name)

    for peer_name in active_ext:
        prof = EXTERNAL_PEER_PROFILES[peer_name]
        trust = random.uniform(0.70, 0.95)
        peers[peer_name] = {
            "identity": {"version": "AISS-1.0", "agent_id": peer_name,
                         "agent_name": peer_name,
                         "public_key": hashlib.sha256(peer_name.encode()).hexdigest()[:44],
                         "algorithm": "Ed25519", "capabilities": ["stamp"]},
            "agent_name":        peer_name,
            "first_seen":        int(time.time()) - 86400 * random.randint(7, 90),
            "last_seen":         int(time.time()) - random.randint(5, 300),
            "interaction_count": random.randint(50, 5000),
            "trust_score":       round(trust, 3),
            "external":          True,
            "external_type":     prof["pattern"],
            "avg_latency_ms":    round(sum(prof["latency_ms"]) / 2),
        }

    peers_path.write_text(json.dumps(peers, indent=2), encoding="utf-8")

def _agent_exists(name): return (AGENTS_DIR / name / "identity.json").exists()
def _get_agent_id(name):
    p = AGENTS_DIR / name / "identity.json"
    if p.exists():
        try: return json.loads(p.read_text(encoding="utf-8")).get("agent_id", name)
        except: pass
    return name
def _count_events(name):
    plain = AGENTS_DIR / name / "events" / "plain"
    if not plain.exists(): return 0
    total = 0
    for f in plain.glob("*.json"):
        try: total += len(json.loads(f.read_text(encoding="utf-8")))
        except: pass
    return total

# ── Génération d'events par signal ───────────────────────────────────────────

def _generate_events(agent_id, name, profile, all_ids):
    now        = int(time.time())
    peer_names = INTERACTION_MAP.get(name, list(all_ids.keys())[:3])
    peers      = [all_ids[p] if p in all_ids else p for p in peer_names]
    if not peers:
        peers = list(all_ids.values())[:3]
    n      = EVENTS_PER_CYCLE[profile]
    evts   = []
    signal = next((a.get("signal", "") for a in DEMO_AGENTS if a["name"] == name), "")

    if profile == "safe":
        prev_h = ""
        for _ in range(n):
            ev = _make_event(agent_id, random.choice(peers),
                             ts=now - random.randint(0, 3600 * 48),
                             previous_hash=prev_h, event_type=_family_event_type(name))
            prev_h = ev["hash"]; evts.append(ev)

    elif profile == "watch":
        dominant = peers[0]
        prev_h   = ""
        if signal == "temporal_sync":
            session_ts = now - random.randint(600, 3600)
            for i in range(n):
                ts   = session_ts + i * random.randint(28, 32)
                peer = dominant if random.random() < 0.80 else random.choice(peers[1:] or [dominant])
                ev   = _make_event(agent_id, peer, ts=ts, previous_hash=prev_h,
                                   event_type=_family_event_type(name))
                prev_h = ev["hash"]; evts.append(ev)
        elif signal == "session_burst":
            for session_ts in [now - 8*3600, now - int(0.5*3600)]:
                for i in range(n // 2):
                    ts = int(session_ts) + i * random.randint(15, 45)
                    ev = _make_event(agent_id, random.choice(peers), ts=ts, previous_hash=prev_h,
                                     event_type=_family_event_type(name))
                    prev_h = ev["hash"]; evts.append(ev)
        elif signal == "a2c_triangle":
            for i in range(n):
                peer = peers[i % len(peers)]
                ev   = _make_event(agent_id, peer,
                                   ts=now - random.randint(0, 3600 * 8),
                                   previous_hash=prev_h, event_type=_family_event_type(name))
                prev_h = ev["hash"]; evts.append(ev)
        else:
            for _ in range(n):
                peer = dominant if random.random() < 0.72 else random.choice(peers[1:] or [dominant])
                ev   = _make_event(agent_id, peer, ts=now - random.randint(0, 3600 * 24),
                                   previous_hash=prev_h, event_type=_family_event_type(name))
                prev_h = ev["hash"]; evts.append(ev)

    elif profile == "alert":
        dominant = peers[0]
        prev_h   = ""
        if signal == "fork_on_merge":
            burst_ts = now - random.randint(300, 1200)
            for i in range(n):
                tsa   = i < n // 4
                ts    = (burst_ts + random.randint(-3, 3)) if tsa else (now - random.randint(0, 3600 * 4))
                peer  = dominant if random.random() < 0.85 else random.choice(peers[1:] or [dominant])
                etype = "merge_event" if (tsa and i == n // 4 - 1) else _family_event_type(name)
                ev    = _make_event(agent_id, peer, ts=ts, tsa=tsa, previous_hash=prev_h, event_type=etype)
                prev_h = ev["hash"]; evts.append(ev)
        elif signal == "temporal_sync_critical":
            open_ts = now - 8 * 3600
            for i in range(n):
                ts   = int(open_ts) + i * 15 + random.randint(0, 1)
                peer = dominant if random.random() < 0.90 else random.choice(peers[1:] or [dominant])
                ev   = _make_event(agent_id, peer, ts=ts, tsa=True, previous_hash=prev_h,
                                   event_type=_family_event_type(name))
                prev_h = ev["hash"]; evts.append(ev)
        elif signal in ("a2c_peers", "tsi_drift"):
            for _ in range(n):
                peer = dominant if random.random() < 0.88 else random.choice(peers[1:] or [dominant])
                ev   = _make_event(agent_id, peer, ts=now - random.randint(0, 3600 * 6),
                                   previous_hash=prev_h, event_type=_family_event_type(name))
                prev_h = ev["hash"]; evts.append(ev)
        else:
            burst_ts = now - random.randint(300, 3600)
            for i in range(n):
                peer = dominant if random.random() < 0.92 else random.choice(peers[1:] or [dominant])
                tsa  = i < n // 3
                ts   = (burst_ts + random.randint(-5, 5)) if tsa else (now - random.randint(0, 3600 * 6))
                ev   = _make_event(agent_id, peer, ts=ts, tsa=tsa, previous_hash=prev_h,
                                   event_type=_family_event_type(name))
                prev_h = ev["hash"]; evts.append(ev)

    return sorted(evts, key=lambda e: e["timestamp"])

# ── Scénarios famille ─────────────────────────────────────────────────────────

def _inject_nexus_fork(ids):
    import json as _j
    agent_name = "nexus_cicd"
    aid = ids.get(agent_name)
    if not aid: return 0
    now = int(time.time())
    plain_dir = AGENTS_DIR / agent_name / "events" / "plain"
    plain_dir.mkdir(parents=True, exist_ok=True)
    all_events = []
    for fpath in sorted(plain_dir.glob("*.json")):
        try:
            data = _j.loads(fpath.read_text(encoding="utf-8"))
            all_events.extend(data if isinstance(data, list) else [data])
        except Exception: pass
    fork_point = all_events[-1].get("hash", "") if all_events else ""
    if not fork_point:
        root = _make_event(aid, ids.get("github_webhook", "ext"), ts=now - 600,
                           event_type="pipeline_trigger")
        fork_point = root["hash"]
    branch_a = _make_event(aid, ids.get("k8s_api_server", "ext"),
                           ts=now - 45, previous_hash=fork_point, event_type="deploy_prod")
    branch_b = _make_event(aid, ids.get("docker_registry", "ext"),
                           ts=now - 43, previous_hash=fork_point, event_type="merge_event")
    month = time.strftime("%Y-%m", time.localtime(now))
    fpath = plain_dir / f"{month}.json"
    existing = []
    if fpath.exists():
        try: existing = _j.loads(fpath.read_text(encoding="utf-8"))
        except Exception: pass
    seen    = {e.get("nonce") for e in existing}
    new_evs = [e for e in [branch_a, branch_b] if e.get("nonce") not in seen]
    existing.extend(new_evs)
    fpath.write_text(_j.dumps(existing, indent=2), encoding="utf-8")
    alerts_path = AGENTS_DIR / agent_name / "vigil" / "alerts.json"
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    existing_a = []
    if alerts_path.exists():
        try: existing_a = _j.loads(alerts_path.read_text(encoding="utf-8"))
        except Exception: pass
    existing_a.append({
        "type": "chain_fork", "severity": "CRITICAL",
        "agent_name": agent_name, "agent_id": aid,
        "message": f"Merge fork — deploy_prod ‖ merge_event at {fork_point[:16]}… (RFC AISS-1.1 §6)",
        "timestamp": now - 30, "details": "nexus_cicd: simultaneous merge main + feature branch",
    })
    alerts_path.write_text(_j.dumps(existing_a[-100:], indent=2), encoding="utf-8")
    return len(new_evs)


def _inject_alphacore_sync(ids):
    import json as _j
    now     = int(time.time())
    open_ts = now - random.randint(30, 120)
    targets = ["alphacore_analyst", "alphacore_executor", "alphacore_risk"]
    injected = 0
    for agent_name in targets:
        aid = ids.get(agent_name)
        if not aid: continue
        peer = ids.get("binance_ws", list(ids.values())[0])
        ts   = int(open_ts + random.uniform(-0.5, 0.5))
        ev   = _make_event(aid, peer, ts=ts, event_type="market_open")
        plain_dir = AGENTS_DIR / agent_name / "events" / "plain"
        plain_dir.mkdir(parents=True, exist_ok=True)
        month = time.strftime("%Y-%m", time.localtime(ts))
        fpath = plain_dir / f"{month}.json"
        existing = []
        if fpath.exists():
            try: existing = _j.loads(fpath.read_text(encoding="utf-8"))
            except Exception: pass
        seen = {e.get("nonce") for e in existing}
        if ev.get("nonce") not in seen:
            existing.append(ev)
            fpath.write_text(_j.dumps(existing, indent=2), encoding="utf-8")
            injected += 1
        alerts_path = AGENTS_DIR / agent_name / "vigil" / "alerts.json"
        alerts_path.parent.mkdir(parents=True, exist_ok=True)
        existing_a = []
        if alerts_path.exists():
            try: existing_a = _j.loads(alerts_path.read_text(encoding="utf-8"))
            except Exception: pass
        existing_a.append({
            "type": "temporal_sync", "severity": "CRITICAL",
            "agent_name": agent_name, "agent_id": aid,
            "message": f"Market open sync — 3 AlphaCore agents t={open_ts} (±0.5s) — AutoGen/GPT-4o commun",
            "timestamp": now - 60, "details": f"sync_window=1s agents={','.join(targets)}",
        })
        alerts_path.write_text(_j.dumps(existing_a[-100:], indent=2), encoding="utf-8")
    return injected


def _inject_pixelflow_cluster(ids):
    import json as _j
    now      = int(time.time())
    sessions = [now - 8*3600, now - 4*3600, now - 3600]
    total    = 0
    for session_ts in sessions:
        for agent_name in ["pixelflow_content", "pixelflow_scheduler"]:
            aid      = ids.get(agent_name)
            peer_aid = ids.get(
                "pixelflow_scheduler" if agent_name == "pixelflow_content" else "pixelflow_content",
                list(ids.values())[0])
            if not aid: continue
            for i in range(8):
                ts    = int(session_ts) + i * random.randint(55, 65)
                etype = "content_publish" if agent_name == "pixelflow_content" else "schedule_post"
                ev    = _make_event(aid, peer_aid, ts=ts, event_type=etype)
                plain_dir = AGENTS_DIR / agent_name / "events" / "plain"
                plain_dir.mkdir(parents=True, exist_ok=True)
                month = time.strftime("%Y-%m", time.localtime(ts))
                fpath = plain_dir / f"{month}.json"
                existing = []
                if fpath.exists():
                    try: existing = _j.loads(fpath.read_text(encoding="utf-8"))
                    except Exception: pass
                seen = {e.get("nonce") for e in existing}
                if ev.get("nonce") not in seen:
                    existing.append(ev)
                    fpath.write_text(_j.dumps(existing, indent=2), encoding="utf-8")
                    total += 1
    alerts_path = AGENTS_DIR / "pixelflow_scheduler" / "vigil" / "alerts.json"
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    existing_a = []
    if alerts_path.exists():
        try: existing_a = _j.loads(alerts_path.read_text(encoding="utf-8"))
        except Exception: pass
    existing_a.append({
        "type": "a2c_concentration", "severity": "HIGH",
        "agent_name": "pixelflow_scheduler", "agent_id": ids.get("pixelflow_scheduler", ""),
        "message": "3 sessions/jour content↔scheduler ±60s — même Claude Haiku (CrewAI) détecté",
        "timestamp": now - 120, "details": "sessions=3 window=60s concentration=88% same_llm=claude-haiku",
    })
    alerts_path.write_text(_j.dumps(existing_a[-100:], indent=2), encoding="utf-8")
    return total

# ── Agents ────────────────────────────────────────────────────────────────────

def create_agents():
    try:
        from aiss.identity import create_agent_identity
    except ImportError as e:
        print(RED(f"Import aiss.identity failed: {e}")); sys.exit(1)
    ids = {}
    print(BOLD("\n  Creating family agents"))
    print(DIM("  " + "-" * 55))
    current_family = None
    for ag in DEMO_AGENTS:
        name   = ag["name"]
        family = ag.get("family", "")
        if family != current_family:
            current_family = family
            finfo  = FAMILIES.get(family, {})
            fcol   = {"CYAN": CYAN, "MAGENTA": MAGENTA, "YELLOW": YELLOW}.get(finfo.get("color"), DIM)
            print(f"  {fcol('── ' + finfo.get('label', family))}")
        color = {"safe": GREEN, "watch": YELLOW, "alert": RED, "critical": MAGENTA}[ag["profile"]]
        if _agent_exists(name):
            aid = _get_agent_id(name)
            print(f"  {DIM('exists')}  {name:<26} {DIM(aid[:20]+'...')}")
        else:
            r   = create_agent_identity(agent_name=name, passphrase=None, tier=ag["tier"],
                                        metadata={"demo": True, "family": family})
            aid = r["agent_id"]
            print(f"  {color('created')} {name:<26} {DIM(aid[:20]+'...')}")
        ids[name] = aid
    return ids

def inject_cycle(ids, cycle):
    print(BOLD(f"\n  Cycle {cycle} -- {datetime.now().strftime('%H:%M:%S')}"))
    print(DIM("  " + "-" * 60))
    total_events   = 0
    total_alerts   = 0

    # Génère tous les events d'abord
    agent_events = {}
    current_family = None
    for ag in DEMO_AGENTS:
        name   = ag["name"]
        family = ag.get("family", "")
        aid    = ids.get(name)
        if not aid: continue
        evts     = _generate_events(aid, name, ag["profile"], ids)
        ext_evts = _generate_external_events(aid, name, ids)
        agent_events[name] = (ag, aid, evts, ext_evts)

    # Injection progressive en sous-cycles
    agent_list = list(agent_events.items())
    for sub in range(SUB_CYCLES):
        if sub > 0:
            time.sleep(SUB_DELAY)
        for name, (ag, aid, evts, ext_evts) in agent_list:
            all_evts  = evts + ext_evts
            n_total   = len(all_evts)
            per_sub   = max(1, n_total // SUB_CYCLES)
            start_idx = sub * per_sub
            end_idx   = (start_idx + per_sub) if sub < SUB_CYCLES - 1 else n_total
            sub_evts  = all_evts[start_idx:end_idx]
            if sub_evts:
                _write_events(name, sub_evts)

    # Stats + alertes (une fois à la fin)
    current_family = None
    for name, (ag, aid, evts, ext_evts) in agent_list:
        family   = ag.get("family", "")
        profile  = ag["profile"]
        if family != current_family:
            current_family = family
            finfo  = FAMILIES.get(family, {})
            fcol   = {"CYAN": CYAN, "MAGENTA": MAGENTA, "YELLOW": YELLOW}.get(finfo.get("color"), DIM)
            print(f"  {fcol('── ' + finfo.get('label', family))}")
        color     = {"safe": GREEN, "watch": YELLOW, "alert": RED, "critical": MAGENTA}[profile]
        stored    = len(evts) + len(ext_evts)
        tsi_state = _write_tsi_history(aid, profile)
        alerts    = _inject_alerts(name, aid, profile)
        all_evts  = evts + ext_evts
        peer_count = {}
        for e in all_evts: peer_count[e["peer_id"]] = peer_count.get(e["peer_id"], 0) + 1
        dom = max(peer_count, key=peer_count.get) if peer_count else "?"
        pct = 100 * peer_count.get(dom, 0) / len(all_evts) if all_evts else 0
        ext_count = len(ext_evts)
        stack_s   = DIM(f" [{ag.get('stack', '')}]") if ag.get("stack") else ""
        alert_s   = f"  {RED(f'+{alerts}al')}" if alerts else ""
        ext_s     = f"  {DIM(f'ext={ext_count}')}" if ext_count else ""
        plabel    = color(f"[{profile.upper():<8}]")
        print(f"  {plabel} {name:<26} +{stored:>3}ev  tsi={tsi_state:<8} conc={pct:3.0f}%{alert_s}{ext_s}{stack_s}")
        total_events += stored
        total_alerts += alerts

    _inject_peers(ids)

    # Scénarios famille toutes les 3 cycles
    attack_str = ""
    if cycle % 3 == 0:
        print(f"\n  {BOLD(MAGENTA('⚡ Scénarios -- cycle ' + str(cycle)))}")
        nexus_forks = _inject_nexus_fork(ids)
        alpha_sync  = _inject_alphacore_sync(ids)
        pixel_evts  = _inject_pixelflow_cluster(ids)
        print(f"  {CYAN('nexus_cicd')}     → {nexus_forks} fork events (merge simultané CI/CD → CRITICAL)")
        print(f"  {YELLOW('alphacore ×3')} → {alpha_sync} agents market_open sync (±0.5s → CRITICAL)")
        print(f"  {MAGENTA('pixelflow ×2')} → {pixel_evts} events 3 sessions (A2C cluster HIGH)")
        attack_str = f"  {MAGENTA('⚡ 3 familles')}"

    print(DIM("  " + "-" * 60))
    print(f"  {GREEN(str(total_events))} events  {RED(str(total_alerts))} alerts{attack_str}  → Vigil recalcule dans 5s")

def show_status(ids):
    print(BOLD("\n  Status — 9 agents · 3 familles"))
    print(DIM("  " + "-" * 60))
    current_family = None
    for ag in DEMO_AGENTS:
        name   = ag["name"]
        family = ag.get("family", "")
        if family != current_family:
            current_family = family
            finfo  = FAMILIES.get(family, {})
            fcol   = {"CYAN": CYAN, "MAGENTA": MAGENTA, "YELLOW": YELLOW}.get(finfo.get("color"), DIM)
            print(f"  {fcol('── ' + finfo.get('label', family))}")
        prof   = ag["profile"]
        color  = {"safe": GREEN, "watch": YELLOW, "alert": RED, "critical": MAGENTA}[prof]
        ok     = GREEN("OK") if _agent_exists(name) else RED("XX")
        stack  = DIM(f" [{ag.get('stack', '')}]") if ag.get("stack") else ""
        plabel = color(f"[{prof.upper():<8}]")
        print(f"  {ok} {plabel} {name:<26} {_count_events(name):>5} events{stack}")

def reset_agents():
    import shutil
    print(BOLD("\n  Resetting family agents..."))
    reg = PIQRYPT_DIR / "registry.json"
    if reg.exists():
        try:
            data  = json.loads(reg.read_text(encoding="utf-8"))
            names = {ag["name"] for ag in DEMO_AGENTS}
            if isinstance(data, dict) and "agents" in data:
                data["agents"] = {k: v for k, v in data["agents"].items() if k not in names}
            reg.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"  {YELLOW('!')} registry: {e}")
    for ag in DEMO_AGENTS:
        d = AGENTS_DIR / ag["name"]
        if d.exists():
            shutil.rmtree(d)
            print(f"  {GREEN('removed')} {ag['name']}")
    print(GREEN("  Done."))

def main():
    parser = argparse.ArgumentParser(description="PiQrypt Families Demo")
    parser.add_argument("--loop",     action="store_true", help="Boucle continue")
    parser.add_argument("--fast",     action="store_true", help="Cycle rapide 5s")
    parser.add_argument("--reset",    action="store_true", help="Effacer les agents")
    parser.add_argument("--status",   action="store_true", help="État sans modifier")
    parser.add_argument("--interval", type=int, default=20, help="Secondes entre cycles")
    parser.add_argument("--families", action="store_true", help="Scénarios familles uniquement")
    parser.add_argument("--family",   type=str, default=None,
                        choices=["nexus", "pixelflow", "alphacore"],
                        help="Famille active : nexus | pixelflow | alphacore (3 agents)")
    args     = parser.parse_args()
    interval = 5 if args.fast else args.interval

    # ── Filtrer DEMO_AGENTS selon --family ───────────────────────────
    global DEMO_AGENTS
    if args.family:
        DEMO_AGENTS = [a for a in DEMO_AGENTS if a["family"] == args.family]
        finfo = FAMILIES.get(args.family, {})
        fcol  = {"CYAN": CYAN, "MAGENTA": MAGENTA, "YELLOW": YELLOW}.get(finfo.get("color"), DIM)
        print()
        print(BOLD(fcol(f"  PiQrypt Demo — {finfo.get('label', args.family)}")))
    else:
        print()
        print(BOLD(CYAN("  PiQrypt Families Demo — Nexus · PixelFlow · AlphaCore")))
    print(DIM("  " + "=" * 55))

    if args.reset:
        reset_agents(); return

    ids = create_agents()

    if args.status:
        show_status(ids); return

    if args.families:
        print(BOLD(CYAN("\n  ⚡ Scénarios Familles")))
        print(DIM("  " + "-" * 55))
        nexus_forks = _inject_nexus_fork(ids)
        alpha_sync  = _inject_alphacore_sync(ids)
        pixel_evts  = _inject_pixelflow_cluster(ids)
        print(f"  {CYAN('Nexus Labs')}  → {nexus_forks} fork events  (merge CI/CD → CRITICAL)")
        print(f"  {YELLOW('AlphaCore')} → {alpha_sync} agents sync   (market_open ±0.5s → CRITICAL)")
        print(f"  {MAGENTA('PixelFlow')} → {pixel_evts} events        (3 sessions → A2C HIGH)")
        print(GREEN("\n  Done. Recharge Vigil pour voir les alertes."))
        return

    cycle = 1
    inject_cycle(ids, cycle)

    if args.loop:
        print(f"\n  {DIM(f'Loop active -- every {interval}s -- Ctrl+C to stop')}")
        try:
            while True:
                time.sleep(interval); cycle += 1; inject_cycle(ids, cycle)
        except KeyboardInterrupt:
            print(f"\n  {YELLOW('Demo stopped.')}"); show_status(ids)

if __name__ == "__main__":
    main()
