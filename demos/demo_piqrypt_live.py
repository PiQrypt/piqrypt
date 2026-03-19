"""
demo_piqrypt_live.py - PiQrypt Live Demo
=========================================
Demo parlante pour presentations :
- 10 agents metier avec profils realistes (trading, compliance, risk, LLM...)
- Events qui declenchent VRAIMENT les algorithmes VRS (concentration peers, burst)
- TSI history avec derive reelle -> UNSTABLE/CRITICAL
- Alertes injectees dans le bon format Vigil
- Interactions A2A realistes (qui parle a qui)
- Mode --loop pour animation continue
- Mode --fast pour demo live (5s)

Usage:
    python demo_piqrypt_live.py                    # 1 cycle
    python demo_piqrypt_live.py --loop             # boucle toutes les 20s
    python demo_piqrypt_live.py --loop --fast      # boucle toutes les 5s
    python demo_piqrypt_live.py --reset            # efface les agents demo
    python demo_piqrypt_live.py --status           # etat sans modifier
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

DEMO_AGENTS = [
    {"name": "trading_bot_alpha",  "profile": "safe",     "tier": "free", "role": "Trading Execution"},
    {"name": "trading_bot_beta",   "profile": "safe",     "tier": "free", "role": "Trading Execution"},
    {"name": "sentiment_ai",       "profile": "safe",     "tier": "free", "role": "Market Sentiment"},
    {"name": "data_aggregator",    "profile": "safe",     "tier": "free", "role": "Data Pipeline"},
    {"name": "risk_engine",        "profile": "watch",    "tier": "free", "role": "Risk Management"},
    {"name": "compliance_watch",   "profile": "watch",    "tier": "free", "role": "Compliance Monitor"},
    {"name": "anomaly_detector",   "profile": "alert",    "tier": "free", "role": "Anomaly Detection"},
    {"name": "shadow_agent",       "profile": "alert",    "tier": "free", "role": "Unverified Source"},
    {"name": "rogue_llm",          "profile": "critical", "tier": "free", "role": "External LLM"},
    {"name": "compromised_node",   "profile": "critical", "tier": "free", "role": "Compromised Agent"},
]

EXTERNAL_PEERS = [
    "exchange_api_binance", "exchange_api_kraken", "oracle_net_chainlink",
    "relay_node_eu", "market_feed_bloomberg", "data_hub_ext", "chain_validator",
]

INTERACTION_MAP = {
    "trading_bot_alpha":  ["risk_engine",      "data_aggregator",   "exchange_api_binance", "oracle_net_chainlink"],
    "trading_bot_beta":   ["risk_engine",      "data_aggregator",   "exchange_api_kraken"],
    "sentiment_ai":       ["data_aggregator",  "trading_bot_alpha", "market_feed_bloomberg"],
    "data_aggregator":    ["sentiment_ai",     "risk_engine",       "oracle_net_chainlink"],
    "risk_engine":        ["compliance_watch", "anomaly_detector",  "trading_bot_alpha", "trading_bot_beta"],
    "compliance_watch":   ["risk_engine",      "data_aggregator",   "relay_node_eu"],
    "anomaly_detector":   ["risk_engine",      "shadow_agent",      "compromised_node"],
    "shadow_agent":       ["rogue_llm",        "compromised_node",  "exchange_api_binance"],
    "rogue_llm":          ["shadow_agent",     "compromised_node",  "chain_validator"],
    "compromised_node":   ["rogue_llm",        "shadow_agent",      "exchange_api_binance"],
}

EVENTS_PER_CYCLE = {"safe": 40, "watch": 65, "alert": 120, "critical": 160}

# Nombre de sous-cycles par cycle principal — chaque sous-cycle écrit une fraction
# des events avec un délai, ce qui donne des incréments progressifs au dashboard
SUB_CYCLES = 4          # 4 petits lots au lieu d'un gros paquet
SUB_DELAY  = 1.2        # secondes entre sous-cycles (4 × 1.2s = 4.8s d'étalement)

def _make_event(agent_id, peer_id, ts=None, tsa=False, previous_hash=None, event_type=None):
    import hashlib as _hl
    nonce  = os.urandom(8).hex()
    ts     = ts or int(time.time())
    etype  = event_type or "a2a_message"
    raw    = f"{agent_id}:{peer_id}:{ts}:{nonce}:{previous_hash or ''}"
    ehash  = _hl.sha256(raw.encode()).hexdigest()
    return {
        "agent_id":      agent_id,
        "peer_id":       peer_id,
        "event_type":    etype,
        "timestamp":     ts,
        "nonce":         nonce,
        "signature":     os.urandom(16).hex(),
        "tsa":           tsa,
        "previous_hash": previous_hash or "",
        "hash":          ehash,
        "payload":       {"event_type": etype, "peer_id": peer_id, "volume": random.randint(1, 10)},
    }

def _generate_events(agent_id, name, profile, all_ids):
    now        = int(time.time())
    peer_names = INTERACTION_MAP.get(name, list(all_ids.keys())[:4])
    peers      = [all_ids[p] if p in all_ids else p for p in peer_names]
    if not peers:
        peers = list(all_ids.values())[:3]
    n    = EVENTS_PER_CYCLE[profile]
    evts = []

    if profile == "safe":
        pool = peers[:min(6, len(peers))]
        prev_h = ""
        for _ in range(n):
            ev = _make_event(agent_id, random.choice(pool), ts=now - random.randint(0, 3600 * 48), previous_hash=prev_h)
            prev_h = ev["hash"]; evts.append(ev)

    elif profile == "watch":
        dominant = peers[0]
        prev_h = ""
        for _ in range(n):
            peer = dominant if random.random() < 0.72 else random.choice(peers[1:] or [dominant])
            ev = _make_event(agent_id, peer, ts=now - random.randint(0, 3600 * 24), previous_hash=prev_h)
            prev_h = ev["hash"]; evts.append(ev)

    elif profile == "alert":
        dominant = peers[0]
        burst_ts = now - random.randint(300, 3600)
        prev_h = ""
        for i in range(n):
            if random.random() < 0.92:
                peer = dominant
                tsa  = i < n // 3
                ts   = (burst_ts + random.randint(-5, 5)) if tsa else (now - random.randint(0, 3600 * 6))
            else:
                peer = random.choice(peers[1:] or [dominant])
                tsa, ts = False, now - random.randint(0, 3600 * 12)
            ev = _make_event(agent_id, peer, ts=ts, tsa=tsa, previous_hash=prev_h)
            prev_h = ev["hash"]; evts.append(ev)

    elif profile == "critical":
        dominant = peers[0]
        burst_ts = now - random.randint(60, 600)
        prev_h = ""
        for i in range(n):
            tsa = i < n // 2
            ts  = (burst_ts + random.randint(-2, 2)) if tsa else (now - random.randint(0, 3600))
            ev = _make_event(agent_id, dominant, ts=ts, tsa=tsa, previous_hash=prev_h)
            prev_h = ev["hash"]; evts.append(ev)

    return sorted(evts, key=lambda e: e["timestamp"])

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
        # Baseline stable 25j puis chute brutale: delta_24h = 0.35 - 0.80 = -0.45 << -0.15 -> UNSTABLE
        for i in range(30, 1, -1):
            snaps.append({"timestamp": now - i * 86400, "score": round(0.82 + random.uniform(-0.005, 0.005), 4)})
        snaps.append({"timestamp": now - 86400, "score": round(0.80 + random.uniform(-0.005, 0.005), 4)})
        snaps.append({"timestamp": now - 3600,  "score": 0.35})
        snaps.append({"timestamp": now,          "score": 0.33})
        last_state = "UNSTABLE"
    elif profile == "critical":
        # Baseline stable 25j puis effondrement: delta_24h = 0.12 - 0.83 = -0.71 -> UNSTABLE
        # unstable_since = 72h -> CRITICAL (> 48h seuil)
        for i in range(30, 1, -1):
            snaps.append({"timestamp": now - i * 86400, "score": round(0.85 + random.uniform(-0.005, 0.005), 4)})
        snaps.append({"timestamp": now - 86400, "score": round(0.83 + random.uniform(-0.005, 0.005), 4)})
        snaps.append({"timestamp": now - 3600,  "score": 0.14})
        snaps.append({"timestamp": now,          "score": 0.12})
        last_state = "UNSTABLE"
    else:
        last_state = "STABLE"

    fpath.write_text(json.dumps({
        "snapshots":      snaps,
        "last_state":     last_state,
        "unstable_since": (now - 72 * 3600) if profile == "critical" else
                          (now - 50 * 3600) if profile == "alert" else None,
    }, indent=2), encoding="utf-8")
    return last_state

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

def _inject_alerts(name, agent_id, profile):
    if profile not in ("alert", "critical"):
        return 0
    alerts_path = AGENTS_DIR / name / "vigil" / "alerts.json"
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if alerts_path.exists():
        try: existing = json.loads(alerts_path.read_text(encoding="utf-8"))
        except: pass
    n          = random.randint(1, 3)
    new_alerts = []
    for _ in range(n):
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
    for name, aid in ids.items():
        ag = next(a for a in DEMO_AGENTS if a["name"] == name)
        peers[aid] = {
            "identity": {"version": "AISS-1.0", "agent_id": aid,
                         "agent_name": name,          # <-- nom lisible pour le graphe
                         "public_key": hashlib.sha256(aid.encode()).hexdigest()[:44],
                         "algorithm": "Ed25519", "capabilities": ["stamp", "verify"]},
            "agent_name":        name,                # <-- doublon de surface pour anomaly_monitor
            "first_seen":        int(time.time()) - 86400,
            "last_seen":         int(time.time()) - random.randint(10, 300),
            "interaction_count": random.randint(50, 800),
            "trust_score":       {"safe": 0.95, "watch": 0.65, "alert": 0.35, "critical": 0.10}[ag["profile"]],
            "external":          False,
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

def create_agents():
    try:
        from aiss.identity import create_agent_identity
    except ImportError as e:
        print(RED(f"Import aiss.identity failed: {e}")); sys.exit(1)

    ids = {}
    print(BOLD("\n  Creating demo agents"))
    print(DIM("  " + "-" * 55))
    for ag in DEMO_AGENTS:
        name    = ag["name"]
        profile = ag["profile"]
        color   = {"safe": GREEN, "watch": YELLOW, "alert": RED, "critical": MAGENTA}[profile]
        if _agent_exists(name):
            aid = _get_agent_id(name)
            print(f"  {DIM('exists')}  {name:<25} {DIM(aid[:20]+'...')}")
        else:
            r   = create_agent_identity(agent_name=name, passphrase=None, tier=ag["tier"],
                                        metadata={"demo": True, "profile": profile})
            aid = r["agent_id"]
            print(f"  {color('created')} {name:<25} {DIM(aid[:20]+'...')}")
        ids[name] = aid
    return ids


# ─── Scénarios d'attaque réels ────────────────────────────────────────────────

def _inject_fork_scenario(ids):
    """
    Injecte un vrai fork détectable par find_forks() de fork.py.
    Stratégie RFC AISS-1.1 §6 : 2 events avec le même previous_hash
    depuis le même agent → ForkDetector.detect() retourne ForkDetected.
    """
    import json as _j
    now = int(time.time())
    injected = []

    for agent_name in ["rogue_llm", "shadow_agent"]:
        aid = ids.get(agent_name)
        if not aid:
            continue

        plain_dir = AGENTS_DIR / agent_name / "events" / "plain"
        plain_dir.mkdir(parents=True, exist_ok=True)

        # Lire le dernier event pour obtenir son hash (fork point)
        all_events = []
        for fpath in sorted(plain_dir.glob("*.json")):
            try:
                data = _j.loads(fpath.read_text(encoding="utf-8"))
                all_events.extend(data if isinstance(data, list) else [data])
            except Exception:
                pass

        if all_events:
            all_events.sort(key=lambda e: e.get("timestamp", 0))
            fork_point_hash = all_events[-1].get("hash", "")
        else:
            # Créer un event racine d'abord
            root = _make_event(aid, ids.get("compromised_node", "ext"), ts=now - 7200)
            fork_point_hash = root.get("hash", "")
            all_events = [root]

        # Branche A — continuation légitime (même previous_hash)
        branch_a = _make_event(
            aid, ids.get("compromised_node", "ext"),
            ts=now - 120, previous_hash=fork_point_hash,
            event_type="a2a_message",
        )
        # Branche B — MÊME previous_hash = fork réel détectable par find_forks()
        branch_b = _make_event(
            aid, ids.get("data_aggregator", ids.get("chain_validator", "ext")),
            ts=now - 118, previous_hash=fork_point_hash,
            event_type="key_rotation",   # type différent = bifurcation intentionnelle
        )

        month = time.strftime("%Y-%m", time.localtime(now))
        fpath = plain_dir / f"{month}.json"
        existing = []
        if fpath.exists():
            try: existing = _j.loads(fpath.read_text(encoding="utf-8"))
            except Exception: pass

        seen = {e.get("nonce") for e in existing}
        new_evs = [e for e in [branch_a, branch_b] if e.get("nonce") not in seen]
        existing.extend(new_evs)
        fpath.write_text(_j.dumps(existing, indent=2), encoding="utf-8")
        injected.append((agent_name, len(new_evs)))

        # Alerte chain_fork dans vigil/alerts.json (format attendu par anomaly_monitor)
        alerts_path = AGENTS_DIR / agent_name / "vigil" / "alerts.json"
        alerts_path.parent.mkdir(parents=True, exist_ok=True)
        existing_a = []
        if alerts_path.exists():
            try: existing_a = _j.loads(alerts_path.read_text(encoding="utf-8"))
            except Exception: pass
        existing_a.append({
            "type":       "chain_fork",
            "severity":   "CRITICAL",
            "agent_name": agent_name,
            "agent_id":   aid,
            "message":    f"Fork at hash {fork_point_hash[:16]}… — branch_a=a2a_message / branch_b=key_rotation",
            "timestamp":  now - 60,
            "details":    f"fork_point={fork_point_hash[:16]} branches=2 rfc=AISS-1.1-§6",
        })
        alerts_path.write_text(_j.dumps(existing_a[-100:], indent=2), encoding="utf-8")

    return injected


def _inject_temporal_sync(ids):
    """
    4 agents stampent au même timestamp exact (±0ms).
    Signature d'un orchestrateur externe / même LLM.
    Détectable par A2C temporal_sync dans anomaly_monitor.
    """
    import json as _j
    now     = int(time.time())
    sync_ts = now - 300   # il y a 5 min

    targets = ["rogue_llm", "shadow_agent", "compromised_node", "anomaly_detector"]
    injected = 0

    for agent_name in targets:
        aid = ids.get(agent_name)
        if not aid:
            continue
        peer_aid = ids.get("chain_validator", list(ids.values())[0])
        ev = _make_event(aid, peer_aid, ts=sync_ts, event_type="synchronized_stamp")

        plain_dir = AGENTS_DIR / agent_name / "events" / "plain"
        plain_dir.mkdir(parents=True, exist_ok=True)
        month = time.strftime("%Y-%m", time.localtime(sync_ts))
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
            "type":       "temporal_sync",
            "severity":   "HIGH",
            "agent_name": agent_name,
            "agent_id":   aid,
            "message":    f"Temporal sync — {len(targets)} agents stampent à t={sync_ts} (±0ms) — même LLM détecté",
            "timestamp":  now - 290,
            "details":    f"sync_window=0ms agents={','.join(targets)}",
        })
        alerts_path.write_text(_j.dumps(existing_a[-100:], indent=2), encoding="utf-8")

    return injected


# ─── Simulation multi-sessions trading ───────────────────────────────────────

TRADING_ROLES = [
    {"name": "analyst",    "role": "MarketAnalyst",  "maps_to": "data_aggregator"},
    {"name": "trader",     "role": "TraderBot",       "maps_to": "risk_engine"},
    {"name": "risk_mgr",   "role": "RiskManager",     "maps_to": "compliance_watch"},
    {"name": "compliance", "role": "ComplianceAgent", "maps_to": "trading_bot_alpha"},
]

TRADING_MSGS = [
    "{role}: BTC {price}k$ sentiment={sent} → long {size}?",
    "{role}: Confirm trade size={size} SL={sl}% TP={tp}%",
    "{role}: Volatility spike, Nasdaq corr={corr:.2f}. Reject?",
    "{role}: KYC OK AML clean. Stamp authorized for {size}.",
    "{role}: Execution confirmed P&L={pnl:+.1f}%. Audit logged.",
    "{role}: Compliance rule#7 — unverified source flagged.",
]


def run_trading_simulation(ids, n_sessions=3, n_interactions=8):
    """
    Simule N sessions de trading multi-agents sur le même LLM sous-jacent.

    Ce qui rend la simulation parlante pour PiQrypt :
    - 4 rôles différents (analyst/trader/risk/compliance)
    - Même LLM → jitter timestamp ±0.5s entre agents (fenêtre de 2s)
    - Anomaly_monitor détecte la synchronisation comme temporal_sync HIGH
    - Chaque session forme une chaîne liée (previous_hash → hash)
    - 3 sessions = dérive TSI visible sur trading_bot_alpha
    """
    import json as _j, hashlib as _hl
    now = int(time.time())
    source_name = "trading_bot_alpha"
    source_aid  = ids.get(source_name, "")

    print(BOLD("\n  Trading Simulation — Multi-Session (même LLM)"))
    print(DIM("  " + "-" * 55))
    print(f"  {DIM('Sessions:')} {n_sessions}  {DIM('Interactions/session:')} {n_interactions}")
    print(f"  {DIM('Agents:')} analyst · trader · risk_mgr · compliance")
    print(f"  {DIM('Jitter:')} ±0.5s (signature LLM commun)")
    print()

    total = 0
    prev_hashes = {r["name"]: "" for r in TRADING_ROLES}

    for session in range(n_sessions):
        session_ts = now - (n_sessions - session) * 1800  # 30min entre sessions
        print(f"  Session {session+1}/{n_sessions}  "
              f"{DIM(datetime.fromtimestamp(session_ts).strftime('%H:%M'))}", end="  ")

        session_events = 0
        for i in range(n_interactions):
            msg_ts = session_ts + i * 15   # 1 tour toutes les 15s

            for role in TRADING_ROLES:
                # Jitter ±0.5s — même LLM = latences similaires
                ts = int(msg_ts + (random.uniform(-0.5, 0.5) if i > 0 else 0))

                msg = random.choice(TRADING_MSGS).format(
                    role=role["role"],
                    price=round(60 + random.uniform(-3, 3), 2),
                    sent=random.choice(["bullish", "bearish", "neutral"]),
                    size=random.choice(["10k", "50k", "100k"]),
                    sl=round(random.uniform(1, 5), 1),
                    tp=round(random.uniform(3, 10), 1),
                    pnl=round(random.uniform(-3, 5), 1),
                    corr=round(random.uniform(0.3, 0.9), 2),
                )
                target_aid = ids.get(role["maps_to"], list(ids.values())[0])

                ev = _make_event(
                    source_aid, target_aid,
                    ts=ts, previous_hash=prev_hashes[role["name"]],
                    event_type="trading_interaction",
                )
                ev["payload"]["message"]      = msg[:80]
                ev["payload"]["role"]         = role["role"]
                ev["payload"]["session"]      = session + 1
                ev["payload"]["payload_hash"] = _hl.sha256(msg.encode()).hexdigest()[:16]
                prev_hashes[role["name"]] = ev["hash"]

                # Écrire dans trading_bot_alpha (source commune = même LLM)
                if source_aid:
                    plain_dir = AGENTS_DIR / source_name / "events" / "plain"
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
                        total += 1; session_events += 1

        print(f"{GREEN(str(session_events))} stamps  {DIM('jitter ±0.5s')}")

    # Alerte A2C temporal_sync sur trading_bot_alpha
    if source_aid:
        alerts_path = AGENTS_DIR / source_name / "vigil" / "alerts.json"
        alerts_path.parent.mkdir(parents=True, exist_ok=True)
        existing_a = []
        if alerts_path.exists():
            try: existing_a = _j.loads(alerts_path.read_text(encoding="utf-8"))
            except Exception: pass
        existing_a.append({
            "type":       "a2c_temporal_sync",
            "severity":   "HIGH",
            "agent_name": source_name,
            "agent_id":   source_aid,
            "message":    f"{n_sessions} sessions trading — 4 rôles — sync ±0.5s — signature LLM commun détectée",
            "timestamp":  now,
            "details":    f"sessions={n_sessions} roles=4 window=2s jitter=0.5s",
        })
        alerts_path.write_text(_j.dumps(existing_a[-100:], indent=2), encoding="utf-8")

    print(DIM("  " + "-" * 55))
    print(f"  {GREEN(str(total))} events  {CYAN('→ temporal_sync HIGH dans Vigil Alert Journal')}")
    return total


def inject_cycle(ids, cycle):
    print(BOLD(f"\n  Cycle {cycle} -- {datetime.now().strftime('%H:%M:%S')}"))
    print(DIM("  " + "-" * 55))
    total_events = 0
    total_alerts = 0

    # Génère tous les events puis les répartit en sous-cycles
    agent_events = {}
    for ag in DEMO_AGENTS:
        name    = ag["name"]
        profile = ag["profile"]
        aid     = ids.get(name)
        if not aid: continue
        evts = _generate_events(aid, name, profile, ids)
        agent_events[name] = (ag, aid, evts)

    # Injection progressive — SUB_CYCLES lots avec pause entre eux
    chunk_size = max(1, len(DEMO_AGENTS) // SUB_CYCLES)
    agent_list = list(agent_events.items())

    for sub in range(SUB_CYCLES):
        if sub > 0:
            time.sleep(SUB_DELAY)
        # Chaque sous-cycle injecte une tranche d'events pour chaque agent
        for name, (ag, aid, evts) in agent_list:
            n_total   = len(evts)
            per_sub   = max(1, n_total // SUB_CYCLES)
            start_idx = sub * per_sub
            end_idx   = (start_idx + per_sub) if sub < SUB_CYCLES - 1 else n_total
            sub_evts  = evts[start_idx:end_idx]
            if sub_evts:
                _write_events(name, sub_evts)

    # Stats finales + alertes (une seule fois à la fin)
    for name, (ag, aid, evts) in agent_list:
        profile  = ag["profile"]
        color    = {"safe": GREEN, "watch": YELLOW, "alert": RED, "critical": MAGENTA}[profile]
        label    = color(f"[{profile.upper():<8}]")
        stored   = len(evts)
        tsi_state = _write_tsi_history(aid, profile)
        alerts   = _inject_alerts(name, aid, profile)
        peer_count = {}
        for e in evts: peer_count[e["peer_id"]] = peer_count.get(e["peer_id"], 0) + 1
        dom = max(peer_count, key=peer_count.get) if peer_count else "?"
        pct = 100 * peer_count.get(dom, 0) / len(evts) if evts else 0
        alert_str = f"  {RED(f'+{alerts}al')}" if alerts else ""
        print(f"  {label} {name:<22} +{stored:>3}ev  tsi={tsi_state:<8} conc={pct:3.0f}%{alert_str}")
        total_events += stored
        total_alerts += alerts

    _inject_peers(ids)

    # ── Scénarios d'attaque — toutes les 3 cycles ────────────────────
    attack_str = ""
    if cycle % 3 == 0:
        forked  = _inject_fork_scenario(ids)
        synced  = _inject_temporal_sync(ids)
        names   = ", ".join(n for n, _ in forked)
        attack_str = f"  {MAGENTA(f'⚡ fork({names}) sync({synced}ag)')}"

    print(DIM("  " + "-" * 55))
    print(f"  {GREEN(str(total_events))} events  {RED(str(total_alerts))} alerts{attack_str}  → Vigil recalcule dans 5s")

def show_status(ids):
    print(BOLD("\n  Status")); print(DIM("  " + "-" * 55))
    for ag in DEMO_AGENTS:
        name  = ag["name"]
        color = {"safe": GREEN, "watch": YELLOW, "alert": RED, "critical": MAGENTA}[ag["profile"]]
        ok    = GREEN("OK") if _agent_exists(name) else RED("XX")
        profile_label = f"[{ag['profile'].upper():<8}]"
        print(f"  {ok} {color(profile_label)} {name:<22} {_count_events(name):>5} events")

def reset_agents():
    import shutil
    print(BOLD("\n  Resetting demo agents..."))
    reg = PIQRYPT_DIR / "registry.json"
    if reg.exists():
        try:
            data  = json.loads(reg.read_text(encoding="utf-8"))
            names = {ag["name"] for ag in DEMO_AGENTS}
            if isinstance(data, dict) and "agents" in data:
                data["agents"] = {k: v for k, v in data["agents"].items() if k not in names}
            reg.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"  {GREEN('OK')} registry cleaned")
        except Exception as e:
            print(f"  {YELLOW('!')} registry: {e}")
    for ag in DEMO_AGENTS:
        d = AGENTS_DIR / ag["name"]
        if d.exists():
            shutil.rmtree(d); print(f"  {GREEN('removed')} {ag['name']}")
    tsi_dir = PIQRYPT_DIR / "tsi"
    if tsi_dir.exists():
        names   = {ag["name"] for ag in DEMO_AGENTS}
        removed = sum(1 for f in tsi_dir.glob("*.json") if any(n in f.name for n in names) and f.unlink() is None)
        if removed: print(f"  {GREEN('OK')} {removed} TSI file(s) removed")
    print(GREEN("  Done."))

def main():
    parser = argparse.ArgumentParser(description="PiQrypt Live Demo")
    parser.add_argument("--loop",     action="store_true", help="Animation continue")
    parser.add_argument("--fast",     action="store_true", help="Cycle rapide 5s")
    parser.add_argument("--reset",    action="store_true", help="Effacer les agents demo")
    parser.add_argument("--status",   action="store_true", help="Etat sans modifier")
    parser.add_argument("--interval", type=int, default=20, help="Secondes entre cycles")
    parser.add_argument("--attack",   action="store_true", help="Injecter fork + temporal_sync maintenant")
    parser.add_argument("--trading",  action="store_true", help="Simulation 3 sessions trading (4 rôles, même LLM)")
    args     = parser.parse_args()
    interval = 5 if args.fast else args.interval

    print()
    print(BOLD(CYAN("  PiQrypt Demo -- Live Agent Network")))
    print(DIM("  " + "=" * 55))

    if args.reset:   reset_agents(); return
    if args.status:
        ids = {ag["name"]: _get_agent_id(ag["name"]) for ag in DEMO_AGENTS}
        show_status(ids); return

    ids   = create_agents()
    cycle = 1

    # ── Modes spéciaux ──────────────────────────────────────────────
    if args.attack:
        print(BOLD(CYAN("\n  ⚡ Attack Injection — fork + temporal_sync")))
        forked = _inject_fork_scenario(ids)
        synced = _inject_temporal_sync(ids)
        for name, n in forked:
            print(f"  {MAGENTA('chain_fork')} → {name}  ({n} branch events)")
        print(f"  {MAGENTA('temporal_sync')} → {synced} agents synchronisés")
        print(GREEN("\n  Done. Recharge le dashboard Vigil pour voir les alertes."))
        return

    if args.trading:
        run_trading_simulation(ids, n_sessions=3, n_interactions=8)
        return

    inject_cycle(ids, cycle)

    token = os.getenv("VIGIL_TOKEN", "")
    if token:
        import webbrowser; time.sleep(1)
        webbrowser.open(f"http://localhost:8421/?token={token}")
        print(f"\n  {GREEN('Dashboard opened')}")

    if args.loop:
        print(f"\n  {DIM(f'Loop active -- every {interval}s -- Ctrl+C to stop')}")
        try:
            while True:
                time.sleep(interval); cycle += 1; inject_cycle(ids, cycle)
        except KeyboardInterrupt:
            print(f"\n  {YELLOW('Demo stopped.')}"); show_status(ids)

if __name__ == "__main__":
    main()
