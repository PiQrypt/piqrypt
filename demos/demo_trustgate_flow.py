# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
DemoLab Runner — PiQrypt + Vigil + Trust Gate
==============================================

Flux réel :
    1. Écrit des events A2A dans ~/.piqrypt/agents/<n>/events/plain/
       (même format exact que demo_multi_agents.py — le seul qui fonctionne)
    2. Vigil lit ces fichiers à chaque GET /api/summary et recalcule le VRS
    3. Le vigil_server.py patché pousse les VRS vers Trust Gate via _push_agents_to_trustgate()
    4. Trust Gate évalue contre sa policy → REQUIRE_HUMAN / BLOCK si VRS dépasse les seuils

Usage :
    python demo_lab_runner.py            # 1 cycle
    python demo_lab_runner.py --loop     # boucle toutes les 20s
    python demo_lab_runner.py --reset    # supprime les agents
    python demo_lab_runner.py --status   # état sans modifier
    python demo_lab_runner.py --events-only --loop  # rechargement seul
"""

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

# ── Path resolution (même pattern que demo_multi_agents.py) ──────────────────
_HERE = Path(__file__).resolve().parent
for _candidate in [_HERE, _HERE.parent]:
    if (_candidate / "aiss").is_dir():
        sys.path.insert(0, str(_candidate))
        break

# ── Config ────────────────────────────────────────────────────────────────────
PIQRYPT_DIR = Path.home() / ".piqrypt"
AGENTS_DIR  = PIQRYPT_DIR / "agents"

DEMO_AGENTS = [
    {
        "name":    "trading_bot_A",
        "tier":    "free",
        "profile": "safe",
        "desc":    "Bot stable — VRS bas — ALLOW attendu",
    },
    {
        "name":    "sentiment_ai",
        "tier":    "free",
        "profile": "watch",
        "desc":    "Dérive légère — VRS ~0.35 — ALLOW_WITH_LOG attendu",
    },
    {
        "name":    "risk_engine",
        "tier":    "free",
        "profile": "alert",
        "desc":    "Agent à risque — VRS ~0.62 — REQUIRE_HUMAN attendu",
    },
    {
        "name":    "shadow_agent",
        "tier":    "free",
        "profile": "critical",
        "desc":    "Agent malveillant — VRS ~0.88 — BLOCK attendu",
    },
]

EXTERNAL_PEERS = [
    "market_feed", "exchange_api", "data_hub", "external_oracle",
    "relay_node_7", "aggregator_Z", "signal_feed", "chain_validator",
]


# ── Couleurs ──────────────────────────────────────────────────────────────────
def _c(code, t): return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def RED(t):    return _c("91", t)
def CYAN(t):   return _c("96", t)
def BOLD(t):   return _c("1",  t)
def DIM(t):    return _c("2",  t)


# ── Génération d'events ───────────────────────────────────────────────────────
def _make_event(agent_id, peer_id, ts=None, tsa=False):
    return {
        "agent_id":   agent_id,
        "peer_id":    peer_id,
        "event_type": "a2a_message",
        "timestamp":  ts or int(time.time()),
        "nonce":      os.urandom(8).hex(),
        "signature":  os.urandom(16).hex(),
        "tsa":        tsa,
        "payload":    {"event_type": "a2a_message", "peer_id": peer_id,
                       "volume": random.randint(1, 10)},
    }


def _generate_events(agent_id, profile, all_peer_ids, n):
    now   = int(time.time())
    peers = list(all_peer_ids.values()) + EXTERNAL_PEERS[:4]
    evts  = []

    if profile == "safe":
        # Distribution uniforme — aucune concentration détectable
        pool = random.sample(peers, min(6, len(peers)))
        for _ in range(n):
            evts.append(_make_event(agent_id, random.choice(pool),
                                    ts=now - random.randint(0, 3600 * 48)))

    elif profile == "watch":
        # Légère concentration ~72%
        dominant = peers[0]
        for _ in range(n):
            peer = dominant if random.random() < 0.72 else random.choice(peers[1:] or [dominant])
            evts.append(_make_event(agent_id, peer, ts=now - random.randint(0, 3600 * 24)))

    elif profile == "alert":
        # Forte concentration ~92% + burst synchronisé → déclenche A2C
        dominant = peers[0]
        burst_ts = now - random.randint(300, 3600)
        for i in range(n):
            if random.random() < 0.92:
                peer = dominant
                tsa  = i < n // 3
                ts   = (burst_ts + random.randint(-5, 5)) if tsa else (now - random.randint(0, 3600 * 6))  # noqa: E501
            else:
                peer = random.choice(peers[1:] or [dominant])
                tsa  = False
                ts   = now - random.randint(0, 3600 * 12)
            evts.append(_make_event(agent_id, peer, ts=ts, tsa=tsa))

    elif profile == "critical":
        # Concentration maximale >97% + burst massif timestamps serrés
        dominant = peers[0]
        burst_ts = now - random.randint(60, 600)
        for i in range(n):
            tsa = i < n // 2
            ts  = (burst_ts + random.randint(-2, 2)) if tsa else (now - random.randint(0, 3600))
            evts.append(_make_event(agent_id, dominant, ts=ts, tsa=tsa))

    return sorted(evts, key=lambda e: e["timestamp"])


# ── TSI history — détermine STABLE/WATCH/UNSTABLE/CRITICAL ───────────────────
def _write_tsi_history(agent_id, profile):
    """
    Écrit ~/.piqrypt/tsi/<agent_id>.json
    TSI → UNSTABLE si z-score > 3.0 ou delta_24h < -0.15
    Pattern identique à demo_multi_agents.py
    """
    tsi_dir = PIQRYPT_DIR / "tsi"
    tsi_dir.mkdir(parents=True, exist_ok=True)

    safe_id = agent_id.replace("/", "_").replace("\\", "_")[:64]
    fpath   = tsi_dir / f"{safe_id}.json"
    now     = int(time.time())
    snaps   = []

    if profile == "safe":
        for i in range(30, -1, -1):
            snaps.append({"timestamp": now - i * 86400,
                          "score": round(0.92 + random.uniform(-0.02, 0.02), 4)})
        last_state = "STABLE"

    elif profile == "watch":
        for i in range(30, -1, -1):
            drift = 0 if i > 5 else (5 - i) * 0.018
            snaps.append({"timestamp": now - i * 86400,
                          "score": round(0.80 - drift + random.uniform(-0.02, 0.02), 4)})
        last_state = "WATCH"

    elif profile == "alert":
        # Stable 25j puis chute → z-score élevé
        for i in range(30, 5, -1):
            snaps.append({"timestamp": now - i * 86400,
                          "score": round(0.82 + random.uniform(-0.01, 0.01), 4)})
        for off, s in [(5*86400, 0.74), (4*86400, 0.60), (3*86400, 0.49),
                       (2*86400, 0.39), (86400, 0.31), (3600, 0.28), (0, 0.26)]:
            snaps.append({"timestamp": now - off, "score": s})
        last_state = "CRITICAL"

    elif profile == "critical":
        # Effondrement maximal
        for i in range(30, 5, -1):
            snaps.append({"timestamp": now - i * 86400,
                          "score": round(0.85 + random.uniform(-0.01, 0.01), 4)})
        for off, s in [(5*86400, 0.70), (4*86400, 0.50), (3*86400, 0.35),
                       (2*86400, 0.22), (86400, 0.15), (3600, 0.12), (0, 0.10)]:
            snaps.append({"timestamp": now - off, "score": s})
        last_state = "CRITICAL"

    else:
        last_state = "STABLE"

    fpath.write_text(json.dumps({
        "snapshots":      snaps,
        "last_state":     last_state,
        "unstable_since": now - 5 * 86400 if profile in ("alert", "critical") else None,
    }, indent=2), encoding="utf-8")

    return last_state


# ── Écriture directe sur disque ───────────────────────────────────────────────
def _write_events_to_disk(agent_name, agent_id, events):
    """
    Écrit dans ~/.piqrypt/agents/<n>/events/plain/YYYY-MM.json
    N'utilise JAMAIS store_event() qui ignore agent_name.
    Déduplique par nonce.
    """
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


# ── Agent helpers ─────────────────────────────────────────────────────────────
def _agent_exists(name):
    return (AGENTS_DIR / name / "identity.json").exists()

def _get_agent_id(name):
    p = AGENTS_DIR / name / "identity.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8")).get("agent_id", name)
        except Exception:
            pass
    return name

def _count_events(name):
    plain = AGENTS_DIR / name / "events" / "plain"
    if not plain.exists():
        return 0
    total = 0
    for f in plain.glob("*.json"):
        try:
            total += len(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return total


# ── Création des agents ───────────────────────────────────────────────────────
def create_agents():
    try:
        from aiss.identity import create_agent_identity
    except ImportError as e:
        print(RED(f"Import aiss.identity échoué: {e}"))
        print(RED("Lance depuis le dossier piqrypt/ avec: python demo_lab_runner.py"))
        sys.exit(1)

    agent_ids = {}
    print(BOLD("\n── Création des agents ─────────────────────────────────────"))
    for ag in DEMO_AGENTS:
        name = ag["name"]
        if _agent_exists(name):
            aid = _get_agent_id(name)
            agent_ids[name] = aid
            print(f"  {DIM('·')} {name:<22} {DIM('existant — ' + aid[:16] + '...')}")
        else:
            try:
                r = create_agent_identity(
                    agent_name=name, passphrase=None, tier=ag["tier"],
                    metadata={"demo": True, "profile": ag["profile"]},
                )
                agent_ids[name] = r["agent_id"]
                print(f"  {GREEN('OK')} {name:<22} {CYAN(r['agent_id'][:16])}...")
            except Exception as e:
                print(f"  {RED('ERR')} {name:<22} {RED(str(e))}")

    return agent_ids


# ── Injection d'un cycle ──────────────────────────────────────────────────────
def inject_cycle(agent_ids, cycle=1):
    print(BOLD(f"\n── Cycle {cycle:04d} — Injection ──────────────────────────────"))

    peer_ids = dict(agent_ids)  # agents se connaissent mutuellement

    for ag in DEMO_AGENTS:
        name    = ag["name"]
        profile = ag["profile"]
        aid     = agent_ids.get(name)
        if not aid:
            continue

        n         = {"safe": 15, "watch": 25, "alert": 60, "critical": 80}[profile]
        evts      = _generate_events(aid, profile, peer_ids, n)
        stored    = _write_events_to_disk(name, aid, evts)
        tsi_state = _write_tsi_history(aid, profile)

        peers_count = {}
        for e in evts:
            peers_count[e["peer_id"]] = peers_count.get(e["peer_id"], 0) + 1
        dom = max(peers_count, key=peers_count.get)
        pct = 100 * peers_count[dom] / len(evts) if evts else 0

        label = {
            "safe":     GREEN("SAFE    "),
            "watch":    YELLOW("WATCH   "),
            "alert":    RED("ALERT   "),
            "critical": RED("CRITICAL"),
        }[profile]

        total = _count_events(name)
        print(f"  [{label}] {name:<22} +{stored:>2} events  tsi={tsi_state:<8}"
              f" total={total:>5}  dom={dom:<20} conc={pct:.0f}%")

    print()
    print(f"  {CYAN('Vigil')} recalcule le VRS à chaque GET /api/summary")
    print(f"  {CYAN('vigil_server')} pousse les VRS → Trust Gate :8422 automatiquement")
    print(f"  {DIM('Vigil    →')} http://localhost:8421")
    print(f"  {DIM('Console  →')} http://localhost:8422/console")


# ── Status ────────────────────────────────────────────────────────────────────
def show_status(agent_ids):
    print(BOLD("\n── État ────────────────────────────────────────────────────"))
    for ag in DEMO_AGENTS:
        name  = ag["name"]
        aid   = agent_ids.get(name, "?")
        n     = _count_events(name)
        label = {
            "safe":     GREEN("SAFE    "),
            "watch":    YELLOW("WATCH   "),
            "alert":    RED("ALERT   "),
            "critical": RED("CRITICAL"),
        }[ag["profile"]]
        ok = GREEN("OK") if _agent_exists(name) else RED("XX")
        print(f"  {ok} [{label}] {name:<22} {n:>5} events  "
              f"{CYAN(aid[:16]+'...' if aid != '?' else '?')}")
    print(f"\n  {AGENTS_DIR}")


# ── Reset ─────────────────────────────────────────────────────────────────────
def reset_agents():
    import shutil
    print(BOLD("\n── Suppression ─────────────────────────────────────────────"))
    reg = PIQRYPT_DIR / "registry.json"
    if reg.exists():
        try:
            data  = json.loads(reg.read_text(encoding="utf-8"))
            names = {ag["name"] for ag in DEMO_AGENTS}
            if isinstance(data, dict) and "agents" in data:
                data["agents"] = {k: v for k, v in data["agents"].items()
                                  if k not in names}
            reg.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"  {GREEN('OK')} registry nettoyé")
        except Exception as e:
            print(f"  {YELLOW('!')} registry: {e}")
    for ag in DEMO_AGENTS:
        d = AGENTS_DIR / ag["name"]
        if d.exists():
            shutil.rmtree(d)
            print(f"  {GREEN('OK')} supprimé: {ag['name']}")
        else:
            print(f"  {DIM('·')} absent:   {ag['name']}")
    # TSI history
    tsi_dir = PIQRYPT_DIR / "tsi"
    if tsi_dir.exists():
        names = {ag["name"] for ag in DEMO_AGENTS}
        removed = 0
        for f in tsi_dir.glob("*.json"):
            if any(n in f.name for n in names):
                f.unlink()
                removed += 1
        if removed:
            print(f"  {GREEN('OK')} {removed} fichier(s) TSI supprimé(s)")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="DemoLab — écrit dans Vigil, push auto vers Trust Gate"
    )
    parser.add_argument("--loop",        action="store_true", help="Boucle continue")
    parser.add_argument("--reset",       action="store_true", help="Supprime les agents")
    parser.add_argument("--status",      action="store_true", help="État sans modifier")
    parser.add_argument("--events-only", action="store_true", help="Events sans recréer les agents")
    parser.add_argument("--interval",    type=int, default=20, help="Secondes entre cycles (défaut: 20)")  # noqa: E501
    args = parser.parse_args()

    print(BOLD(CYAN("DemoLab Runner — PiQrypt v1.8.1 + Vigil + Trust Gate")))
    print(DIM("─" * 60))

    if args.reset:
        reset_agents()
        return

    if args.status:
        agent_ids = {ag["name"]: _get_agent_id(ag["name"]) for ag in DEMO_AGENTS}
        show_status(agent_ids)
        return

    if not args.events_only:
        agent_ids = create_agents()
    else:
        agent_ids = {ag["name"]: _get_agent_id(ag["name"]) for ag in DEMO_AGENTS}
        missing   = [n for n in agent_ids if not _agent_exists(n)]
        if missing:
            print(RED(f"Agents manquants: {missing}"))
            print(RED("Lance sans --events-only d'abord."))
            sys.exit(1)

    if args.loop:
        print(CYAN(f"\n  Boucle — interval={args.interval}s — Ctrl+C pour arrêter"))
        cycle = 1
        try:
            while True:
                inject_cycle(agent_ids, cycle)
                show_status(agent_ids)
                print(DIM(f"\n  Prochain cycle dans {args.interval}s..."))
                time.sleep(args.interval)
                cycle += 1
        except KeyboardInterrupt:
            print(CYAN("\n\n  Arrêt."))
    else:
        inject_cycle(agent_ids, 1)
        show_status(agent_ids)


if __name__ == "__main__":
    main()
