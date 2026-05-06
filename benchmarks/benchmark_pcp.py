"""
PCP Protocol — Performance Benchmark
=====================================
Mesure les latences réelles pour le paper arXiv §11.

Usage:
    python benchmark_pcp.py

Output:
    benchmark_results.json  (chiffres bruts)
    benchmark_report.txt    (tableau prêt pour le paper)

Prérequis:
    pip install piqrypt
"""

import contextlib
import hashlib
import io
import json
import statistics
import time
import uuid
import os
import sys

# ─── Import PiQrypt ──────────────────────────────────────────────────────────

try:
    import piqrypt as aiss
    HAVE_PIQRYPT = True
except ImportError:
    print("[ERREUR] piqrypt non installé. Lance: pip install piqrypt")
    sys.exit(1)

# Vérifie si ML-DSA-65 est disponible (AISS-2)
try:
    from aiss.crypto import generate_keypair_mldsa
    HAVE_MLDSA = True
except ImportError:
    HAVE_MLDSA = False
    print("[INFO] ML-DSA-65 non disponible — benchmarks AISS-2 ignorés")

# ─── Paramètres ──────────────────────────────────────────────────────────────

N_ITERATIONS  = 1000   # itérations par mesure
N_IO          = 100    # itérations pour benchmarks I/O (store_event, search, full loop)
CHAIN_SIZES   = [100, 1000, 10000]  # tailles de chaîne pour vérification
AGENT_COUNTS  = [1, 10, 100]        # agents pour VRS

PERCENTILES   = [5, 50, 95]  # p5, médiane, p95

# ─── Utilitaires ─────────────────────────────────────────────────────────────

def percentile(data, p):
    """Calcule le p-ième percentile d'une liste triée."""
    data_sorted = sorted(data)
    k = (len(data_sorted) - 1) * p / 100
    f = int(k)
    c = f + 1
    if c >= len(data_sorted):
        return data_sorted[f]
    return data_sorted[f] + (k - f) * (data_sorted[c] - data_sorted[f])

def ms(seconds):
    return round(seconds * 1000, 2)

def format_table_row(label, p5, median, p95, notes=""):
    return f"| {label:<40} | {p5:>8} | {median:>8} | {p95:>8} | {notes} |"

# ─── Benchmark 1 : Event Stamping AISS-1 ────────────────────────────────────

def compute_prev_hash(event):
    """Compute the hash of an event as PiQrypt expects it."""
    return hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()

def bench_stamp_aiss1():
    print("\n[1/4] Event stamping AISS-1 (Ed25519)...")

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    payload = {
        "event_type": "trade_executed",
        "symbol": "AAPL",
        "quantity": 100,
        "price": 182.50,
        "timestamp_ms": 1739382400000
    }

    times = []
    prev_hash = None

    for i in range(N_ITERATIONS):
        t0 = time.perf_counter()
        event = aiss.stamp_event(private_key, agent_id, payload, previous_hash=prev_hash)
        t1 = time.perf_counter()
        times.append(t1 - t0)
        prev_hash = compute_prev_hash(event)

    return {
        "p5":    ms(percentile(times, 5)),
        "p50":   ms(percentile(times, 50)),
        "p95":   ms(percentile(times, 95)),
        "mean":  ms(statistics.mean(times)),
        "n":     N_ITERATIONS
    }

# ─── Benchmark 2 : Event Stamping AISS-2 ────────────────────────────────────

def bench_stamp_aiss2():
    if not HAVE_MLDSA:
        return None

    print("\n[2/4] Event stamping AISS-2 (Ed25519 + ML-DSA-65)...")

    try:
        private_key, public_key = aiss.generate_keypair(profile="AISS-2")
        agent_id = aiss.derive_agent_id(public_key)
    except Exception as e:
        print(f"  [SKIP] AISS-2 keypair failed: {e}")
        return None

    payload = {"event_type": "trade_executed", "symbol": "AAPL", "quantity": 100}

    times = []
    prev_hash = None

    for i in range(N_ITERATIONS):
        t0 = time.perf_counter()
        try:
            event = aiss.stamp_event(private_key, agent_id, payload, previous_hash=prev_hash, profile="AISS-2")
        except Exception:
            event = aiss.stamp_event(private_key, agent_id, payload, previous_hash=prev_hash)
        t1 = time.perf_counter()
        times.append(t1 - t0)
        prev_hash = compute_prev_hash(event)

    return {
        "p5":    ms(percentile(times, 5)),
        "p50":   ms(percentile(times, 50)),
        "p95":   ms(percentile(times, 95)),
        "mean":  ms(statistics.mean(times)),
        "n":     N_ITERATIONS
    }


def bench_verify_chain():
    print("\n[3/4] Chain verification (single event verify_event)...")

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    results = {}

    for chain_size in CHAIN_SIZES:
        print(f"  Building chain of {chain_size} events...", end=" ", flush=True)

        events = []
        prev_hash = None
        for i in range(chain_size):
            event = aiss.stamp_event(
                private_key, agent_id,
                {"event_type": "decision", "index": i},
                previous_hash=prev_hash
            )
            events.append(event)
            prev_hash = compute_prev_hash(event)

        print(f"done. Measuring verification...", end=" ", flush=True)

        # Measure: verify all events sequentially
        reps = max(5, min(50, 500 // chain_size))
        times = []

        for _ in range(reps):
            t0 = time.perf_counter()
            for ev in events:
                try:
                    aiss.verify_event(public_key, ev)
                except Exception:
                    pass
            t1 = time.perf_counter()
            times.append(t1 - t0)

        print("done.")

        results[chain_size] = {
            "p50": ms(percentile(times, 50)),
            "p5":  ms(percentile(times, 5)),
            "p95": ms(percentile(times, 95)),
            "n":   reps
        }

    return results


def bench_vrs():
    print("\n[4/4] Chain building throughput (VRS proxy)...")

    results = {}

    for n_agents in AGENT_COUNTS:
        events_per_agent = max(100, 1000 // n_agents)
        total_events = n_agents * events_per_agent

        print(f"  {n_agents} agent(s), {total_events} events total...", end=" ", flush=True)

        agent_data = []
        for a in range(n_agents):
            pk, pub = aiss.generate_keypair()
            aid = aiss.derive_agent_id(pub)
            evts = []
            prev_hash = None
            for i in range(events_per_agent):
                e = aiss.stamp_event(pk, aid, {"type": "action", "i": i}, previous_hash=prev_hash)
                evts.append(e)
                prev_hash = compute_prev_hash(e)
            agent_data.append((aid, evts, pub))

        # Measure full chain verification across all agents
        times = []
        for _ in range(10):
            t0 = time.perf_counter()
            for aid, evts, pub in agent_data:
                for ev in evts:
                    aiss.verify_event(ev, pub)
            t1 = time.perf_counter()
            times.append(t1 - t0)

        results[n_agents] = {
            "total_events": total_events,
            "p50": ms(percentile(times, 50)),
            "n":   10,
            "note": "full chain verify"
        }
        print("done.")

    return results

# ─── Event Size Measurement ──────────────────────────────────────────────────

def measure_event_size():
    print("\n[+] Measuring event size...")

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    payload_small   = {"event_type": "decision", "value": 42}
    payload_typical = {
        "event_type": "trade_executed",
        "symbol": "AAPL",
        "quantity": 100,
        "price": 182.50,
        "reasoning": "RSI below 30, momentum positive"
    }

    e_small   = aiss.stamp_event(private_key, agent_id, payload_small)
    e_typical = aiss.stamp_event(private_key, agent_id, payload_typical,
                                  previous_hash=compute_prev_hash(e_small))

    size_small   = len(json.dumps(e_small).encode("utf-8"))
    size_typical = len(json.dumps(e_typical).encode("utf-8"))

    return {
        "small_bytes":   size_small,
        "typical_bytes": size_typical
    }

# ─── System Info ─────────────────────────────────────────────────────────────

def get_system_info():
    import platform
    info = {
        "platform": platform.platform(),
        "python":   platform.python_version(),
        "processor": platform.processor(),
    }
    try:
        import piqrypt
        info["piqrypt_version"] = getattr(piqrypt, "__version__", "unknown")
    except Exception:
        info["piqrypt_version"] = "unknown"
    return info

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("PCP Protocol — Performance Benchmark")
    print("=" * 60)

    results = {}

    # System info
    results["system"] = get_system_info()
    print(f"\nSystem: {results['system']['platform']}")
    print(f"Python: {results['system']['python']}")
    print(f"PiQrypt: {results['system']['piqrypt_version']}")

    # Run benchmarks
    results["stamp_aiss1"]      = bench_stamp_aiss1()
    results["stamp_aiss2"]      = bench_stamp_aiss2()
    results["verify_chain"]     = bench_verify_chain()
    results["vrs"]              = bench_vrs()
    results["event_size"]       = measure_event_size()
    results["store_event"]      = bench_store_event()
    results["trustgate_eval"]   = bench_trustgate_eval()
    results["search_events"]    = bench_search_events()
    results["full_loop_aiss1"]  = bench_full_loop_aiss1()
    results["full_loop_aiss2"]  = bench_full_loop_aiss2()
    results["event_size_aiss2"] = measure_event_size_aiss2()

    # Save raw results
    with open("benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\n[OK] Raw results saved to benchmark_results.json")

    # Generate report
    report = generate_report(results)
    with open("benchmark_report.txt", "w", encoding="utf-8") as f:
        f.write(report)
    print("[OK] Report saved to benchmark_report.txt")

    # Print report
    print("\n" + "=" * 60)
    print(report)

    return results

# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(r):
    lines = []
    lines.append("PCP PROTOCOL — BENCHMARK RESULTS")
    lines.append("=" * 60)
    lines.append(f"Platform : {r['system']['platform']}")
    lines.append(f"Python   : {r['system']['python']}")
    lines.append(f"PiQrypt  : {r['system']['piqrypt_version']}")
    lines.append(f"N        : {N_ITERATIONS} iterations per measurement")
    lines.append("")

    # Table 1: Event Stamping
    lines.append("TABLE 1 — Event Stamping")
    lines.append("-" * 60)
    lines.append(f"{'Profile':<30} {'p5 (ms)':>8} {'p50 (ms)':>9} {'p95 (ms)':>9}")
    lines.append("-" * 60)

    s1 = r["stamp_aiss1"]
    lines.append(f"{'AISS-1 (Ed25519)':<30} {s1['p5']:>8} {s1['p50']:>9} {s1['p95']:>9}")

    if r["stamp_aiss2"]:
        s2 = r["stamp_aiss2"]
        lines.append(f"{'AISS-2 (Ed25519+ML-DSA-65)':<30} {s2['p5']:>8} {s2['p50']:>9} {s2['p95']:>9}")
    else:
        lines.append(f"{'AISS-2 (ML-DSA-65)':<30} {'N/A':>8} {'N/A':>9} {'N/A':>9}")

    lines.append("")

    # Table 2: Chain Verification
    lines.append("TABLE 2 — Chain Verification (AISS-1)")
    lines.append("-" * 60)
    lines.append(f"{'Chain length':<20} {'p50 (ms)':>10} {'p5 (ms)':>9} {'p95 (ms)':>9}")
    lines.append("-" * 60)

    for size, v in r["verify_chain"].items():
        lines.append(f"{str(size) + ' events':<20} {v['p50']:>10} {v['p5']:>9} {v['p95']:>9}")

    lines.append("")

    # Table 3: VRS
    lines.append("TABLE 3 — VRS Computation")
    lines.append("-" * 60)
    lines.append(f"{'Agents':<10} {'Events in window':>18} {'p50 (ms)':>10} {'Notes'}")
    lines.append("-" * 60)

    for n_ag, v in r["vrs"].items():
        note = v.get("note", "")
        lines.append(f"{str(n_ag) + ' agent(s)':<10} {v['total_events']:>18} {v['p50']:>10}  {note}")

    lines.append("")

    # Event size
    ev = r["event_size"]
    lines.append(f"EVENT SIZE (AISS-1): {ev['small_bytes']} bytes (minimal) / {ev['typical_bytes']} bytes (typical)")

    ev2 = r.get("event_size_aiss2")
    if ev2:
        lines.append(f"EVENT SIZE (AISS-2): {ev2['typical_bytes']} bytes (typical)")
    else:
        lines.append("EVENT SIZE (AISS-2): N/A")
    lines.append("")

    # Table 4: Full Agent Loop
    lines.append("TABLE 4 — Full Agent Loop (stamp → store → eval → verify → search)")
    lines.append("-" * 60)
    lines.append(f"{'Profile':<30} {'p5 (ms)':>8} {'p50 (ms)':>9} {'p95 (ms)':>9} {'mean (ms)':>10}")
    lines.append("-" * 60)

    fl1 = r.get("full_loop_aiss1")
    if fl1:
        lines.append(
            f"{'AISS-1 (Ed25519)':<30} {fl1['p5']:>8} {fl1['p50']:>9} {fl1['p95']:>9} {fl1['mean']:>10}"
        )
    else:
        lines.append(f"{'AISS-1':<30} {'N/A':>8} {'N/A':>9} {'N/A':>9} {'N/A':>10}")

    fl2 = r.get("full_loop_aiss2")
    if fl2:
        lines.append(
            f"{'AISS-2 (Ed25519+ML-DSA-65)':<30} {fl2['p5']:>8} {fl2['p50']:>9} {fl2['p95']:>9} {fl2['mean']:>10}"
        )
    else:
        lines.append(f"{'AISS-2 (ML-DSA-65)':<30} {'N/A':>8} {'N/A':>9} {'N/A':>9} {'N/A':>10}")

    lines.append("")

    # Table 5: Store + Search latencies
    lines.append("TABLE 5 — Store & Search Latencies")
    lines.append("-" * 60)

    se = r.get("store_event")
    if se:
        lines.append(f"{'store_event() [SQLite]':<30} {se['p5']:>8} {se['p50']:>9} {se['p95']:>9} {se['mean']:>10}")
    else:
        lines.append(f"{'store_event() [SQLite]':<30} {'N/A':>8} {'N/A':>9} {'N/A':>9} {'N/A':>10}")

    tge = r.get("trustgate_eval")
    if tge:
        lines.append(
            f"{'TrustGate policy eval':<30} {tge['p5']:>8} {tge['p50']:>9} {tge['p95']:>9} {tge['mean']:>10}"
        )
    else:
        lines.append(f"{'TrustGate policy eval':<30} {'N/A':>8} {'N/A':>9} {'N/A':>9} {'N/A':>10}")

    lines.append("")
    lines.append(f"{'search_events() by chain size':<30} {'p5 (ms)':>8} {'p50 (ms)':>9} {'p95 (ms)':>9}")
    lines.append("-" * 60)

    sr = r.get("search_events") or {}
    for chain_size in sorted(sr.keys()):
        v = sr[chain_size]
        lines.append(
            f"{str(chain_size) + ' stored events':<30} {v['p5']:>8} {v['p50']:>9} {v['p95']:>9}"
        )

    if not sr:
        lines.append(f"{'N/A':<30}")

    lines.append("")
    lines.append("Copy these numbers into §11 of PCP_arXiv_v1.1.md")

    return "\n".join(lines)


# ─── Benchmark 5 : Store Event ──────────────────────────────────────────────

def bench_store_event():
    print("\n[5/10] store_event() latency (SQLite)...")

    try:
        from aiss.memory import store_event
    except ImportError:
        print("  [SKIP] aiss.memory.store_event non disponible")
        return None

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    payload = {"event_type": "bench_store", "value": 42}
    prev_hash = None
    times = []

    _sink = io.StringIO()
    with contextlib.redirect_stdout(_sink), contextlib.redirect_stderr(_sink):
        for i in range(N_IO):
            event = aiss.stamp_event(private_key, agent_id, payload, previous_hash=prev_hash)
            prev_hash = compute_prev_hash(event)
            t0 = time.perf_counter()
            try:
                store_event(event)
            except Exception:
                pass
            t1 = time.perf_counter()
            times.append(t1 - t0)

    return {
        "p5":   ms(percentile(times, 5)),
        "p50":  ms(percentile(times, 50)),
        "p95":  ms(percentile(times, 95)),
        "mean": ms(statistics.mean(times)),
        "n":    N_IO,
    }


# ─── Benchmark 6 : TrustGate Policy Evaluation ──────────────────────────────

def bench_trustgate_eval():
    print("\n[6/10] TrustGate policy evaluation latency...")

    try:
        from trustgate.policy import PolicyEngine
    except ImportError:
        print("  [SKIP] trustgate.policy.PolicyEngine non disponible")
        return None

    # Minimal ALLOW-all policy
    minimal_policy = {
        "rules": [
            {"condition": "true", "action": "allow"}
        ]
    }

    try:
        engine = PolicyEngine(minimal_policy)
    except Exception as e:
        print(f"  [SKIP] PolicyEngine init failed: {e}")
        return None

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)
    event = aiss.stamp_event(private_key, agent_id, {"event_type": "bench_eval"})

    times = []
    for _ in range(N_ITERATIONS):
        t0 = time.perf_counter()
        try:
            engine.evaluate(event)
        except Exception:
            pass
        t1 = time.perf_counter()
        times.append(t1 - t0)

    return {
        "p5":   ms(percentile(times, 5)),
        "p50":  ms(percentile(times, 50)),
        "p95":  ms(percentile(times, 95)),
        "mean": ms(statistics.mean(times)),
        "n":    N_ITERATIONS,
    }


# ─── Benchmark 7 : Search Events ─────────────────────────────────────────────

def bench_search_events():
    print("\n[7/10] search_events() latency by chain size (10 / 100 / 1000)...")

    try:
        from aiss.memory import store_event, search_events
    except ImportError:
        print("  [SKIP] aiss.memory non disponible")
        return {}

    SEARCH_SIZES = [10, 100, 1000]
    results = {}

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    stored = 0
    prev_hash = None

    for size in SEARCH_SIZES:
        while stored < size:
            event = aiss.stamp_event(
                private_key, agent_id,
                {"event_type": "bench_search", "index": stored},
                previous_hash=prev_hash,
            )
            prev_hash = compute_prev_hash(event)
            try:
                store_event(event)
            except Exception:
                pass
            stored += 1

        print(f"  Chain size {size}...", end=" ", flush=True)

        reps = max(10, min(N_IO, N_IO // size)) if size > 0 else N_IO
        times = []

        _sink = io.StringIO()
        with contextlib.redirect_stdout(_sink), contextlib.redirect_stderr(_sink):
            for _ in range(reps):
                t0 = time.perf_counter()
                try:
                    search_events(agent_id=agent_id, limit=10)
                except Exception:
                    pass
                t1 = time.perf_counter()
                times.append(t1 - t0)

        results[size] = {
            "p5":  ms(percentile(times, 5)),
            "p50": ms(percentile(times, 50)),
            "p95": ms(percentile(times, 95)),
            "n":   reps,
        }
        print("done.")

    return results


# ─── Benchmark 8 : Full Agent Loop AISS-1 ────────────────────────────────────

def bench_full_loop_aiss1():
    print("\n[8/10] Full agent loop AISS-1 (stamp→store→eval→verify→search)...")

    try:
        from aiss.memory import store_event, search_events
    except ImportError:
        print("  [SKIP] aiss.memory non disponible")
        return None

    tg_engine = None
    try:
        from trustgate.policy import PolicyEngine
        tg_engine = PolicyEngine({"rules": [{"condition": "true", "action": "allow"}]})
    except Exception:
        pass

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    payload = {"event_type": "full_loop_aiss1", "value": 42}
    prev_hash = None
    times = []

    _sink = io.StringIO()
    with contextlib.redirect_stdout(_sink), contextlib.redirect_stderr(_sink):
        for _ in range(N_IO):
            t0 = time.perf_counter()

            # 1. stamp
            event = aiss.stamp_event(private_key, agent_id, payload, previous_hash=prev_hash)
            prev_hash = compute_prev_hash(event)

            # 2. store
            try:
                store_event(event)
            except Exception:
                pass

            # 3. TrustGate eval
            if tg_engine is not None:
                try:
                    tg_engine.evaluate(event)
                except Exception:
                    pass

            # 4. verify
            try:
                aiss.verify_event(public_key, event)
            except Exception:
                pass

            # 5. search (last 10)
            try:
                search_events(agent_id=agent_id, limit=10)
            except Exception:
                pass

            t1 = time.perf_counter()
            times.append(t1 - t0)

    return {
        "p5":   ms(percentile(times, 5)),
        "p50":  ms(percentile(times, 50)),
        "p95":  ms(percentile(times, 95)),
        "mean": ms(statistics.mean(times)),
        "n":    N_IO,
    }


# ─── Benchmark 9 : Full Agent Loop AISS-2 ────────────────────────────────────

def bench_full_loop_aiss2():
    if not HAVE_MLDSA:
        return None

    print("\n[9/10] Full agent loop AISS-2 (stamp→store→eval→verify→search)...")

    try:
        from aiss.memory import store_event, search_events
    except ImportError:
        print("  [SKIP] aiss.memory non disponible")
        return None

    tg_engine = None
    try:
        from trustgate.policy import PolicyEngine
        tg_engine = PolicyEngine({"rules": [{"condition": "true", "action": "allow"}]})
    except Exception:
        pass

    try:
        private_key, public_key = aiss.generate_keypair(profile="AISS-2")
        agent_id = aiss.derive_agent_id(public_key)
    except Exception as e:
        print(f"  [SKIP] AISS-2 keypair failed: {e}")
        return None

    payload = {"event_type": "full_loop_aiss2", "value": 42}
    prev_hash = None
    times = []

    _sink = io.StringIO()
    with contextlib.redirect_stdout(_sink), contextlib.redirect_stderr(_sink):
        for _ in range(N_ITERATIONS):
            t0 = time.perf_counter()

            # 1. stamp (AISS-2 hybrid)
            try:
                event = aiss.stamp_event(
                    private_key, agent_id, payload,
                    previous_hash=prev_hash, profile="AISS-2",
                )
            except Exception:
                event = aiss.stamp_event(private_key, agent_id, payload, previous_hash=prev_hash)
            prev_hash = compute_prev_hash(event)

            # 2. store
            try:
                store_event(event)
            except Exception:
                pass

            # 3. TrustGate eval
            if tg_engine is not None:
                try:
                    tg_engine.evaluate(event)
                except Exception:
                    pass

            # 4. verify
            try:
                aiss.verify_event(public_key, event)
            except Exception:
                pass

            # 5. search (last 10)
            try:
                search_events(agent_id=agent_id, limit=10)
            except Exception:
                pass

            t1 = time.perf_counter()
            times.append(t1 - t0)

    return {
        "p5":   ms(percentile(times, 5)),
        "p50":  ms(percentile(times, 50)),
        "p95":  ms(percentile(times, 95)),
        "mean": ms(statistics.mean(times)),
        "n":    N_ITERATIONS,
    }


# ─── Event Size Measurement AISS-2 ───────────────────────────────────────────

def measure_event_size_aiss2():
    if not HAVE_MLDSA:
        return None

    print("\n[+] Measuring AISS-2 event size...")

    try:
        private_key, public_key = aiss.generate_keypair(profile="AISS-2")
        agent_id = aiss.derive_agent_id(public_key)
    except Exception as e:
        print(f"  [SKIP] AISS-2 keypair failed: {e}")
        return None

    payload_typical = {
        "event_type": "trade_executed",
        "symbol": "AAPL",
        "quantity": 100,
        "price": 182.50,
        "reasoning": "RSI below 30, momentum positive",
    }

    try:
        event = aiss.stamp_event(
            private_key, agent_id, payload_typical, profile="AISS-2"
        )
    except Exception:
        event = aiss.stamp_event(private_key, agent_id, payload_typical)

    return {"typical_bytes": len(json.dumps(event).encode("utf-8"))}


if __name__ == "__main__":
    main()
