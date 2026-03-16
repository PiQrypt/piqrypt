#!/usr/bin/env python3
"""
quickstart_dev.py — PiQrypt Developer Quickstart
=================================================

Demonstrates the full AISS-1 core loop in under 2 minutes:
  1. Generate a cryptographic identity (Ed25519)
  2. Stamp a genesis event
  3. Build a 3-event chain
  4. Verify chain integrity
  5. Export the audit trail
  6. Show what Vigil would see

No configuration required. No running server needed.
Everything happens locally in ~/.piqrypt/

Usage:
    python quickstart_dev.py
    python quickstart_dev.py --clean     # wipe agent after demo
    python quickstart_dev.py --agent my_bot  # custom agent name

Requirements:
    pip install piqrypt

IP: e-Soleau DSO2026006483 (INPI France — 19/02/2026)
PiQrypt v1.7.1 — https://piqrypt.com
"""

import argparse
import json
import sys
import time
from pathlib import Path

# ── Colour helpers (no dependency) ───────────────────────────────────────────

def _c(text, code): return f"\033[{code}m{text}\033[0m"
def green(t):  return _c(t, "32")
def cyan(t):   return _c(t, "36")
def yellow(t): return _c(t, "33")
def bold(t):   return _c(t, "1")
def dim(t):    return _c(t, "2")

SEP = dim("─" * 60)


# ── Import guard ──────────────────────────────────────────────────────────────

def _check_import():
    try:
        import piqrypt as aiss  # noqa: F401
        return True
    except ImportError:
        print("\n❌  PiQrypt not found.")
        print("    Install with:  pip install piqrypt")
        print("    Then re-run:   python quickstart_dev.py\n")
        sys.exit(1)


# ── Steps ─────────────────────────────────────────────────────────────────────

def step_identity(agent_name: str) -> tuple:
    """Step 1 — Generate Ed25519 keypair and derive agent_id."""
    import piqrypt as aiss

    print(f"\n{bold('Step 1 — Cryptographic Identity')}")
    print(SEP)

    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)

    print(f"  Agent name : {cyan(agent_name)}")
    print(f"  Agent ID   : {green(agent_id[:32])}...")
    print(f"  Algorithm  : Ed25519 (RFC 8032)")
    print(f"  Key size   : 32 bytes private / 32 bytes public")
    print(dim(f"\n  → Agent ID is derived deterministically from the public key."))
    print(dim(f"    Same keypair always yields the same ID — no central registry needed."))

    return private_key, public_key, agent_id


def step_genesis(private_key: bytes, agent_id: str) -> dict:
    """Step 2 — Stamp the genesis event (first event in the chain)."""
    import piqrypt as aiss

    print(f"\n{bold('Step 2 — Genesis Event')}")
    print(SEP)

    genesis = aiss.stamp_genesis_event(
        private_key, aiss.generate_keypair()[1], agent_id,
        payload={
            "event_type": "agent_initialized",
            "name":        "quickstart_demo",
            "version":     "1.7.1",
            "purpose":     "developer_quickstart",
        }
    )

    genesis_hash = aiss.compute_event_hash(genesis)

    print(f"  Event type    : {cyan(genesis['payload']['event_type'])}")
    print(f"  Timestamp     : {genesis['timestamp']}")
    print(f"  Nonce (UUIDv4): {genesis['nonce']}")
    print(f"  Previous hash : {dim('genesis')} (chain anchor)")
    print(f"  Event hash    : {green(genesis_hash[:32])}...")
    print(f"  Signature     : {genesis['signature'][:32]}...")
    print(dim(f"\n  → The genesis event anchors the chain. All subsequent events"))
    print(dim(f"    reference its hash — making retroactive modification detectable."))

    return genesis


def step_chain(private_key: bytes, agent_id: str, genesis: dict) -> list:
    """Step 3 — Stamp 3 more events and build the chain."""
    import piqrypt as aiss

    print(f"\n{bold('Step 3 — Building the Event Chain')}")
    print(SEP)

    events = [genesis]
    actions = [
        ("market_analysis",  {"symbol": "AAPL", "signal": "buy",  "confidence": 0.87}),
        ("trade_decision",   {"symbol": "AAPL", "action": "buy",  "quantity": 100}),
        ("trade_executed",   {"symbol": "AAPL", "order_id": "ORD-2026-001", "status": "filled"}),
    ]

    for event_type, payload in actions:
        prev_hash = aiss.compute_event_hash(events[-1])
        event = aiss.stamp_event(
            private_key,
            agent_id,
            payload={"event_type": event_type, **payload},
            previous_hash=prev_hash,
        )
        events.append(event)
        eh = aiss.compute_event_hash(event)
        print(f"  {green('✓')} {cyan(event_type):<25} hash: {eh[:16]}...  ← prev: {prev_hash[:12]}...")

    print(dim(f"\n  → Each event's previous_hash binds it to the prior event."))
    print(dim(f"    Modifying any event breaks all subsequent hashes — detectable instantly."))

    return events


def step_verify(events: list) -> bool:
    """Step 4 — Verify chain integrity."""
    import piqrypt as aiss
    from aiss.chain import verify_chain_linkage, verify_monotonic_timestamps

    print(f"\n{bold('Step 4 — Chain Verification')}")
    print(SEP)

    # Verify linkage
    try:
        verify_chain_linkage(events)
        print(f"  {green('✓')} Hash chain linkage     VALID  ({len(events)} events)")
    except Exception as e:
        print(f"  ✗ Hash chain linkage     INVALID: {e}")
        return False

    # Verify timestamps
    try:
        verify_monotonic_timestamps(events)
        print(f"  {green('✓')} Monotonic timestamps   VALID")
    except Exception as e:
        print(f"  ✗ Monotonic timestamps   INVALID: {e}")
        return False

    # Verify all signatures
    failed = 0
    for i, event in enumerate(events):
        try:
            aiss.verify_event(event)
        except Exception:
            failed += 1

    if failed == 0:
        print(f"  {green('✓')} Event signatures       ALL VALID  ({len(events)}/{len(events)})")
    else:
        print(f"  ✗ Event signatures       {failed} INVALID")
        return False

    # Tamper demonstration
    print(f"\n  {bold('Tamper detection demo:')}")
    import copy
    tampered = copy.deepcopy(events[1])
    tampered["payload"]["confidence"] = 0.01   # attacker modifies value

    from aiss.chain import verify_chain_linkage as vcl
    tampered_chain = [events[0], tampered] + events[2:]
    try:
        vcl(tampered_chain)
        print(f"  ✗ Tamper NOT detected (unexpected)")
    except Exception:
        print(f"  {green('✓')} Tamper detected        payload modified → chain broken immediately")

    return True


def step_store(events: list, agent_id: str, agent_name: str):
    """Step 5 — Store events to local disk."""
    import piqrypt as aiss

    print(f"\n{bold('Step 5 — Persisting to ~/.piqrypt/')}")
    print(SEP)

    stored = 0
    for event in events:
        try:
            aiss.store_event(event, agent_name=agent_name)
            stored += 1
        except Exception as e:
            print(f"  {yellow('⚠')} store_event: {e}")

    storage_path = Path.home() / ".piqrypt" / "agents" / agent_name
    print(f"  {green('✓')} Stored {stored} events")
    print(f"  Location : {storage_path}")
    print(dim(f"\n  → Events are stored as JSON with OS-level permissions."))
    print(dim(f"    Use IdentitySession + passphrase for encrypted key storage (Pro)."))


def step_export(events: list, agent_id: str, public_key: bytes) -> str:
    """Step 6 — Export audit chain."""
    import piqrypt as aiss

    print(f"\n{bold('Step 6 — Audit Export')}")
    print(SEP)

    output_path = "quickstart_audit.json"

    identity = aiss.export_identity(agent_id, public_key)
    audit = aiss.export_audit_chain(identity, events)

    with open(output_path, "w") as f:
        json.dump(audit, f, indent=2)

    file_size = Path(output_path).stat().st_size
    print(f"  {green('✓')} Exported to : {cyan(output_path)}")
    print(f"  File size   : {file_size:,} bytes")
    print(f"  Events      : {len(events)}")
    print(f"  Chain hash  : {green(aiss.compute_chain_hash(events)[:32])}...")
    print(dim(f"\n  → This file is verifiable by any party holding the agent's public key."))
    print(dim(f"    piqrypt verify {output_path}"))

    return output_path


def step_vigil_preview(events: list, agent_id: str, agent_name: str):
    """Step 7 — Show what Vigil would score."""
    print(f"\n{bold('Step 7 — Vigil Preview (what the monitoring layer sees)')}")
    print(SEP)

    try:
        from aiss.anomaly_monitor import compute_vrs
        result = compute_vrs(agent_name, agent_id=agent_id, events=events, persist=False)
        vrs    = result["vrs"]
        state  = result["state"]
        ts     = result["components"]["trust_score"]["score"]
        tsi    = result["components"]["tsi"]["state"]

        state_icon = {"SAFE": "🟢", "WATCH": "🟡", "ALERT": "🟠", "CRITICAL": "🔴"}.get(state, "⚪")
        print(f"  VRS (Vigil Risk Score) : {bold(f'{vrs:.3f}')}  {state_icon} {green(state) if state == 'SAFE' else yellow(state)}")
        print(f"  Trust Score            : {ts:.3f}")
        print(f"  TSI (temporal drift)   : {tsi}")
        print(f"  Chain anomalies        : {len(result['components']['chain']['anomalies'])}")
        print(dim(f"\n  → VRS = 0.35×(1−TS) + 0.30×TSI + 0.20×A2C + 0.15×chain"))
        print(dim(f"    A fresh agent with a clean chain scores SAFE by design."))
    except Exception as e:
        print(f"  {yellow('⚠')}  Vigil not available in this environment ({e})")
        print(dim(f"    Run 'python piqrypt_start.py --vigil' to start the monitoring server."))


def step_next_steps():
    """Print actionable next steps."""
    print(f"\n{bold('Next Steps')}")
    print(SEP)
    steps = [
        ("Multi-agent session",  "python quickstart_session.py"),
        ("Start Vigil monitor",  "python piqrypt_start.py --vigil"),
        ("Start full stack",     "python piqrypt_start.py"),
        ("Verify audit file",    "piqrypt verify quickstart_audit.json"),
        ("Encrypted key (Pro)",  "piqrypt identity secure my_agent"),
        ("Post-quantum (Pro+)",  "pip install piqrypt[post-quantum]"),
        ("Developer docs",       "https://docs.piqrypt.com"),
    ]
    for label, cmd in steps:
        print(f"  {green('→')} {label:<28} {cyan(cmd)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PiQrypt Developer Quickstart")
    parser.add_argument("--agent", default="quickstart_agent", help="Agent name")
    parser.add_argument("--clean", action="store_true", help="Delete agent dir after demo")
    args = parser.parse_args()

    _check_import()

    print()
    print(bold("═" * 60))
    print(bold("  PiQrypt — Developer Quickstart"))
    print(bold("  AISS-1 core loop · 5 minutes · zero config"))
    print(bold("═" * 60))

    t0 = time.time()

    # Run steps
    private_key, public_key, agent_id = step_identity(args.agent)
    genesis  = step_genesis(private_key, agent_id)
    events   = step_chain(private_key, agent_id, genesis)
    ok       = step_verify(events)
    step_store(events, agent_id, args.agent)
    out_path = step_export(events, agent_id, public_key)
    step_vigil_preview(events, agent_id, args.agent)
    step_next_steps()

    elapsed = time.time() - t0
    print()
    print(bold("═" * 60))
    status = green("✅  All steps passed") if ok else yellow("⚠   Completed with warnings")
    print(f"  {status}  ({elapsed:.1f}s)")
    print(f"  Audit file : {cyan(out_path)}")
    print(f"  Agent ID   : {dim(agent_id)}")
    print(bold("═" * 60))
    print()

    # Cleanup
    if args.clean:
        import shutil
        agent_dir = Path.home() / ".piqrypt" / "agents" / args.agent
        if agent_dir.exists():
            shutil.rmtree(agent_dir)
            print(dim(f"  Cleaned: {agent_dir}"))
        if Path(out_path).exists():
            Path(out_path).unlink()
            print(dim(f"  Cleaned: {out_path}"))
        print()


if __name__ == "__main__":
    main()
