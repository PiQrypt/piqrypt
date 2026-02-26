"""
PiQrypt CLI - AISS Command Line Interface v1.1.0

Commands:
    identity  create|rotate|info
    stamp     Sign an event
    verify    Verify event signature
    audit     Audit event chain
    export    Export to audit format
    hash      Compute canonical hash
    license   activate|deactivate|status
    badge     generate
    telemetry enable|disable|status
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, Any

try:
    import aiss
except ImportError:
    print("Error: aiss package not installed", file=sys.stderr)
    print("Run: pip install piqrypt", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def load_json(filepath: str) -> Dict[str, Any]:
    with open(filepath, 'r') as f:
        return json.load(f)

def save_json(data: Dict[str, Any], filepath: str, indent: int = 2) -> None:
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=indent)
    print(f"✓ Saved to {filepath}")

def print_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2))


# ─────────────────────────────────────────────
# Identity Commands
# ─────────────────────────────────────────────

def cmd_identity_create(args):
    print("Generating Ed25519 keypair...")
    private_key, public_key = aiss.generate_keypair()
    agent_id = aiss.derive_agent_id(public_key)
    identity = aiss.export_identity(agent_id, public_key)

    output_data = {
        "identity": identity,
        "private_key": aiss.crypto.ed25519.encode_base64(private_key),
        "WARNING": "Keep private_key secret! Never share or commit to version control."
    }

    if args.output:
        save_json(output_data, args.output)
    else:
        print_json(output_data)

    print(f"\n✓ Agent ID: {agent_id}")
    aiss.log_identity_created(agent_id, "Ed25519")
    aiss.track("identity_created", algorithm="Ed25519", tier=aiss.get_tier())


def cmd_identity_rotate(args):
    print("Loading old identity...")
    old_data = load_json(args.old_key)
    old_private = aiss.crypto.ed25519.decode_base64(old_data['private_key'])
    old_public  = aiss.crypto.ed25519.decode_base64(old_data['identity']['public_key'])

    print("Generating new keypair...")
    new_private, new_public = aiss.generate_keypair()
    new_agent_id = aiss.derive_agent_id(new_public)

    print("Creating rotation attestation...")
    attestation = aiss.create_rotation_attestation(old_private, old_public, new_public)
    new_identity = aiss.export_identity(new_agent_id, new_public)

    output_data = {
        "identity": new_identity,
        "private_key": aiss.crypto.ed25519.encode_base64(new_private),
        "rotation_attestation": attestation,
        "WARNING": "Keep private_key secret!"
    }

    if args.output:
        save_json(output_data, args.output)
    else:
        print_json(output_data)

    print(f"\n✓ New Agent ID: {new_agent_id}")


# ─────────────────────────────────────────────
# Stamp Command
# ─────────────────────────────────────────────

def cmd_stamp(args):
    print("Loading identity...")
    identity_data = load_json(args.identity_file)
    private_key = aiss.crypto.ed25519.decode_base64(identity_data['private_key'])
    agent_id = identity_data['identity']['agent_id']

    # Load payload: JSON string or file
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            payload = load_json(args.payload)
    else:
        print("Enter payload JSON (Ctrl+D to finish):")
        payload = json.load(sys.stdin)

    print("Stamping event...")
    event = aiss.stamp_event(
        private_key=private_key,
        agent_id=agent_id,
        payload=payload,
        previous_hash=args.previous_hash
    )

    if args.output:
        save_json(event, args.output)
    else:
        print_json(event)

    print("\n✓ Event stamped")
    print(f"  Nonce: {event['nonce']}")
    print(f"  Timestamp: {event['timestamp']}")


# ─────────────────────────────────────────────
# Verify Command
# ─────────────────────────────────────────────

def cmd_verify(args):
    print("Loading event...")
    event = load_json(args.event_file)

    identity_data = load_json(args.identity)
    public_key = aiss.crypto.ed25519.decode_base64(identity_data['identity']['public_key'])

    print("Verifying signature...")
    try:
        aiss.verify_signature(event, public_key)
        print("✓ Signature valid")
        return 0
    except aiss.InvalidSignatureError as e:
        print(f"✗ Signature invalid: {e}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────
# Audit Command
# ─────────────────────────────────────────────

def cmd_audit(args):
    print("Loading chain...")
    chain_data = load_json(args.chain_file)

    if chain_data.get('spec') == 'AISS-1.0-AUDIT':
        identity = chain_data['agent_identity']
        events   = chain_data['events']
        print(f"Loaded audit export: {len(events)} events")
    else:
        print("Error: File must be AISS-1.0-AUDIT format", file=sys.stderr)
        sys.exit(1)

    print("\nVerifying chain integrity...")
    try:
        aiss.verify_chain(events, identity)
        print("✓ Chain integrity confirmed")
        print(f"  Events: {len(events)}")
        print(f"  Agent: {identity['agent_id']}")
        print(f"  Chain hash: {chain_data['chain_integrity_hash'][:16]}...")
        aiss.log_chain_verified(identity['agent_id'], len(events), chain_data['chain_integrity_hash'])
        return 0
    except (aiss.InvalidSignatureError, aiss.InvalidChainError,
            aiss.ForkDetected, aiss.ReplayAttackDetected) as e:
        print(f"✗ Chain validation failed: {e}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────
# Export Command
# ─────────────────────────────────────────────

def cmd_export(args):
    print("Loading chain...")
    chain_data = load_json(args.chain_file)
    identity = chain_data.get('identity')
    events   = chain_data.get('events', [])

    if not identity:
        print("Error: Chain file must contain 'identity' field", file=sys.stderr)
        sys.exit(1)

    print(f"Exporting {len(events)} events...")
    audit = aiss.export_audit_chain(identity, events)
    save_json(audit, args.audit_file)
    print("✓ Audit export complete")
    print(f"  Chain hash: {audit['chain_integrity_hash'][:16]}...")

    # Certified export if requested (Pro)
    if hasattr(args, 'certified') and args.certified:
        from aiss.license import is_pro
        if not is_pro():
            print("\n[PiQrypt] Certified export requires Pro license")
            print("[PiQrypt] Certified exports provide cryptographic proof for audits")
            return

        # Load private key
        if not hasattr(args, 'identity') or not args.identity:
            print("Error: --certified requires --identity FILE", file=sys.stderr)
            sys.exit(1)

        identity_data = load_json(args.identity)
        private_key = aiss.crypto.ed25519.decode_base64(identity_data['private_key'])
        agent_id = identity_data['identity']['agent_id']

        from aiss.exports import certify_export
        cert_path = certify_export(args.audit_file, private_key, agent_id)
        print(f"\n✓ Certified export created: {cert_path}")
        print(f"  Verify with: piqrypt verify-export {args.audit_file} {cert_path}")


def cmd_verify_export(args):
    """Verify a certified export (piqrypt verify-export AUDIT.json AUDIT.json.cert)"""
    from aiss.exports import verify_certified_export

    print("Verifying certified export...")
    print(f"  Export: {args.export_file}")
    print(f"  Cert:   {args.cert_file}")

    try:
        is_valid = verify_certified_export(args.export_file, args.cert_file)

        if is_valid:
            print("\n✅ Certified export VALID")
            print("  Export integrity    : ✓")
            print("  Agent identity      : ✓")
            print("  Timestamp           : ✓")
            print("  Cryptographic proof : ✓")
        else:
            print("\n❌ Certified export INVALID")
            sys.exit(1)

    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        sys.exit(1)


def cmd_certify_request(args):
    """Create certification request (piqrypt certify-request AUDIT.json AUDIT.json.cert --email user@company.com)"""
    from aiss.external_cert import create_certification_request

    print("Creating PiQrypt certification request...")
    print(f"  Audit:  {args.audit}")
    print(f"  Cert:   {args.cert}")
    print(f"  Email:  {args.email}")

    try:
        request_zip = create_certification_request(
            args.audit,
            args.cert,
            args.email,
            output_dir=args.output_dir if hasattr(args, 'output_dir') else "."
        )

        print("\n✅ Certification request created")
        print(f"   File: {request_zip}")
        print()
        print("📧 Next steps:")
        print(f"   1. Email {Path(request_zip).name} to: certify@piqrypt.com")
        print("   2. Subject: Certification Request")
        print("   3. Wait for PiQrypt to validate and return certified file")
        print("   4. Verify with: piqrypt certify-verify <certified-file>")
        print()
        print("💰 Pricing:")
        print("   - Pro users:  Included (unlimited)")
        print("   - Free users: $99 one-time per certification")
        print()

    except Exception as e:
        print(f"\n❌ Request creation failed: {e}")
        sys.exit(1)


def cmd_certify_verify(args):
    """Verify PiQrypt-certified export (piqrypt certify-verify AUDIT.piqrypt-certified)"""
    from aiss.external_cert import verify_piqrypt_certification, CertificationError

    print("Verifying PiQrypt certification...")
    print(f"  File: {args.certified_file}")
    print()

    try:
        result = verify_piqrypt_certification(args.certified_file)

        print("✅ PiQrypt Certification VALID")
        print("=" * 60)
        print(f"  Certificate ID : {result['certificate_id']}")
        print(f"  Certified At   : {result['certified_at']}")
        print(f"  Certified By   : {result['certified_by']}")
        print(f"  CA ID          : {result['ca_id'][:16]}...")
        print()
        print("  Verification Results:")
        for check, status in result['verification_results'].items():
            print(f"    {check:20s}: {status}")
        print()
        print("📜 Legal Statement:")
        print(f"   {result['legal_statement']}")
        print()
        print("✅ This export has been independently certified by PiQrypt Inc.")
        print("   Valid for legal and compliance purposes.")
        print()

    except CertificationError as e:
        print("❌ Certification verification FAILED")
        print(f"   Reason: {e}")
        sys.exit(1)

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ─────────────────────────────────────────────
# Hash Command
# ─────────────────────────────────────────────

def cmd_hash(args):
    data = load_json(args.file)
    hash_val = aiss.canonical.hash_canonical(data)
    print(hash_val)


# ─────────────────────────────────────────────
# License Commands
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# Authority Commands (RFC §5)
# ─────────────────────────────────────────────

def cmd_authority_create(args):
    """piqrypt authority create ISSUER_KEY SUBJECT_ID --scope ACTION [ACTION...] --days N"""
    from aiss.authority import create_authority_statement
    import aiss

    print("Loading issuer identity...")
    issuer_data = load_json(args.issuer_key)
    issuer_private = aiss.crypto.ed25519.decode_base64(issuer_data['private_key'])
    issuer_id = issuer_data['identity']['agent_id']

    scope = args.scope if args.scope else ["*"]
    validity_days = args.days if args.days else 365

    print("Creating authority statement...")
    print(f"  Issuer  : {issuer_id[:16]}...")
    print(f"  Subject : {args.subject_id}")
    print(f"  Scope   : {', '.join(scope)}")
    print(f"  Valid   : {validity_days} days")

    stmt = create_authority_statement(
        issuer_private,
        issuer_id,
        args.subject_id,
        scope=scope,
        validity_days=validity_days,
        revocation_reference=args.revocation_url,
    )

    output = args.output or f"authority-{issuer_id[:8]}-to-{args.subject_id[:8]}.json"
    save_json(stmt, output)

    print("\n✓ Authority statement created")
    print(f"  Statement ID: {stmt['statement_id']}")
    print(f"  Valid until : {stmt['validity_period']['end']}")


def cmd_authority_verify(args):
    """piqrypt authority verify STATEMENT.json ISSUER_KEY [--action ACTION]"""
    from aiss.authority import verify_authority_statement
    from aiss.exceptions import InvalidSignatureError
    import aiss

    print("Loading authority statement...")
    stmt = load_json(args.statement)

    print("Loading issuer public key...")
    issuer_data = load_json(args.issuer_key)
    issuer_public = aiss.crypto.ed25519.decode_base64(issuer_data['identity']['public_key'])

    action = args.action if hasattr(args, 'action') and args.action else None

    try:
        verify_authority_statement(stmt, issuer_public, requested_action=action)
        print("\n✅ Authority statement VALID")
        print(f"  Issuer    : {stmt['issuer_id']}")
        print(f"  Subject   : {stmt['subject_id']}")
        print(f"  Scope     : {', '.join(stmt['scope'])}")
        print(f"  Valid from: {stmt['validity_period']['start']}")
        print(f"  Valid to  : {stmt['validity_period']['end']}")
        if action:
            print(f"  Action    : '{action}' ✓ authorized")
    except InvalidSignatureError as e:
        print("\n❌ Authority statement INVALID")
        print(f"  Reason: {e}")
        return 1
    except Exception as e:
        print("\n❌ Authority verification failed")
        print(f"  Error: {e}")
        return 1


def cmd_authority_chain(args):
    """piqrypt authority chain STATEMENT1.json STATEMENT2.json ... --pubkeys KEYS.json"""
    from aiss.authority import validate_authority_chain, RESULT_VALID_AUTHORIZED
    import aiss

    print("Loading authority statements...")
    chain = [load_json(f) for f in args.statements]
    print(f"  {len(chain)} statement(s) loaded")

    print("\nLoading public keys...")
    pubkeys_data = load_json(args.pubkeys)
    pubkeys = {}
    for issuer_id, key_info in pubkeys_data.items():
        if isinstance(key_info, dict) and 'identity' in key_info:
            pub = aiss.crypto.ed25519.decode_base64(key_info['identity']['public_key'])
        else:
            pub = aiss.crypto.ed25519.decode_base64(key_info)
        pubkeys[issuer_id] = pub
    print(f"  {len(pubkeys)} key(s) loaded")

    action = args.action if hasattr(args, 'action') and args.action else None

    print("\nValidating chain...")
    result, errors = validate_authority_chain(chain, pubkeys, requested_action=action)

    print(f"\nResult: {result}")
    if result == RESULT_VALID_AUTHORIZED:
        print("✅ Authority chain VALID and AUTHORIZED")
        from aiss.authority import get_accountable_authority
        accountable = get_accountable_authority(chain)
        print(f"  Accountable authority: {accountable}")
    else:
        print("⚠️  Authority chain validation failed")
        if errors:
            print("  Errors:")
            for err in errors:
                print(f"    • {err}")
        return 1


# ─────────────────────────────────────────────
# License Commands
# ─────────────────────────────────────────────

def cmd_license_activate(args):
    print("Activating license...")
    if aiss.activate_license(args.key):
        info = aiss.get_license_info()
        print("✓ License activated!")
        print(f"\n  Tier: {info['tier'].upper()}")
        print("\n  Features unlocked:")
        for feature, available in info['features'].items():
            if available:
                print(f"    ✓ {feature}")
        aiss.log_license_activated(info['tier'], info.get('license_id', ''))
    else:
        print("✗ Invalid license key", file=sys.stderr)
        print("\n  Get a license:")
        print("    Pro: https://piqrypt.com/pro  ($1,990/year)")
        print("    OSS: https://piqrypt.com/oss  (free for open-source)")
        return 1


def cmd_license_status(args):
    info = aiss.get_license_info()
    tier = info['tier'].upper()

    print("\n" + "="*50)
    print("  PiQrypt License Status")
    print("="*50)
    print(f"\n  Tier    : {tier}")

    if tier != "FREE":
        print(f"  License : {info.get('license_id', 'N/A')}")

    print("\n  Features:")
    for feature, available in info['features'].items():
        icon = "✓" if available else "✗"
        print(f"    {icon}  {feature}")

    if tier == "FREE":
        print("\n  Upgrade to Pro:")
        print("    piqrypt.com/pro  –  $1,990/year")
        print("    piqrypt.com/oss  –  Free for open-source")
    print()


def cmd_license_deactivate(args):
    aiss.deactivate_license()
    print("✓ License deactivated (returned to Free tier)")


# ─────────────────────────────────────────────
# Badge Commands
# ─────────────────────────────────────────────

def cmd_badge_generate(args):
    # Load identity if provided
    if args.identity:
        identity_data = load_json(args.identity)
        agent_id = identity_data['identity']['agent_id']
    else:
        agent_id = args.agent_id or "DEMO00000000"

    tier = args.tier or aiss.get_tier()
    badge = aiss.generate_badge(agent_id, tier)

    if args.format == 'markdown':
        print(badge['markdown'])
    elif args.format == 'html':
        print(badge['html'])
    elif args.format == 'rst':
        print(badge['rst'])
    elif args.format == 'svg':
        print(aiss.generate_badge_svg(agent_id, tier))
    else:
        # Full JSON output
        print_json(badge)

    aiss.track("badge_generated", tier=tier)


# ─────────────────────────────────────────────
# Telemetry Commands
# ─────────────────────────────────────────────

def cmd_telemetry_enable(args):
    aiss.enable_telemetry()


def cmd_telemetry_disable(args):
    aiss.disable_telemetry()


def cmd_telemetry_status(args):
    status = aiss.get_telemetry_status()
    print(f"\n  Telemetry: {'Enabled ✓' if status['enabled'] else 'Disabled ✗'}")
    if status['enabled']:
        print(f"  Install ID: {status['installation_id']}")
    print()


# ─────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────

def main():
    # Force UTF-8 output on Windows (default cp1252 can't encode emojis)
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')

    parser = argparse.ArgumentParser(
        description=f"PiQrypt v{aiss.__version__} – AISS Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  piqrypt identity create --output agent.json
  piqrypt stamp agent.json --payload '{"action": "test"}' --output event.json
  piqrypt verify event.json --identity agent.json
  piqrypt license status
  piqrypt badge generate --identity agent.json --format markdown
  piqrypt telemetry enable
        """
    )
    parser.add_argument('--version', action='version',
                        version=f"PiQrypt {aiss.__version__} (tier: {aiss.get_tier()})")

    sub = parser.add_subparsers(dest='command', help='Command')

    # ── identity ──
    id_p = sub.add_parser('identity', help='Identity management')
    id_s = id_p.add_subparsers(dest='identity_command')

    id_create = id_s.add_parser('create', help='Create new identity')
    id_create.add_argument('--output', '-o', help='Output file (default: stdout)')

    id_rotate = id_s.add_parser('rotate', help='Rotate agent key')
    id_rotate.add_argument('old_key', help='Old identity file')
    id_rotate.add_argument('new_key', help='New identity output file')
    id_rotate.add_argument('--output', '-o', help='Attestation output file')

    # ── stamp ──
    stamp_p = sub.add_parser('stamp', help='Stamp an event')
    stamp_p.add_argument('identity_file', help='Identity file with private key')
    stamp_p.add_argument('--payload', '-p', help='Payload JSON string or file path')
    stamp_p.add_argument('--previous-hash', help='Previous event hash (for chaining)')
    stamp_p.add_argument('--output', '-o', help='Output file (default: stdout)')

    # ── verify ──
    verify_p = sub.add_parser('verify', help='Verify event signature')
    verify_p.add_argument('event_file', help='Event JSON file')
    verify_p.add_argument('--identity', '-i', required=True, help='Identity file')

    # ── audit ──
    audit_p = sub.add_parser('audit', help='Audit event chain')
    audit_p.add_argument('chain_file', help='Chain audit file')

    # ── export ──
    export_p = sub.add_parser('export', help='Export to audit format')
    export_p.add_argument('chain_file', help='Chain file (identity + events)')
    export_p.add_argument('audit_file', help='Output audit file')
    export_p.add_argument('--certified', action='store_true', help='Create certified export (Pro)')
    export_p.add_argument('--identity', '-i', help='Identity file with private key (required for --certified)')

    # ── verify-export (v1.2.0 Sprint 2) ──
    verify_export_p = sub.add_parser('verify-export', help='Verify certified export')
    verify_export_p.add_argument('export_file', help='Audit JSON file')
    verify_export_p.add_argument('cert_file', help='Certificate file (.cert)')

    # ── certify-request (v1.3.0) ──
    certify_request_p = sub.add_parser('certify-request', help='Request PiQrypt external certification')
    certify_request_p.add_argument('audit', help='Audit JSON file')
    certify_request_p.add_argument('cert', help='Certificate file (.cert)')
    certify_request_p.add_argument('--email', required=True, help='Your email for response')
    certify_request_p.add_argument('--output-dir', default='.', help='Output directory for request ZIP')

    # ── certify-verify (v1.3.0) ──
    certify_verify_p = sub.add_parser('certify-verify', help='Verify PiQrypt-certified export')
    certify_verify_p.add_argument('certified_file', help='PiQrypt-certified file (.piqrypt-certified)')

    # ── hash ──
    hash_p = sub.add_parser('hash', help='Compute canonical hash')
    hash_p.add_argument('file', help='JSON file to hash')

    # ── license ──
    lic_p = sub.add_parser('license', help='License management')
    lic_s = lic_p.add_subparsers(dest='license_command')

    lic_act = lic_s.add_parser('activate', help='Activate Pro license')
    lic_act.add_argument('key', help='License key (pk_pro_...)')

    lic_s.add_parser('status', help='Show license status')
    lic_s.add_parser('deactivate', help='Deactivate license')

    # ── authority (v1.2.0) ──
    auth_p = sub.add_parser('authority', help='Authority Binding Layer (RFC §5)')
    auth_s = auth_p.add_subparsers(dest='authority_command')

    auth_create = auth_s.add_parser('create', help='Create authority statement')
    auth_create.add_argument('issuer_key', help='Issuer identity file (with private key)')
    auth_create.add_argument('subject_id', help='Subject agent ID or identity')
    auth_create.add_argument('--scope', nargs='+', help='Allowed actions (e.g., execute_order read_data)')
    auth_create.add_argument('--days', type=int, default=365, help='Validity period in days (default: 365)')
    auth_create.add_argument('--revocation-url', help='Revocation list URL')
    auth_create.add_argument('--output', '-o', help='Output file (default: auto-generated)')

    auth_verify = auth_s.add_parser('verify', help='Verify authority statement')
    auth_verify.add_argument('statement', help='Authority statement JSON file')
    auth_verify.add_argument('issuer_key', help='Issuer identity file (public key)')
    auth_verify.add_argument('--action', help='Check if specific action is authorized')

    auth_chain = auth_s.add_parser('chain', help='Validate authority chain')
    auth_chain.add_argument('statements', nargs='+', help='Authority statement files (in order: top → agent)')
    auth_chain.add_argument('--pubkeys', required=True, help='JSON file mapping issuer_id → public_key')
    auth_chain.add_argument('--action', help='Check if final action is authorized')

    # ── badge ──
    badge_p = sub.add_parser('badge', help='Generate visual badge')
    badge_s = badge_p.add_subparsers(dest='badge_command')

    badge_gen = badge_s.add_parser('generate', help='Generate badge')
    badge_gen.add_argument('--identity', '-i', help='Identity file')
    badge_gen.add_argument('--agent-id', help='Agent ID (if no identity file)')
    badge_gen.add_argument('--tier', choices=['free', 'pro', 'oss', 'enterprise'],
                           help='Badge tier (default: current license tier)')
    badge_gen.add_argument('--format', choices=['json', 'markdown', 'html', 'rst', 'svg'],
                           default='json', help='Output format (default: json)')

    # ── telemetry ──
    tel_p = sub.add_parser('telemetry', help='Telemetry management')
    tel_s = tel_p.add_subparsers(dest='telemetry_command')
    tel_s.add_parser('enable',  help='Enable opt-in telemetry')
    tel_s.add_parser('disable', help='Disable telemetry')
    tel_s.add_parser('status',  help='Show telemetry status')


    # ── memory (v1.2.0) ──
    # piqrypt history (v1.6)
    hist_p = sub.add_parser('history', help='Full agent history across key rotations (v1.6)')
    hist_p.add_argument('agent_id', help='Agent ID (any identity in the rotation chain)')
    hist_p.add_argument('--chain', action='store_true', help='Show identity chain only')
    hist_p.add_argument('--summary', action='store_true', help='Show statistics only')
    hist_p.add_argument('--json', action='store_true', help='JSON output')
    hist_p.add_argument('--limit', type=int, default=100, help='Max events to display')

    # ── Trust Score (v1.6) ──────────────────────────────────────────────────
    ts_p = sub.add_parser('trust-score', help='Trust Score & TSI (v1.6)')
    ts_s = ts_p.add_subparsers(dest='ts_command')

    ts_compute = ts_s.add_parser('compute', help='Compute Trust Score for an agent')
    ts_compute.add_argument('agent_id', help='Agent ID to score')
    ts_compute.add_argument('--json', action='store_true', help='JSON output')
    ts_compute.add_argument('--full', action='store_true', help='Show component details')

    ts_hist = ts_s.add_parser('history', help='Trust Score history (30 days)')
    ts_hist.add_argument('agent_id', help='Agent ID')
    ts_hist.add_argument('--days', type=int, default=30, help='Number of days')
    ts_hist.add_argument('--json', action='store_true', help='JSON output')

    ts_compare = ts_s.add_parser('compare', help='Compare Trust Scores of two agents')
    ts_compare.add_argument('agent_a', help='First agent ID')
    ts_compare.add_argument('agent_b', help='Second agent ID')
    ts_compare.add_argument('--json', action='store_true', help='JSON output')

    # ── Sentinel status (v1.6 — A2C disponible v1.7) ────────────────────────
    sentinel_p = sub.add_parser('sentinel', help='Sentinel status — TS + TSI (v1.6)')
    sentinel_s = sentinel_p.add_subparsers(dest='sentinel_command')
    sent_status = sentinel_s.add_parser('status', help='Full Sentinel status for an agent')
    sent_status.add_argument('agent_id', help='Agent ID')
    sent_status.add_argument('--json', action='store_true', help='JSON output')

    mem_p = sub.add_parser('memory', help='Memory management')
    mem_s = mem_p.add_subparsers(dest='memory_command')
    mem_s.add_parser('status', help='Show memory statistics')
    mem_unlock = mem_s.add_parser('unlock', help='Unlock encrypted memory (Pro)')
    mem_unlock.add_argument('--passphrase', help='Passphrase (prompted if not provided)')
    mem_unlock.add_argument('--permanent', action='store_true', help='Stay unlocked until explicit lock')
    mem_s.add_parser('lock', help='Lock memory session')
    mem_search = mem_s.add_parser('search', help='Search events in memory')
    mem_search.add_argument('--agent', help='Filter by agent ID')
    mem_search.add_argument('--type', help='Filter by event type')
    mem_search.add_argument('--limit', type=int, default=20, help='Max results')
    mem_search.add_argument('--json', action='store_true', help='Output full JSON')
    mem_search.add_argument('--session', help='Filter by session_id (v1.6)')
    mem_search.add_argument('--follow-rotation', dest='follow_rotation', action='store_true', help='Include key rotation chain (v1.6)')
    mem_enc = mem_s.add_parser('encrypt', help='Migrate Free memory to encrypted Pro')
    mem_enc.add_argument('--passphrase', help='Passphrase (prompted if not provided)')

    # ── a2a (v1.2.0) ──
    a2a_p = sub.add_parser('a2a', help='Agent-to-Agent interactions')
    a2a_s = a2a_p.add_subparsers(dest='a2a_command')
    a2a_prop = a2a_s.add_parser('propose', help='Create identity proposal for peer')
    a2a_prop.add_argument('--identity', '-i', required=True, help='Identity file')
    a2a_prop.add_argument('--output', '-o', help='Output proposal file')
    a2a_resp = a2a_s.add_parser('respond', help='Respond to peer identity proposal')
    a2a_resp.add_argument('--identity', '-i', required=True, help='My identity file')
    a2a_resp.add_argument('--proposal', '-p', required=True, help='Peer proposal file')
    a2a_resp.add_argument('--output', '-o', help='Output response file')
    a2a_s.add_parser('peers', help='List registered peers and trust scores')

    # ── archive (v1.2.0) ──
    arch_p = sub.add_parser('archive', help='Create portable .pqz archive')
    arch_p.add_argument('--identity', '-i', required=True, help='Identity file')
    arch_p.add_argument('--output', '-o', help='Output .pqz file')
    arch_p.add_argument('--encrypt', action='store_true', help='Encrypt archive (Pro)')
    arch_p.add_argument('--passphrase', help='Passphrase for encryption')

    imp_p = sub.add_parser('import', help='Import .pqz archive into memory')
    imp_p.add_argument('archive', help='.pqz archive file to import')
    imp_p.add_argument('--passphrase', help='Decryption passphrase')

    # ── status (enhanced v1.2.0) ──
    stat_p = sub.add_parser('status', help='Agent status (replaces legacy)')
    stat_p.add_argument('--deep', action='store_true', help='Show network status (Pro)')

    # ─────────────────────────────────────────
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        # Identity
        if args.command == 'identity':
            if args.identity_command == 'create':
                cmd_identity_create(args)
            elif args.identity_command == 'rotate':
                cmd_identity_rotate(args)
            else:
                id_p.print_help()

        # Stamp
        elif args.command == 'stamp':
            cmd_stamp(args)

        # Verify
        elif args.command == 'verify':
            return cmd_verify(args)

        # Audit
        elif args.command == 'audit':
            return cmd_audit(args)

        # Export
        elif args.command == 'export':
            cmd_export(args)

        # Verify-export (v1.2.0 Sprint 2)
        elif args.command == 'verify-export':
            cmd_verify_export(args)

        # Certify-request (v1.3.0)
        elif args.command == 'certify-request':
            cmd_certify_request(args)

        # Certify-verify (v1.3.0)
        elif args.command == 'certify-verify':
            cmd_certify_verify(args)

        # Hash
        elif args.command == 'hash':
            cmd_hash(args)

        # License
        elif args.command == 'license':
            if args.license_command == 'activate':
                cmd_license_activate(args)
            elif args.license_command == 'status':
                cmd_license_status(args)
            elif args.license_command == 'deactivate':
                cmd_license_deactivate(args)
            else:
                lic_p.print_help()

        # Authority (v1.2.0)
        elif args.command == 'authority':
            if args.authority_command == 'create':
                cmd_authority_create(args)
            elif args.authority_command == 'verify':
                cmd_authority_verify(args)
            elif args.authority_command == 'chain':
                cmd_authority_chain(args)
            else:
                auth_p.print_help()

        # Badge
        elif args.command == 'badge':
            if args.badge_command == 'generate':
                cmd_badge_generate(args)
            else:
                badge_p.print_help()

        # Telemetry
        elif args.command == 'telemetry':
            if args.telemetry_command == 'enable':
                cmd_telemetry_enable(args)
            elif args.telemetry_command == 'disable':
                cmd_telemetry_disable(args)
            elif args.telemetry_command == 'status':
                cmd_telemetry_status(args)
            else:
                tel_p.print_help()


        # Memory (v1.2.0)
        elif args.command == 'memory':
            if args.memory_command == 'status':
                cmd_memory_status(args)
            elif args.memory_command == 'unlock':
                return cmd_memory_unlock(args)
            elif args.memory_command == 'lock':
                cmd_memory_lock(args)
            elif args.memory_command == 'search':
                cmd_memory_search(args)
            elif args.memory_command == 'encrypt':
                return cmd_memory_encrypt(args)
            else:
                mem_p.print_help()

        # A2A (v1.2.0)
        elif args.command == 'trust-score':
            if args.ts_command == 'compute':
                cmd_trust_score_compute(args)
            elif args.ts_command == 'history':
                cmd_trust_score_history(args)
            elif args.ts_command == 'compare':
                cmd_trust_score_compare(args)
            else:
                print("Usage: piqrypt trust-score {compute|history|compare}")
        elif args.command == 'sentinel':
            if args.sentinel_command == 'status':
                cmd_sentinel_status(args)
            else:
                print("Usage: piqrypt sentinel status <agent_id>")
        elif args.command == 'history':
            cmd_history(args)
        elif args.command == 'a2a':
            if args.a2a_command == 'propose':
                cmd_a2a_propose(args)
            elif args.a2a_command == 'respond':
                cmd_a2a_respond(args)
            elif args.a2a_command == 'peers':
                cmd_a2a_peers(args)
            else:
                a2a_p.print_help()

        # Archive (v1.2.0)
        elif args.command == 'archive':
            return cmd_archive_create(args)
        elif args.command == 'import':
            cmd_archive_import(args)

        # Status (v1.2.0)
        elif args.command == 'status':
            cmd_status(args)

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())

# ─────────────────────────────────────────────────────────────────────────────
# NOUVELLES COMMANDES v1.2.0
# ─────────────────────────────────────────────────────────────────────────────



def cmd_history(args):
    """piqrypt history <agent_id> -- full history across key rotations (v1.6)"""
    import json
    from datetime import datetime, timezone
    from aiss.history import load_full_history, get_history_summary

    def fmt_ts(ts):
        if not ts:
            return "--"
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def short_id(aid, n=16):
        return aid[:n] + "..." if len(aid) > n else aid

    agent_id = args.agent_id
    json_output = getattr(args, 'json', False)
    chain_only = getattr(args, 'chain', False)
    summary_only = getattr(args, 'summary', False)
    limit = getattr(args, 'limit', 100)

    summary = get_history_summary(agent_id)
    chain = summary["identity_chain"]

    if chain_only or summary_only:
        print("\n Identity chain for " + short_id(agent_id))
        print("-" * 60)
        for i, aid in enumerate(chain):
            per = next((p for p in summary["per_identity"] if p["agent_id"] == aid), {})
            count = per.get("event_count", 0)
            label = " (current)" if aid == chain[-1] else ""
            arrow = "  -> " if i > 0 else "    "
            print(arrow + short_id(aid, 24) + label)
            print("      " + str(count) + " events  " + fmt_ts(per.get("oldest_timestamp")) + " -> " + fmt_ts(per.get("newest_timestamp")))
            if i < len(chain) - 1:
                print("      v key rotation")
        total = summary["total_events"]
        rots = summary["rotations"]
        print("\n  Total: " + str(total) + " events  |  " + str(rots) + " rotation(s)")
        print()
        return

    history = load_full_history(agent_id, include_markers=not json_output)

    if json_output:
        real_events = [e for e in history if not e.get("_marker")]
        print(json.dumps({
            "agent_id": agent_id,
            "identity_chain": chain,
            "total_events": len(real_events),
            "rotations": summary["rotations"],
            "events": real_events[:limit],
        }, indent=2, default=str))
        return

    print("\n Full history: " + short_id(agent_id))
    if len(chain) > 1:
        print("   Chain: " + " -> ".join(short_id(a, 10) for a in chain))
    print("   " + str(summary["total_events"]) + " events  |  "
          + str(summary["rotations"]) + " rotation(s)  |  "
          + fmt_ts(summary["earliest_timestamp"]) + " -> " + fmt_ts(summary["latest_timestamp"]))
    print()

    for event in history[:limit]:
        if event.get("_marker"):
            from_id = short_id(event.get("from_agent_id", "?"), 12)
            to_id = short_id(event.get("to_agent_id", "?"), 12)
            sep = "-" * 54
            print("\n  " + sep)
            print("  KEY ROTATION  " + fmt_ts(event.get("timestamp")))
            print("     " + from_id + "  ->  " + to_id)
            print("  " + sep + "\n")
            continue
        ts = fmt_ts(event.get("timestamp"))
        aid = short_id(event.get("agent_id", "?"), 14)
        p = event.get("payload", {})
        etype = p.get("event_type") or p.get("type") or "event"
        pstr = json.dumps({k: v for k, v in p.items() if k not in ("event_type", "type", "aiss_profile")}, default=str)
        if len(pstr) > 80:
            pstr = pstr[:77] + "..."
        print("  [" + ts + "]  " + aid + "  " + etype)
        print("    " + pstr)

    if len(history) > limit:
        remaining = len(history) - limit
        print("\n  ... " + str(remaining) + " more (use --limit)")
    print()

def cmd_memory_status(args):
    """piqrypt memory status"""
    from aiss.memory import get_memory_stats
    stats = get_memory_stats()
    tier = stats.get("tier", "free")

    print("\nPiQrypt Memory Status")
    print(f"{'─'*40}")
    print(f"  Tier       : {tier.upper()}")
    print(f"  Encrypted  : {stats.get('encrypted', False)}")
    print(f"  Storage    : {stats.get('storage_path')}")
    print(f"  Retention  : {stats.get('retention_years', 10)} years")

    if tier == "free":
        print(f"  Events     : {stats.get('total_events', 0)}")
        months = stats.get("months", [])
        if months:
            print("\n  Monthly breakdown:")
            for m in months[-6:]:
                print(f"    {m['month']}: {m['count']} events")
        print("\n[PiQrypt] Agent operating with local-only trust")
    else:
        print(f"  Session    : {'active' if stats.get('session_active') else 'locked'}")
        months = stats.get("months", [])
        if months:
            print(f"  Monthly files: {len(months)}")
        if not stats.get("session_active"):
            print("\n[PiQrypt] Run: piqrypt memory unlock")

    print()


def cmd_memory_unlock(args):
    """piqrypt memory unlock [--permanent]"""
    import getpass
    from aiss.memory import unlock

    passphrase = args.passphrase or getpass.getpass("🔒 Memory passphrase: ")
    permanent = getattr(args, 'permanent', False)

    try:
        unlock(passphrase, permanent=permanent)
        mode = "permanently" if permanent else "for 1 hour"
        print(f"✓ Memory unlocked {mode}")
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1


def cmd_memory_lock(args):
    """piqrypt memory lock"""
    from aiss.memory import lock
    lock()
    print("✓ Memory locked")


def cmd_memory_search(args):
    """piqrypt memory search — v1.6: supports --session and --follow-rotation"""
    from aiss.memory import search_events
    import json

    session_id = getattr(args, 'session', None)
    follow_rotation = getattr(args, 'follow_rotation', False)
    results = search_events(
        participant=args.agent,
        event_type=args.type,
        limit=args.limit or 20,
        session_id=session_id,
        follow_rotation=follow_rotation,
    )

    if not results:
        print("No events found.")
        return

    print(f"\nFound {len(results)} events:\n")
    for e in results:
        import datetime
        ts = datetime.datetime.fromtimestamp(
            e.get("timestamp", 0),
            tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        nonce = e.get("nonce", "")[:8]
        et = e.get("payload", {}).get("event_type", "event")
        aid = e.get("agent_id", "")[:16]
        print(f"  {nonce} | {ts} | {aid} | {et}")

    if args.json:
        print(f"\n{json.dumps(results, indent=2)}")


def cmd_memory_encrypt(args):
    """piqrypt memory encrypt — migrate Free events to encrypted Pro storage"""
    import getpass
    from aiss.memory import migrate_to_encrypted

    print("⚠️  This will encrypt all plaintext events with AES-256-GCM.")
    print("   Original files will be renamed to .json.migrated")
    print()

    passphrase = args.passphrase or getpass.getpass("🔒 Set encryption passphrase: ")
    confirm = getpass.getpass("🔒 Confirm passphrase: ")

    if passphrase != confirm:
        print("❌ Passphrases do not match.")
        return 1

    result = migrate_to_encrypted(passphrase)
    print("\n✓ Migration complete:")
    print(f"  Events migrated : {result['migrated']}")
    print(f"  Months migrated : {result['months']}")
    print(f"  Errors          : {result['errors']}")


def cmd_a2a_propose(args):
    """piqrypt a2a propose --identity IDENTITY_FILE"""
    import json
    from aiss.a2a import create_identity_proposal

    identity_data = load_json(args.identity)
    priv = aiss.crypto.ed25519.decode_base64(identity_data["private_key"])
    pub = aiss.crypto.ed25519.decode_base64(identity_data["identity"]["public_key"])
    agent_id = identity_data["identity"]["agent_id"]

    proposal = create_identity_proposal(
        priv, pub, agent_id,
        capabilities=["stamp", "verify", "a2a", "task_delegation"]
    )

    if args.output:
        save_json(proposal, args.output)
    else:
        print(json.dumps(proposal, indent=2))

    print(f"\n✓ Proposal created for: {agent_id[:16]}...")
    print(f"  Session nonce: {proposal['session_nonce'][:8]}...")
    print("  Send this to peer agent.")


def cmd_a2a_respond(args):
    """piqrypt a2a respond --identity MY_IDENTITY --proposal PROPOSAL_FILE"""
    import json
    from aiss.a2a import perform_handshake

    identity_data = load_json(args.identity)
    priv = aiss.crypto.ed25519.decode_base64(identity_data["private_key"])
    pub = aiss.crypto.ed25519.decode_base64(identity_data["identity"]["public_key"])
    agent_id = identity_data["identity"]["agent_id"]

    peer_proposal = load_json(args.proposal)

    result = perform_handshake(
        priv, pub, agent_id, peer_proposal,
        store_in_memory=True
    )

    if args.output:
        save_json(result["response"], args.output)
    else:
        print(json.dumps(result["response"], indent=2))

    print("\n✓ Handshake complete!")
    print(f"  Session ID : {result['session_id'][:8]}...")
    print(f"  Peer       : {result['peer_agent_id'][:16]}...")
    print("  Stored in memory: yes")


def cmd_a2a_peers(args):
    """piqrypt a2a peers"""
    from aiss.a2a import list_peers

    peers = list_peers()

    if not peers:
        print("No peers registered yet.")
        print("\n[PiQrypt] Use 'piqrypt a2a propose' to initiate A2A handshake")
        return

    print(f"\nRegistered peers ({len(peers)}):\n")
    print(f"  {'Agent ID':<20} {'Interactions':>12} {'Trust Score':>12} {'Last Seen'}")
    print(f"  {'─'*68}")

    for p in peers:
        import datetime
        ls = datetime.datetime.fromtimestamp(
            p.get("last_seen", 0), tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d")
        trust = f"{p.get('trust_score', 1.0):.2f}"
        print(f"  {p['agent_id'][:20]:<20} {p['interaction_count']:>12} {trust:>12} {ls}")
    print()


def cmd_archive_create(args):
    """piqrypt archive --output OUTPUT.pqz [--agent AGENT_ID] [--encrypt]"""
    import getpass
    from aiss.memory import load_events
    from aiss.archive import create_archive

    identity_data = load_json(args.identity)
    identity = identity_data["identity"]
    agent_id = identity["agent_id"]

    events = load_events(agent_id=agent_id)

    if not events:
        print(f"No events found for agent {agent_id[:16]}...")
        return 1

    passphrase = None
    if args.encrypt:
        from aiss.license import is_pro
        if not is_pro():
            print("[PiQrypt] Encrypted archives require Pro license")
            print("[PiQrypt] Archive will be created without encryption")
        else:
            passphrase = args.passphrase or getpass.getpass("🔒 Archive passphrase: ")

    output = args.output or f"piqrypt-archive-{agent_id[:8]}.pqz"

    meta = create_archive(events, identity, output, passphrase=passphrase)

    print(f"\n✓ Archive created: {output}")
    print(f"  Events     : {meta['events_count']}")
    print(f"  Encrypted  : {meta['encrypted']}")
    print(f"  Size       : {meta.get('size_mb', 0):.2f} MB")
    print(f"  Period     : {meta.get('period_start', '')[:10]} → {meta.get('period_end', '')[:10]}")
    print(f"\n  To read: python decrypt.py {output}")
    print(f"  To verify: python verify.py {output}")


def cmd_archive_import(args):
    """piqrypt import ARCHIVE.pqz"""
    import getpass
    from aiss.archive import import_archive

    passphrase = args.passphrase
    if not passphrase and args.archive.endswith('.pqz'):
        try:
            passphrase = getpass.getpass("🔒 Archive passphrase (press Enter if unencrypted): ")
            if not passphrase:
                passphrase = None
        except Exception:
            passphrase = None

    result = import_archive(args.archive, passphrase=passphrase)

    print(f"\n✓ Archive imported: {args.archive}")
    print(f"  Imported   : {result['imported']} events")
    print(f"  Agent      : {result.get('agent_id', '')[:16]}...")
    print(f"  Period     : {result.get('period_start', '')[:10]} → {result.get('period_end', '')[:10]}")


def _ts_tier_icon(tier: str) -> str:
    return {"Elite": "🏆", "A+": "✅", "A": "✅", "B": "⚠️", "At Risk": "❌"}.get(tier, "")


def _tsi_state_icon(state: str) -> str:
    return {"STABLE": "🟢", "WATCH": "🟡", "UNSTABLE": "🟠", "CRITICAL": "🔴"}.get(state, "⚪")


def cmd_trust_score_compute(args):
    """piqrypt trust-score compute <agent_id> [--json] [--full]"""
    import json as _json
    from aiss.trust_score import compute_trust_score
    from aiss.tsi_engine import compute_tsi

    result = compute_trust_score(args.agent_id)
    tsi = compute_tsi(args.agent_id, current_score=result["trust_score"])

    if args.json:
        print(_json.dumps({"trust_score": result, "tsi": tsi}, indent=2))
        return

    ts = result["trust_score"]
    tier = result["tier"]
    icon = _ts_tier_icon(tier)
    tsi_icon = _tsi_state_icon(tsi["tsi_state"])

    print(f"\nTrust Score — {args.agent_id[:24]}...")
    print(f"{'─'*44}")
    print(f"  Score global  : {ts:.4f}  [{tier}] {icon}")
    print(f"  TSI State     : {tsi['tsi_state']} {tsi_icon}")
    print()
    comps = result.get("components", {})
    labels = {
        "I":   ("I   (Integrity)      ", 1.00),
        "V_t": ("V_t (Verified)       ", 0.80),
        "D_t": ("D_t (Diversity)      ", 0.70),
        "F":   ("F   (Finalization)   ", 0.80),
        "R":   ("R   (Rotation Health)", 0.80),
    }
    for key, (label, warn_threshold) in labels.items():
        val = comps.get(key, 1.0)
        flag = "✅" if val >= warn_threshold else "⚠️"
        print(f"  {label} : {val:.4f}  {flag}")

    if args.full:
        print()
        print("  Détails composantes :")
        for key, detail in result.get("component_details", {}).items():
            print(f"    {key}: {detail}")

    a2c = result.get("a2c_risk")
    print(f"\n  A2C Risk      : {'N/A (disponible v1.7.0)' if a2c is None else a2c}")
    print(f"  Événements    : {result['event_count']}")
    print()


def cmd_trust_score_history(args):
    """piqrypt trust-score history <agent_id> [--days N] [--json]"""
    import json as _json
    from aiss.tsi_engine import get_tsi_history

    history = get_tsi_history(args.agent_id, days=args.days)

    if args.json:
        print(_json.dumps(history, indent=2))
        return

    print(f"\nTrust Score History — {args.agent_id[:24]}... (derniers {args.days}j)")
    print(f"  {'Date':<12} {'Score':>7}  {'Tier':<8}")
    print(f"  {'─'*12} {'─'*7}  {'─'*8}")
    for snap in history:
        from aiss.trust_score import _tier
        tier = _tier(snap["score"])
        print(f"  {snap['date']:<12} {snap['score']:>7.4f}  {tier}")
    if not history:
        print("  Aucun historique disponible (premier calcul).")
    print()


def cmd_trust_score_compare(args):
    """piqrypt trust-score compare AGENT_A AGENT_B [--json]"""
    import json as _json
    from aiss.trust_score import compute_trust_score
    from aiss.tsi_engine import compute_tsi

    ra = compute_trust_score(args.agent_a)
    rb = compute_trust_score(args.agent_b)
    tsi_a = compute_tsi(args.agent_a, current_score=ra["trust_score"])
    tsi_b = compute_tsi(args.agent_b, current_score=rb["trust_score"])

    if args.json:
        print(_json.dumps({
            "agent_a": {"trust_score": ra, "tsi": tsi_a},
            "agent_b": {"trust_score": rb, "tsi": tsi_b},
        }, indent=2))
        return

    a_id = args.agent_a[:16]
    b_id = args.agent_b[:16]
    print(f"\nComparaison Trust Score")
    print(f"  {'Métrique':<22} {a_id:<18} {b_id:<18} {'Δ':>8}")
    print(f"  {'─'*22} {'─'*18} {'─'*18} {'─'*8}")

    rows = [
        ("Score global", ra["trust_score"], rb["trust_score"]),
        ("I  (Integrity)",      ra["components"].get("I", 0),   rb["components"].get("I", 0)),
        ("V_t (Verified)",      ra["components"].get("V_t", 0), rb["components"].get("V_t", 0)),
        ("D_t (Diversity)",     ra["components"].get("D_t", 0), rb["components"].get("D_t", 0)),
        ("F  (Finalization)",   ra["components"].get("F", 0),   rb["components"].get("F", 0)),
        ("R  (Rotation)",       ra["components"].get("R", 0),   rb["components"].get("R", 0)),
    ]
    for label, va, vb in rows:
        delta = va - vb
        sign = "+" if delta >= 0 else ""
        print(f"  {label:<22} {va:<18.4f} {vb:<18.4f} {sign}{delta:>7.4f}")

    print(f"\n  Tier A : {ra['tier']} {_ts_tier_icon(ra['tier'])}")
    print(f"  Tier B : {rb['tier']} {_ts_tier_icon(rb['tier'])}")
    print(f"  TSI  A : {tsi_a['tsi_state']} {_tsi_state_icon(tsi_a['tsi_state'])}")
    print(f"  TSI  B : {tsi_b['tsi_state']} {_tsi_state_icon(tsi_b['tsi_state'])}")
    print()


def cmd_sentinel_status(args):
    """piqrypt sentinel status <agent_id> [--json]"""
    import json as _json
    from aiss.trust_score import compute_trust_score
    from aiss.tsi_engine import compute_tsi

    result = compute_trust_score(args.agent_id)
    tsi = compute_tsi(args.agent_id, current_score=result["trust_score"])

    if args.json:
        print(_json.dumps({"trust_score": result, "tsi": tsi}, indent=2))
        return

    ts = result["trust_score"]
    tsi_state = tsi["tsi_state"]
    tsi_icon = _tsi_state_icon(tsi_state)

    print(f"\nSentinel Status — {args.agent_id[:24]}...")
    print(f"{'─'*44}")
    print(f"  Trust Score   : {ts:.4f}  [{result['tier']}] {_ts_tier_icon(result['tier'])}")
    print(f"  TSI State     : {tsi_state} {tsi_icon}")
    d24 = tsi.get("delta_24h")
    d7  = tsi.get("delta_7d")
    z   = tsi.get("z_score")
    print(f"  Δ 24h         : {f'{d24:+.4f}' if d24 is not None else 'N/A (historique insuffisant)'}")
    print(f"  Δ 7j          : {f'{d7:+.4f}'  if d7  is not None else 'N/A'}")
    print(f"  Z-score       : {f'{z:.4f}'    if z   is not None else 'N/A'}")

    reasons = tsi.get("drift_reasons", [])
    if reasons:
        print(f"  Alertes       : {len(reasons)}")
        for r in reasons:
            print(f"    • {r}")
    else:
        print(f"  Alertes       : 0 actives")

    print(f"  A2C Risk      : N/A (disponible v1.7.0)")
    print(f"  Snapshots     : {tsi['snapshot_count']} (fenêtre {tsi['window_days']}j)")
    print()


def cmd_status(args):
    """piqrypt status [--deep]"""
    from aiss.memory import get_memory_stats, load_events
    from aiss.license import is_pro, get_tier
    from aiss.a2a import list_peers

    tier = get_tier()

    print("\nPiQrypt Status")
    print(f"{'─'*40}")

    stats = get_memory_stats()
    total_events = stats.get("total_events", 0)
    if total_events == 0 and stats.get("months"):
        # Pro: approximate from file sizes
        total_events = f"~{len(stats.get('months', []))} months encrypted"

    print("  Identity    : active")
    print(f"  Tier        : {tier.upper()}")
    print(f"  Events      : {total_events}")
    print("  Chain       : verified ✓")
    print(f"  Protection  : {'encrypted (Pro)' if is_pro() and stats.get('encrypted') else 'local'}")

    if args.deep if hasattr(args, 'deep') else False:
        if not is_pro():
            print("\n[PiQrypt] Deep status available in Pro")
            print("[PiQrypt] Network trust available (Pro)")
            return

        peers = list_peers()
        print(f"\n  Network peers : {len(peers)}")
        if peers:
            avg_trust = sum(p.get("trust_score", 1.0) for p in peers) / len(peers)
            print(f"  Avg trust     : {avg_trust:.2f}")

        # Trust score for own chain
        from aiss.a2a import compute_trust_score
        events_raw = load_events()
        if events_raw:
            ts = compute_trust_score("", events_raw)
            print(f"  Trust score   : {ts['trust_score']} ({ts['tier']})")
    else:
        print("\n[PiQrypt] Agent operating with local-only trust")
        if not is_pro():
            print("[PiQrypt] Network trust available (Pro)")

    print()
