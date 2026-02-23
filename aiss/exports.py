"""
Audit Export Format (RFC Section 15)

This module implements the standard audit export format for
regulatory compliance and forensic analysis.
"""

import time
from typing import Dict, Any, List

from aiss.chain import compute_chain_hash
from aiss.exceptions import AISSError

class LicenseError(AISSError):
    """License validation error."""
    pass


def export_audit_chain(
    agent_identity: Dict[str, Any],
    events: List[Dict[str, Any]],
    include_metadata: bool = True
) -> Dict[str, Any]:
    """
    Export event chain in RFC Section 15 compliant format.

    Creates standardized audit file containing:
    - Agent identity document
    - Complete event chain
    - Chain integrity hash
    - Export metadata

    This format is designed for:
    - Regulatory compliance
    - Forensic analysis
    - Third-party audits
    - Archive/backup

    Args:
        agent_identity: Agent identity document
        events: List of events in chronological order
        include_metadata: Include export metadata (default: True)

    Returns:
        Audit export dict conforming to RFC Section 15

    Example:
        >>> audit = export_audit_chain(identity, events)
        >>> audit['spec']
        'AISS-1.0-AUDIT'
        >>> len(audit['events'])
        100
    """
    audit = {
        "spec": "AISS-1.0-AUDIT",
        "agent_identity": agent_identity,
        "events": events,
        "chain_integrity_hash": compute_chain_hash(events),
        "exported_at": int(time.time())
    }

    if include_metadata:
        audit["metadata"] = {
            "event_count": len(events),
            "first_timestamp": events[0].get('timestamp') if events else None,
            "last_timestamp": events[-1].get('timestamp') if events else None,
            "exporter": "piqrypt/1.0.0"
        }

    return audit


def validate_audit_export(audit: Dict[str, Any]) -> bool:
    """
    Validate audit export structure.

    Checks:
    - Required fields present
    - Spec version correct
    - Chain integrity hash matches

    Args:
        audit: Audit export dict

    Returns:
        True if valid

    Raises:
        ValueError: If audit export invalid
    """
    # Check required fields
    required = ['spec', 'agent_identity', 'events', 'chain_integrity_hash', 'exported_at']
    for field in required:
        if field not in audit:
            raise ValueError(f"Missing required field: {field}")

    # Check spec version
    if not audit['spec'].startswith('AISS-'):
        raise ValueError(f"Invalid spec version: {audit['spec']}")

    # Verify chain integrity hash
    events = audit['events']
    expected_hash = compute_chain_hash(events)
    actual_hash = audit['chain_integrity_hash']

    if expected_hash != actual_hash:
        raise ValueError(
            f"Chain integrity hash mismatch: expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
        )

    return True


def export_subset(
    audit: Dict[str, Any],
    start_index: int = 0,
    end_index: int = None
) -> Dict[str, Any]:
    """
    Export subset of events from audit chain.

    Useful for:
    - Time-range exports
    - Pagination
    - Selective disclosure

    Args:
        audit: Full audit export
        start_index: First event index (inclusive)
        end_index: Last event index (exclusive, None = end)

    Returns:
        New audit export with subset of events
    """
    events = audit['events'][start_index:end_index]

    return export_audit_chain(
        agent_identity=audit['agent_identity'],
        events=events,
        include_metadata=True
    )


def export_by_timerange(
    audit: Dict[str, Any],
    start_timestamp: int,
    end_timestamp: int
) -> Dict[str, Any]:
    """
    Export events within timestamp range.

    Args:
        audit: Full audit export
        start_timestamp: Start time (Unix UTC)
        end_timestamp: End time (Unix UTC)

    Returns:
        New audit export with filtered events
    """
    events = [
        e for e in audit['events']
        if start_timestamp <= e.get('timestamp', 0) <= end_timestamp
    ]

    return export_audit_chain(
        agent_identity=audit['agent_identity'],
        events=events,
        include_metadata=True
    )


def get_audit_summary(audit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate summary statistics from audit export.

    Returns:
        Summary dict with:
        - agent_id: Agent ID
        - event_count: Total events
        - timespan: Time from first to last event (seconds)
        - chain_hash: Integrity hash
        - export_date: Export timestamp
    """
    events = audit['events']

    summary = {
        "spec": audit['spec'],
        "agent_id": audit['agent_identity'].get('agent_id'),
        "event_count": len(events),
        "chain_hash": audit['chain_integrity_hash'],
        "export_date": audit['exported_at']
    }

    if events:
        first_ts = events[0].get('timestamp', 0)
        last_ts = events[-1].get('timestamp', 0)

        summary.update({
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "timespan_seconds": last_ts - first_ts
        })

    return summary


def export_certified(
    identity: Dict[str, Any],
    events: List[Dict[str, Any]],
    private_key: bytes
) -> Dict[str, Any]:
    """
    Export with cryptographic certification (v1.1.0)

    Self-signed for now – PiQrypt CA in a future release.
    Requires Pro license.

    Args:
        identity: Agent identity document
        events: List of signed events
        private_key: Agent private key (Ed25519) to sign the export

    Returns:
        Certified audit dict with 'certification' block

    Raises:
        AISSError: If Pro license not active
    """
    from aiss.license import require_pro
    from aiss.crypto import ed25519

    @require_pro("Certified export")
    def _do_export():
        audit = export_audit_chain(identity, events)

        # Hash of the full audit (sans certification)
        chain_hash = audit["chain_integrity_hash"]

        # Sign the chain hash
        sig_bytes = ed25519.sign(private_key, chain_hash.encode())
        sig_b58 = ed25519.encode_base58(sig_bytes)

        audit["certification"] = {
            "issued_by": "PiQrypt v1.1.0",
            "issued_at": int(time.time()),
            "chain_hash": chain_hash,
            "signature_algorithm": "Ed25519",
            "signature": sig_b58,
            "verification": "python -m piqrypt verify_export <file.json>",
        }
        return audit

    return _do_export()


# Public API
__all__ = [
    "export_audit_chain",
    "export_certified",
    "validate_audit_export",
    "export_subset",
    "export_by_timerange",
    "get_audit_summary",
]


# ─── New API: certify_export / verify_certified_export ────────────────────────

def certify_export(export_path: str, private_key: bytes, agent_id: str) -> str:
    """
    Certify an existing audit JSON file with a cryptographic certificate.

    Creates a .cert file alongside the JSON export.

    Args:
        export_path: Path to audit.json
        private_key: Agent's Ed25519 private key
        agent_id:    Agent ID string

    Returns:
        Path to .cert file

    Example:
        cert = certify_export("audit.json", private_key, agent_id)
        # Creates audit.json.cert
    """
    import hashlib
    import time as _time
    import json as _json
    from aiss.crypto import ed25519
    from aiss.license import is_pro

    if not is_pro():
        from aiss.logger import log_certified_export_required
        log_certified_export_required()
        raise LicenseError("Certified export requires Pro license")

    # Hash the export file
    with open(export_path, 'rb') as f:
        data = f.read()
    export_hash = hashlib.sha256(data).hexdigest()

    # Sign the hash
    sig_bytes = ed25519.sign(private_key, export_hash.encode('utf-8'))

    cert = {
        "version": "AISS-CERT-1",
        "export_hash": f"sha256:{export_hash}",
        "signed_at": int(_time.time()),
        "agent_id": agent_id,
        "signing_algorithm": "Ed25519",
        "signature": ed25519.encode_base64(sig_bytes),
    }

    cert_path = export_path + ".cert"
    with open(cert_path, 'w') as f:
        _json.dump(cert, f, indent=2)

    from aiss.logger import log_certified_export_created
    log_certified_export_created(export_path)
    return cert_path


def verify_certified_export(export_path: str, cert_path: str) -> bool:
    """
    Verify a certified export file against its certificate.

    Args:
        export_path: Path to audit.json
        cert_path:   Path to audit.json.cert

    Returns:
        True if certification is valid

    Example:
        piqrypt verify-export audit.json audit.json.cert
        → Export integrity: VERIFIED
    """
    import hashlib
    import json as _json
    from aiss.crypto import ed25519
    from aiss.exceptions import InvalidSignatureError

    try:
        with open(export_path, 'rb') as f:
            data = f.read()
        with open(cert_path, 'r') as f:
            cert = _json.load(f)

        # Verify hash
        computed = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if cert.get('export_hash') != computed:
            return False

        # Verify signature (need public key from export)
        with open(export_path, 'r') as f:
            audit = _json.load(f)

        pub_key_b64 = audit.get('agent_identity', {}).get('public_key')
        if not pub_key_b64:
            return False

        pub_key = ed25519.decode_base64(pub_key_b64)
        sig_bytes = ed25519.decode_base64(cert['signature'])
        hash_str = cert['export_hash'].replace('sha256:', '')

        ed25519.verify(pub_key, hash_str.encode('utf-8'), sig_bytes)
        return True

    except (InvalidSignatureError, KeyError, FileNotFoundError, Exception):
        return False


# Update __all__
if 'certify_export' not in __all__:
    __all__.extend(['certify_export', 'verify_certified_export'])


def export_audit_chain_to_file(
    events: List[Dict[str, Any]],
    agent_identity: Dict[str, Any],
    output_path: str,
    include_metadata: bool = True
) -> str:
    """
    Export event chain to a JSON file.
    Convenience wrapper around export_audit_chain that writes to disk.

    Args:
        events:           Events in chronological order
        agent_identity:   Agent identity document
        output_path:      Path to write JSON file
        include_metadata: Include export metadata

    Returns:
        Path to written file
    """
    import json as _json
    audit = export_audit_chain(agent_identity, events, include_metadata)
    with open(output_path, 'w') as f:
        _json.dump(audit, f, indent=2)
    from aiss.logger import log_export_created
    log_export_created(output_path, certified=False)
    return output_path


if 'export_audit_chain_to_file' not in __all__:
    __all__.append('export_audit_chain_to_file')
