# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Tests - texte affiché par `piqrypt certify-verify` et texte de l'attestation émise.

Le texte ne doit contenir ni affirmation de certification, ni valeur légale ou réglementaire. Il
dit ce qui a été contrôlé localement et ce qui ne l'a pas été. Tier free, sans réseau : la clé de
l'autorité est une clé de test injectée à la place de la clé livrée avec le paquet.
"""
import nacl.signing  # noqa: F401

import contextlib
import hashlib
import io
import json
import re
import zipfile
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import aiss
from aiss.crypto import ed25519
from aiss.exports import export_audit_chain
from aiss import external_cert

FORBIDDEN = [
    r"independently\s+certified", r"valid\s+for\s+legal", r"legal\s+and\s+compliance",
    r"compliance\s+purposes", r"\bcertified\b", r"\bcertification\s+valid\b", r"\bcompliant\b",
    r"\baudited\b", r"legal\s+purposes", r"legally", r"legal\s+statement",
]


def assert_no_forbidden(text):
    # La ligne "File:" reprend le chemin donné par l'utilisateur (extension .piqrypt-certified).
    text = "\n".join(line for line in text.splitlines() if not line.strip().startswith("File:"))
    for pattern in FORBIDDEN:
        assert not re.search(pattern, text, re.IGNORECASE), (pattern, text)


def make_request_zip(tmp_path):
    priv, pub = ed25519.generate_keypair()
    agent_id = aiss.derive_agent_id(pub)
    events = [aiss.stamp_event(priv, agent_id, {"i": i}, nonce=f"n{i}") for i in range(3)]
    audit = export_audit_chain(aiss.export_identity(agent_id, pub), events)
    audit_bytes = json.dumps(audit, indent=2).encode()
    certificate = {
        "agent_id": agent_id,
        "export_hash": f"sha256:{hashlib.sha256(audit_bytes).hexdigest()}",
        "signature": "present-but-not-checked",
    }
    archive = tmp_path / "request.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("request.json", json.dumps({"request_id": "CERT-TEST-0001", "user_email": "user@example.com"}))
        zf.writestr("audit.json", audit_bytes)
        zf.writestr("audit.json.cert", json.dumps(certificate))
    return archive


def make_ca(tmp_path):
    ca_priv, ca_pub = ed25519.generate_keypair()
    key_file = tmp_path / "ca.key"
    key_file.write_text(json.dumps({"ca_id": "piqrypt-ca-test-key-0001", "private_key": ed25519.encode_base64(ca_priv)}))
    return key_file, ca_pub


def run_certify_verify(path, ca_pub):
    from cli.main import cmd_certify_verify
    out = io.StringIO()
    code = 0
    with patch.object(external_cert, "load_ca_public_key", return_value=(ca_pub, "piqrypt-ca-test-key-0001")):
        with contextlib.redirect_stdout(out):
            try:
                cmd_certify_verify(Namespace(certified_file=str(path)))
            except SystemExit as exc:
                code = exc.code
    return out.getvalue(), code


def issue(tmp_path):
    key_file, ca_pub = make_ca(tmp_path)
    certified = external_cert.validate_and_certify(str(make_request_zip(tmp_path)), str(key_file), str(tmp_path))
    return Path(certified), ca_pub


def test_issued_attestation_text_is_factual_and_free_of_forbidden_claims(tmp_path):
    certified, ca_pub = issue(tmp_path)
    statement = json.loads(certified.read_text())["piqrypt_attestation"]["legal_statement"]
    assert_no_forbidden(statement)
    for fact in ("export_hash", "chain integrity hash", "presence only", "Revocation was not checked",
                 "neither an independent audit nor a legal or regulatory statement"):
        assert fact in statement


def test_command_output_is_factual_and_free_of_forbidden_claims(tmp_path):
    certified, ca_pub = issue(tmp_path)
    output, code = run_certify_verify(certified, ca_pub)
    assert code == 0
    assert_no_forbidden(output)
    for expected in ("Attestation signature verified locally", "Checked locally by this command",
                     "Not checked by this command", "event signatures and hash chain",
                     "the link between the attestation and the audit data in the file",
                     "attestation contains no hash of that data",
                     "timestamp tokens", "revocation",
                     "neither an independent audit nor a legal or regulatory statement"):
        assert expected in output, expected
    assert "CERT-TEST-0001" in output  # l'identifiant de l'attestation reste affiché


def test_attestation_issued_with_the_old_wording_is_not_echoed(tmp_path):
    """Un ancien fichier porte l'ancienne formule dans son champ signé : elle n'est pas affichée."""
    certified, ca_pub = issue(tmp_path)
    key_file = tmp_path / "ca.key"
    ca_priv = ed25519.decode_base64(json.loads(key_file.read_text())["private_key"])
    document = json.loads(certified.read_text())
    attestation = document["piqrypt_attestation"]
    attestation.pop("ca_signature")
    attestation["legal_statement"] = ("PiQrypt Inc. has independently verified this export. "
                                      "Valid for legal and compliance purposes.")
    attestation["ca_signature"] = ed25519.encode_base64(
        ed25519.sign(ca_priv, json.dumps({k: v for k, v in attestation.items() if k != "ca_signature"},
                                         sort_keys=True).encode()))
    old = tmp_path / "old.piqrypt-certified"
    old.write_text(json.dumps(document))
    output, code = run_certify_verify(old, ca_pub)
    assert code == 0
    assert "Valid for legal" not in output and "independently verified" not in output
    assert_no_forbidden(output)


def test_exit_codes_and_failure_text_are_unchanged_in_meaning(tmp_path):
    certified, ca_pub = issue(tmp_path)
    document = json.loads(certified.read_text())
    document["piqrypt_attestation"]["certified_by"] = "someone else"
    tampered = tmp_path / "tampered.piqrypt-certified"
    tampered.write_text(json.dumps(document))
    output, code = run_certify_verify(tampered, ca_pub)
    assert code == 1
    assert "Attestation verification FAILED" in output
    assert_no_forbidden(output)
    _, other_pub = ed25519.generate_keypair()
    output, code = run_certify_verify(certified, other_pub)
    assert code == 1


def test_api_result_and_file_format_are_unchanged(tmp_path):
    certified, ca_pub = issue(tmp_path)
    document = json.loads(certified.read_text())
    assert sorted(document) == ["agent_certification", "audit", "piqrypt_attestation", "version"]
    assert document["version"] == "PIQRYPT-CERTIFIED-1.0"
    attestation = document["piqrypt_attestation"]
    assert sorted(attestation) == [
        "ca_id", "ca_signature", "certificate_id", "certified_at", "certified_by", "legal_statement",
        "request_id", "verification_results", "version"]
    assert sorted(attestation["verification_results"]) == [
        "agent_signature", "chain_integrity", "events_count", "export_hash"]
    result = external_cert.verify_piqrypt_certification(str(certified), ca_public_key=ca_pub, ca_key_id="x")
    assert result["status"] == "valid"
    assert sorted(result) == ["ca_id", "certificate_id", "certified_at", "certified_by", "legal_statement",
                              "status", "verification_results"]
