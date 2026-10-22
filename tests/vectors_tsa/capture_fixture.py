#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
"""
Capture of the real RFC 3161 fixtures stored next to this file. NOT run by the test suite
(network access): it was run once to produce freetsa_events.json and freetsa_cacert.pem.

It builds two deterministic events (one AISS-2.1, one AISS-1, from scripts/gen_aiss21_vectors.py),
asks https://freetsa.org/tsr for a token for each with aiss.rfc3161.request_timestamp, downloads
the public root certificate and records the SHA-256 that freetsa.org publishes for it.

Usage:  python tests/vectors_tsa/capture_fixture.py
"""
import datetime
import hashlib
import importlib.util
import json
import re
import sys
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TSA_URL = "https://freetsa.org/tsr"
sys.path.insert(0, str(ROOT))


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(request, timeout=60).read()


def main():
    spec = importlib.util.spec_from_file_location(
        "gen_aiss21_vectors", ROOT / "scripts" / "gen_aiss21_vectors.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    from aiss import rfc3161

    aiss21 = gen.event21(gen.A, 0, "tsa/aiss21", {"action": "timestamp fixture", "n": 1},
                         gen.genesis_hash(gen.A.agent_id))
    aiss1 = gen.event1(gen.B, 0, "tsa/aiss1", {"action": "timestamp fixture", "n": 1},
                       gen.sha256_hex(gen.B.ed_pub))
    aiss21.pop("trusted_timestamp", None)

    events = {}
    for label, event in (("aiss21", aiss21), ("aiss1", aiss1)):
        algorithm, digest, schema = rfc3161._imprint_for_event(event)
        token = rfc3161.request_timestamp(
            b"", tsa_url=TSA_URL, hash_algorithm=algorithm, digest=digest, schema=schema)
        stamped = dict(event)
        stamped["trusted_timestamp"] = token
        events[label] = stamped
        print(label, algorithm, digest.hex()[:16], "token", len(token["token"]))

    root_pem = fetch("https://freetsa.org/files/cacert.pem")
    (HERE / "freetsa_cacert.pem").write_bytes(root_pem)
    page = fetch("https://freetsa.org/").decode("utf-8", "replace")
    published = re.search(r"cacert\.pem\s*SHA256:\s*([0-9a-f]{64})", re.sub(r"<[^>]+>", " ", page))
    certificate = x509.load_pem_x509_certificate(root_pem)

    document = {
        "description": "Real RFC 3161 tokens from the public TSA freetsa.org for two deterministic "
                       "events. Public data only. Not a qualified timestamp service (eIDAS).",
        "tsa_url": TSA_URL,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": {
            "file": "freetsa_cacert.pem",
            "subject": certificate.subject.rfc4514_string(),
            "file_sha256": hashlib.sha256(root_pem).hexdigest(),
            "der_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "published_file_sha256": published.group(1) if published else None,
            "published_at": "https://freetsa.org/ (page lists the SHA256 of cacert.pem)",
            "not_valid_after": certificate.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "events": events,
    }
    with open(HERE / "freetsa_events.json", "w", encoding="utf-8", newline="\n") as fh:
        json.dump(document, fh, indent=1, sort_keys=True, ensure_ascii=True)
        fh.write("\n")
    print("written", HERE / "freetsa_events.json")


if __name__ == "__main__":
    main()
