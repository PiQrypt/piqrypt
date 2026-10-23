# Limits and posture (PiQrypt 1.10)

This document says what PiQrypt 1.10 does, what it does not do, and how to read its outputs.
Every statement here was checked against the code of this release. When the code and another
document disagree, the code and this document win, and the other document is a defect to report.

PiQrypt is a library for signing events, chaining them by hash and verifying them offline. It is
not an audit, a certification, a legal service or a compliance programme, and nothing it prints
should be presented as one.

## 1. What a successful verification means

`verify_chain` and `get_verification_report` establish, for the events and the identity document
you pass in:

* each event carries the signatures its version requires, and they verify under the keys of that
  identity document (Ed25519 for AISS-1; Ed25519 and ML-DSA-65, both required, for AISS-2.1);
* each event commits to the previous one by hash (SHA-256 for AISS-1 and AISS-2.0, SHA-512 for
  AISS-2.1) and the chain is not broken;
* for AISS-2.1, the `agent_id` of every event matches the identity, the identity binding (if any)
  verifies, and the anti-downgrade rule holds.

It does **not** establish:

* that the identity document belongs to a given person, organisation or machine. PiQrypt binds
  events to keys, not keys to the real world;
* that what an event says is true, or that the host was not compromised when it was signed;
* that the log is complete. Removing the last events of a hash chain leaves a valid chain. Only an
  external anchor (an RFC 3161 token you verified, a copy held by someone else) can show that
  nothing newer existed;
* that the chain starts at a genesis event: `verify_chain` does not require it, so a chain whose
  head was cut can verify (this is a known limit to settle in the AISS-2.1 text);
* that two logs of the same agent do not diverge. A fork is detected by comparing two logs, not
  inside one list of events.

The `valid` field of a report covers the points in the first list. Timestamps are reported in a
separate `tsa` section that never changes `valid`.

## 2. Cryptography

| Item | AISS-1 | AISS-2.0 (legacy, still verifiable) | AISS-2.1 |
|---|---|---|---|
| Signatures | Ed25519 (RFC 8032) | Ed25519 and ML-DSA-65 | Ed25519 and ML-DSA-65, domain separated, empty ML-DSA context |
| Chain hash | SHA-256 | SHA-256 | SHA-512 (128 hexadecimal characters) |
| Canonical form | PiQrypt AISS-1 canonicalization | as AISS-1 | RFC 8785 (JCS) |
| Quantum-resistant signatures | No | Yes, both signatures are required | Yes, both signatures are required |

* **AISS-1 is not quantum-resistant.** Ed25519 can be broken by a sufficiently large quantum
  computer. Use AISS-2.1 for chains that must stay verifiable over decades.
* **ML-DSA-65 is the algorithm of NIST FIPS 204.** The implementation reproduces the NIST ACVP
  vectors through dilithium-py (keyGen, sigVer and sigGen, deterministic groups). No module of
  PiQrypt has been validated under any NIST programme (CMVP, FIPS 140-3). The `fips` entry of the
  backend information names the standard being implemented, not a validation.
* **Backends.** liboqs is used when it is installed and exposes ML-DSA-65. Otherwise PiQrypt falls
  back to dilithium-py, a pure-Python implementation. Its authors state that it is educational,
  not constant time and not designed to resist side-channel attacks, and that it should not be used
  for cryptographic applications. For signing outside tests, install the `post-quantum` extra
  (liboqs-python, Python 3.10 or later). Verification handles no private key, so the side-channel
  concern applies mainly to key generation and signing.
* **Interoperability.** The workflow that cross-checks liboqs and dilithium-py on the AISS-2.1
  vectors has never been run. Until it has, do not rely on a claim that the two backends agree on
  PiQrypt messages. The independent verifier in `test_vectors_aiss21/` is a second implementation of
  the format that imports nothing from PiQrypt; a test checks that its verdicts and the library's
  match on all 57 vectors.
* **Keys at rest.** Encrypted keys use AES-256-GCM with a scrypt-derived key (N = 2^17, r = 8, p = 1
  by default). Through the API, an AISS-1 identity created without a passphrase keeps its Ed25519
  key as plaintext (`private.key.json`); a hybrid identity always requires a passphrase (8
  characters minimum). File
  permissions 0o600 are applied on POSIX only. Erasure of key material in memory is best effort:
  Python `bytes` are immutable and can be copied, cryptographic libraries keep internal copies,
  memory is not locked, and swap is not controlled. This reduces the window of exposure; it does not
  remove it.
* **Custody.** The Signer interface lets a hardware module or a KMS hold the keys, but none has been
  tested, level 3 of the RFC is not implemented, and identity bindings and hybrid rotation
  attestations do not use the interface yet (`docs/SIGNER.md`).

## 3. Time

Without a verified RFC 3161 token, the time of an event is whatever its signer wrote. See
`docs/TIMESTAMPS.md` for the details; in short:

* the `trusted_timestamp` field is detached and unsigned, so its presence and its `status` prove
  nothing;
* a token is `verified` only when its CMS signature, imprint, nonce, TSA certificate and chain to a
  trust root that **you** configured all check out. PiQrypt ships no trust root;
* revocation of the TSA certificate is not checked;
* a token from a free public TSA is not a qualified electronic time stamp, and PiQrypt does not
  turn it into one;
* DigiCert and Entrust tokens currently verify as `invalid` because the parser used
  (`rfc3161-client` 1.0.9) cannot read them. This fails closed and says nothing about the tokens;
* fork resolution counts a token only through a verifier you pass in.

## 4. Attestations and `piqrypt certify-verify`

`piqrypt certify-verify` checks two things: the format version of a certified export file, and the
signature of its attestation with the CA public key bundled in the package. It does not check:

* the audit data in the file (event signatures and hash chain);
* the link between the attestation and that audit data: the attestation contains no hash of the
  data, so the link is not established;
* timestamp tokens, or the revocation of any key or certificate;
* that the values recorded in the attestation are true. They are shown as recorded by the issuer.

A signed attestation is evidence that the issuer signed a record. It is not an audit and it is not a
legal or regulatory statement. PiQrypt does not claim legal value, admissibility or conformity with
any regulation for its outputs, including `.pqz` exports and timestamp tokens.

## 5. Licences and what is gated

Gating is a commercial mechanism, not a security boundary. It is stated here because the behaviour
differs between the two packages.

* In `piqrypt` (Elastic-2.0), `stamp_event_aiss2_hybrid` and `stamp_genesis_event_aiss2_hybrid`
  require a Pro licence. Creating a hybrid identity, upgrading an identity, and hybrid rotation are
  not licence-checked. Without a licence that grants the quantum feature, a per-process counter
  limits ML-DSA-65 operations (1000).
* In `aiss-standard` (MIT) there is no licence module: the same functions are not gated,
  and the ML-DSA-65 backend shipped from 1.10.0 applies no operation limit. Releases of
  `aiss-standard` up to 2.0.2 applied the same 1000 operation limit.
* Requesting an RFC 3161 token is not licence-checked in 1.10.
* The Free-tier token is checked with a local HMAC whose secret is in the source, and the demo
  counter lives in the process. Neither is designed to resist a determined user.
* Verification is never gated: anyone can verify any chain, in either package.

The tier descriptions on the website and in the pricing documents describe commercial
entitlement. Where they list a feature that the code does not enforce, the code behaviour above is
what happens.

## 6. Local services

Vigil (port 8421) and TrustGate (port 8422) are local HTTP servers that bind to 127.0.0.1 by
default and authenticate with a static bearer token taken from the environment (`VIGIL_TOKEN`,
`TRUSTGATE_TOKEN`). The token is shared: there is no per-user identity, and the servers speak plain
HTTP. Do not expose them to a network without a reverse proxy that provides TLS and your own
access control.

## 7. Wording used in PiQrypt documents

PiQrypt documents describe what a function checks, not what a result is worth. They use words such
as "signs", "verifies locally", "hash-chained", "tamper-evident" (a change to a stamped event is
detectable), "declared by the issuer" and "not checked by this command".

They do not use "certified" for the output of a local check, "compliant" or "conformant" for the
code, "audit" for a library result, "independent" for something PiQrypt produced itself, or
"legally admissible", "court-admissible", "qualified" or "eIDAS" for any output. If you find one in
a document or a message, it is a defect: please report it.

## 8. Reporting

Security issues: security@piqrypt.com, as described in `SECURITY.md`. Errors in this document, or
a statement here that the code does not support, are defects too and can be reported the same way.
