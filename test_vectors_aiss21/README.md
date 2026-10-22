# AISS-2.1 test vectors

Target specification version: **AISS-2.1**. The specification text is still to be written;
until it is, these vectors and the reference implementation define the format, and
`verify_standalone.py` is the guard against the implementation defining the specification
by itself (see "Independent verifier").

These vectors are **interoperability test data**. They are not a certification, a
conformance claim or an audit result of any kind.

## Files

| File | Content |
|---|---|
| `keys.json` | Test agents A (native hybrid), B (AISS-1 identity upgraded to AISS-2.1), C (rotation target) plus helpers D and E (negatives). Seeds, public keys, private keys. |
| `agent_id.json` | `derive_agent_id_aiss21`, positive cases and wrong key sizes (31/33 bytes Ed25519, 1951/1953 bytes ML-DSA-65). |
| `hash_and_message.json` | For five events: JCS bytes, signed message M' and SHA-512 chain hash (hex). Non-ASCII, nested objects, large integers, detached fields. |
| `events.json` | Valid signed events and negatives (tampered payload, swapped signatures, missing signature, missing or non-strict `base64:`, versions `AISS-2.10` and `AISS-2.0`, foreign keys, integer outside +/-(2^53-1)). |
| `chains.json` | Native chain, upgraded-identity chain (AISS-1 then AISS-2.1), and negatives (downgrade, foreign `agent_id`, removed event, concurrent rotations). |
| `identities.json` | Native identity, upgraded identity with binding, and negatives (altered binding, replaced keys, ambiguous documents, `agent_id` not derived). |
| `rotation.json` | Four-signature rotation attestations and complete chained rotations (old chain, rotation event, new genesis), with negatives. |
| `verify_standalone.py` | Independent verifier (no import of `aiss` or `piqrypt`). |

Every file has a `description`, the targeted `spec_version` and, for each vector, `"valid"`
(`true` / `false`). Negative vectors carry a `"reason"`: a human explanation of the rule
that rejects them, **not** an error code to match.

All keys are **TEST ONLY**: they are derived from public labels (SHA-256 of a fixed string)
and must never be used anywhere else.

## Format summary

* **Canonicalization**: RFC 8785 (JCS) for every AISS-2.1 structure. Integers must stay
  within +/-(2^53-1).
* **agent_id (hybrid)**: `Base58(SHA-512(b"PiQrypt-AISS-2.1-agent-id\x00" || len32(pk_ed) || pk_ed || len32(pk_pq) || pk_pq))[0:32]`,
  lengths as 4-byte big-endian integers; `pk_ed` is 32 bytes, `pk_pq` is 1952 bytes.
* **Signed message**: `M' = domain_prefix || len(label) || label || 0x00 || JCS(document)`,
  `label = b"Ed25519+ML-DSA-65"` (one length byte), empty context (the `0x00`).
  For events the document excludes `signatures` and `trusted_timestamp`; for bindings and
  rotation attestations it excludes `signatures` only.
  Domain prefixes: events `b"PiQrypt-AISS-2.1\x00"`, binding `b"PiQrypt-AISS-2.1-binding\x00"`,
  rotation `b"PiQrypt-AISS-2.1-rotation\x00"`.
* **Signatures**: `"base64:" + base64` (strict alphabet, no whitespace), Ed25519 and
  ML-DSA-65 over the same M'. ML-DSA-65 is FIPS 204 pure signing with an empty context.
* **Chain hash**: SHA-512 of the JCS of the event without `signatures` and
  `trusted_timestamp` (128 hex characters) for `AISS-2.1` events; SHA-256 of the AISS-1
  canonical form for any other version (64 hex characters). The version is compared
  exactly: `AISS-2.10` is not `AISS-2.1`.
* **Genesis hash**: `SHA-512(b"PiQrypt-AISS-2.1-genesis\x00" || agent_id)`, or the hash of
  the rotation event for a chained rotation.
* **Chains**: signatures, linkage, non-decreasing timestamps, no fork, unique nonces,
  `agent_id` of every event equal to the identity's, and anti-downgrade (native identity:
  AISS-2.1 events only; upgraded identity: no AISS-1 or AISS-2.0 event after the first
  AISS-2.1 event).
* **Identities**: native (`public_key_classical` + `public_key_pq`, assurance `hybrid`) or
  upgraded (`public_key` + `public_key_pq` + `binding`, assurance `classical_only`,
  `agent_id` unchanged). A document carrying `public_key_classical` together with
  `binding` or `public_key` is ambiguous and rejected.

## Generation

```
python scripts/gen_aiss21_vectors.py            # rewrites test_vectors_aiss21/
python scripts/gen_aiss21_vectors.py --out DIR  # writes elsewhere
```

The generator is fully deterministic: fixed seeds, explicit nonces and timestamps, Ed25519
(RFC 8032, deterministic) and ML-DSA-65 with `deterministic=True`. Two runs give identical
files. It imports nothing from `aiss`; it needs `rfc8785`, `base58`, `cryptography` and
`dilithium-py`.

Production signing is hedged (randomized) for ML-DSA-65, so a production signature will
never equal one of these byte for byte. Verification is identical.

## Replaying

* With the reference library: `pytest tests/test_vectors_aiss21.py` regenerates the files
  into a temporary directory, compares them with the committed ones and checks the
  library's verdict on every vector.
* With the independent verifier: `python test_vectors_aiss21/verify_standalone.py`
  prints one verdict per vector and exits non-zero on any mismatch with `"valid"`.
  `pytest tests/test_verify_standalone.py` also checks that its verdicts equal the
  library's on every vector.
* In your own implementation: load each file, apply the rules above to each vector and
  compare your verdict with `"valid"`. Vector shapes: see the `description` of each file.

When comparing files byte for byte, normalize line endings: a checkout with
`core.autocrlf=true` converts the LF files to CRLF.

## Independent verifier

`verify_standalone.py` imports nothing from `aiss` or `piqrypt` and re-implements the rules
above from this document. It guards against the implementation defining the specification:
any difference between its verdicts and the library's on a vector is a defect to be
investigated, not smoothed over. Its independence is in the code, not in the authorship: it
was written in the same project as the library and the generator.

## Limits

* The specification is not written yet; these vectors are not a substitute for it.
* AISS-1 events in the mixed chains use ASCII payloads and integers only; AISS-1
  canonicalization differs from JCS for non-BMP key ordering and some numbers, which these
  vectors do not exercise.
* Floating-point formatting follows the `rfc8785` package; no vector covers the full
  RFC 8785 number test suite.
* No RFC 3161 token is verified; `trusted_timestamp` is only checked to be excluded from
  signatures and hashes.
* Negative vectors cover the rules listed above, not every possible malformed document.
* The `"reason"` of a negative vector explains the rule; implementations may reject for
  an earlier rule and report a different message.
* "Concurrent rotations" is rejected by the linkage rule (the second rotation does not
  follow the first). A fork is detected between two journals, not in a linear list: a list
  in which two events share a `previous_hash` always also breaks the linkage rule.
* `verify_chain` does not require the first event to be a genesis event. A chain stripped of
  its first events is accepted by the library and by the independent verifier, provided the
  remaining events are consistent. This is a point to settle in the normative text.
