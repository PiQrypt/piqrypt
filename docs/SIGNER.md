# Signer interface

Status: preparation for level 3 of the AISS RFC (hardware-backed keys). This document
describes what exists in the library today and what an implementer must provide. Nothing in
it is a claim of conformance, certification or audit, and no hardware module has been tested.

## Why

By default a private key is loaded into the memory of the process that signs. A `Signer`
separates "who signs" from "how an event is built": the caller builds the message, the signer
holds the key and returns raw signatures. An HSM, a KMS or a PKCS#11 token can then be plugged
in without the key ever entering the Python process.

## Contract

```python
from aiss.signer import Signer, HybridSigner, SignerError

class MySigner(Signer):
    @property
    def algorithm(self) -> str: ...        # "Ed25519" or "ML-DSA-65"
    def public_key(self) -> bytes: ...     # raw key: 32 bytes (Ed25519) or 1952 bytes (ML-DSA-65)
    def sign(self, message: bytes) -> bytes: ...   # raw signature: 64 or 3309 bytes
    def close(self) -> None: ...           # release the session; optional to override
```

A `Signer` is a context manager (`with signer: ...` calls `close()`).

* The private key is never exposed: no public attribute, method or `repr` returns it.
* The message `M'` is built by the caller (domain prefix, algorithm label, empty context,
  JCS of the document). The signer signs exactly the bytes it receives and builds nothing.
* `public_key()` is stable for the lifetime of the object.
* Any failure raises an exception. A signer never returns a partial, empty or wrongly sized
  signature. After `close()`, `sign()` raises.

`HybridSigner(classical, post_quantum, verify_after_sign=True)` combines an Ed25519 signer and
an ML-DSA-65 signer. `sign(message)` returns a `HybridSignature(classical, post_quantum)` or
raises `SignerError` (a subclass of `AISSError`); it never returns one signature alone. It
checks the lengths (64 and 3309 bytes) and, by default, verifies each signature with the
signer's own public key before returning it, so that a faulty HSM or remote bridge cannot cause
an unverifiable event to be emitted.

## Using a signer

```python
from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, stamp_genesis_event_aiss2_hybrid

event = stamp_event_aiss2_hybrid(None, None, agent_id, payload,
                                 previous_hash=previous_hash, signer=hybrid_signer)
```

`signer` is the last, optional parameter of `stamp_event_aiss2_hybrid` and
`stamp_genesis_event_aiss2_hybrid`. With a signer, the two private-key parameters must be
`None`. Without it, behaviour is unchanged. With the same inputs and a deterministic ML-DSA
backend, the event is byte for byte identical to the one produced from raw private keys (this is
tested).

Shipped implementations:

| Class | Module | Licence | Key storage |
|---|---|---|---|
| `InMemoryEd25519Signer`, `InMemoryMlDsa65Signer` | `aiss.signer` | MIT | `bytearray`, erased by `close()` |
| `EncryptedFileEd25519Signer`, `EncryptedFileMlDsa65Signer`, `load_hybrid_signer` | `aiss.signer_file` | Elastic-2.0 | `private.key.enc` (v1) and `private_pq.key.enc` (v2), format unchanged |

`aiss.signer_file` imports `aiss/key_store.py` and therefore carries the same Elastic-2.0 header;
`aiss.signer` and `aiss.signer_conformance` do not import it and stay MIT.

## Requirements for an HSM, KMS or PKCS#11 implementer

1. **ML-DSA-65 is pure FIPS 204 signing with an empty context.** Not the pre-hash variant, not
   a non-empty context, not "external mu". The signature must verify with
   `ML_DSA_65.verify(pk, M', sig)` (empty context). Hedged (randomized) or deterministic signing
   are both accepted; verification is identical.
2. **Ed25519 is RFC 8032 pure Ed25519** over the same `M'`.
3. **No key export.** The private key must be generated and used inside the module, marked
   non-extractable, and never returned by any method of your class.
4. **Fail closed.** On any error (timeout, session lost, PIN locked, unexpected length) raise an
   exception. Never return a default value, a truncated signature or a cached one.
5. **Stable public key** for the object's lifetime, read from the module, not recomputed from a
   secret.
6. **Close releases the session**, and signing after `close()` raises.
7. Return raw signatures: 64 bytes for Ed25519 and 3309 bytes for ML-DSA-65, as `bytes`.

## Conformance checks

```python
from aiss.signer_conformance import assert_signer_conforms, assert_hybrid_signer_conforms

assert_signer_conforms(lambda: MySigner(...))      # a factory: a fresh signer on each call
assert_hybrid_signer_conforms(lambda: HybridSigner(MyEd(...), MyPq(...)))
```

`check_signer` and `check_hybrid_signer` return the list of violations instead of asserting.
The checks cover what can be observed from outside: sizes, stable public key, signatures that
the library verifies, no public attribute named like a secret, and failing closed after
`close()`. They cannot show that a key is non-extractable or that a module behaves as it should
internally. Passing them is not a certification of the signer or of the module behind it.

## Limits

* No hardware security module, KMS or PKCS#11 token has been tested. The only "remote" signer in
  the test suite is a fake that keeps its keys in a closure.
* Level 3 of the RFC is not implemented. This is the interface and its checks, not a hardware
  integration.
* Not yet adapted to the interface (candidates for 1.11): identity bindings
  (`_create_identity_binding`, used by `upgrade_agent_identity`, which also generates the
  ML-DSA-65 key locally), hybrid rotation attestations (`create_rotation_attestation_hybrid`,
  four signatures from two key pairs) and `create_rotation_event_aiss21`, which depends on them.
  `create_agent_identity(hybrid=True)` and `upgrade_agent_identity` generate keys in the process
  by design.
* In-memory signers reduce the exposure of a key in memory but cannot remove it: Python `bytes`
  are immutable and may be copied by the interpreter, cryptographic libraries keep internal
  copies, memory is not locked and swap is not controlled.
