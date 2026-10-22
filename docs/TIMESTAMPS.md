# Trusted timestamps (RFC 3161)

An RFC 3161 token is a signed statement by a Time-Stamp Authority (TSA) that a digest existed at a
given time (genTime). PiQrypt can request such a token for an event and verify it later. This
document says what is timestamped, how tokens are stored, how they are verified, and what is not
verified.

Nothing here is a claim of legal value. A token from a free public TSA such as freetsa.org is not a
qualified electronic time stamp under eIDAS, and PiQrypt does not make it one.

## What is timestamped

| Event version | Digest sent to the TSA | hashAlgorithm |
|---|---|---|
| AISS-2.1 | the chain hash of the event: SHA-512 of the JCS form without `signatures` and `trusted_timestamp` (`compute_event_hash`, 64 bytes) | sha512 |
| AISS-1 and AISS-2.0 | SHA-256 of the AISS-1 canonical form of the event without `trusted_timestamp` (behaviour unchanged) | sha256 |

At verification time the expected algorithm and digest are **recomputed from the event**. They are
never read from the token or from the event's own `imprint` or `data_hash` fields.

Each request carries a random nonce. The response must echo the nonce, the digest and the
algorithm, otherwise the request fails. The nonce is kept in `trusted_timestamp` so that it can be
checked again later.

## The `trusted_timestamp` field

The field is **detached**: no signature covers it. Anyone can add, remove or edit it, so its mere
presence, its self-declared `status` and any local time prove nothing. Only a successful
verification does (below).

AISS-2.1 schema:

| Key | Meaning |
|---|---|
| `status` | `pending` (no token yet) or `granted` |
| `token` | `base64:` followed by the DER TimeStampResp returned by the TSA |
| `hash_algorithm` | `sha512` |
| `imprint` | hex of the digest that was sent (informational) |
| `nonce` | hex of the nonce that was sent |
| `authority`, `url` | the TSA that answered |

A pending event carries `{"status": "pending"}` (plus an optional `note`). The key `rfc3161_token`
is still accepted when reading older events; `token` is what the library writes. For AISS-1 and
AISS-2.0 events the previous keys remain (`timestamp`, `data_hash`, `token_size_bytes`) and
`nonce` is added. The local `timestamp` is the request time, not a proof.

## Statuses

`aiss.rfc3161.verify_tsa_token(event, trust_roots=None)` returns a dict with:

| Key | Meaning |
|---|---|
| `status` | `verified`, `structure_only`, `pending` or `invalid` |
| `verified` | `True` only when `status == "verified"` |
| `reason` | explanation |
| `gen_time` | genTime read from the token (UTC epoch seconds); unauthenticated unless `verified` |
| `tsa` | subject of the TSA certificate, when found |
| `chain` | `validated` or `not_validated` |
| `revocation` | always `not_checked` |

* `verified`: the token is a granted TimeStampResp, its imprint (algorithm and bytes) equals the
  one recomputed from the event, the nonce equals the stored one, the CMS signature is valid, the
  TSA certificate carries a critical extendedKeyUsage `timeStamping`, the chain leads to a
  certificate of the trust store, and the certificates were valid at genTime.
* `structure_only`: a well-formed token whose chain was **not** validated, because no trust root is
  configured or because `rfc3161-client` is not installed. Imprint and nonce are still checked when
  possible. It is never `verified` and never anchors anything.
* `pending`: no token was obtained yet.
* `invalid`: everything else, including an empty token, a self-declared `status`, a token for
  another event or algorithm, a different nonce, a chain that does not lead to a configured root,
  and a response the library cannot parse.

## Verification needs the optional extra

```
pip install "piqrypt[timestamp]"      # rfc3161-client >=1.0.9,<2 (Apache-2.0)
```

Without it, requesting and storing tokens still works, and verification gives at best
`structure_only`.

## Trust store

PiQrypt ships **no** root certificate. You decide which roots to trust, in this order:

1. the `trust_roots` argument: a path to a PEM file or a directory, or a list of PEM text, PEM or
   DER bytes, paths or certificates;
2. the environment variable `PIQRYPT_TSA_TRUST_ROOTS` (paths separated by `os.pathsep`);
3. the directory `~/.piqrypt/tsa_roots/` (under `PIQRYPT_HOME` when set), files `*.pem`, `*.crt`,
   `*.cer`.

Every certificate of the store is treated as a trust anchor.

Getting a root and checking it out of band:

1. Download the CA certificate from the TSA operator (freetsa.org: `https://freetsa.org/files/cacert.pem`;
   commercial TSAs publish theirs with their certification practice statement).
2. Compare its fingerprint with a value obtained **through another channel** than the download itself
   (for example the operator's printed or signed documentation, or a copy kept in your own records).
   A fingerprint read from the same web page as the file only protects against a corrupted download.
3. Two different numbers exist: the SHA-256 of the file (`sha256sum cacert.pem`) and the SHA-256
   fingerprint of the certificate (`openssl x509 -in cacert.pem -noout -fingerprint -sha256`).
   Make sure you compare the same kind.
4. Only then copy the file into the trust store.

## Effect on fork resolution

The canonical-chain selection (`aiss.fork`) counts an event as anchored **only** when a verifier
you pass in declares its token verified and returns its genTime:

```python
from aiss.rfc3161 import make_tsa_verifier
from aiss.fork import select_canonical_chain

verifier = make_tsa_verifier("/path/to/roots")      # loads the trust store once
canonical, others = select_canonical_chain(branches, tsa_verifier=verifier)
```

Without a verifier no event is anchored: the first two steps are neutral and the choice falls to the
chain length, then the hash. Step 2 uses the genTime of the token, never `trusted_timestamp.timestamp`.
The result is deterministic for the same input **and the same trust store**: two verifiers with
different roots can disagree on which events are anchored.

## Verification reports

`aiss.verify.get_verification_report(events, identity, trust_roots=None)` adds a `tsa` section that
counts the events per status: `verified`, `structure_only`, `pending`, `invalid` and `absent` (no
`trusted_timestamp` field at all), with a `details` list for every event that is not verified and
the number of trust roots used. A pending or structure-only event is never counted as anchored. The
section is informational: it never changes `valid`, and `verify_chain` does not look at timestamps.

## What is not verified

* **Revocation.** No OCSP or CRL check is made in 1.10. A token whose TSA certificate was revoked
  after issuance still verifies if the chain was valid at genTime.
* **Qualification.** Whether the TSA is a qualified trust service provider is outside the library.
* **TSA policy and accuracy.** The policy OID and the accuracy field are not interpreted.
* **Long-term validation.** No archive timestamps, no renewal of tokens whose certificates expire.
* **Time sources.** genTime is what the TSA states; PiQrypt cannot check the TSA's clock.
* **Byte-level integrity of the token.** Some regions of a CMS token are not covered by its
  signature (for example the copy of the root certificate embedded in the token, which is not used
  because the root comes from the trust store). The binding between a token and an event rests on
  the imprint and the signature, not on the token's bytes.

## Compatibility

* freetsa.org accepts sha512 (its page lists sha1, sha224, sha256, sha384 and sha512 request digests)
  and its tokens verify with `rfc3161-client` 1.0.9.
* DigiCert and Entrust both granted sha512 requests when tried on 2026-10-22, but `rfc3161-client`
  1.0.9 cannot parse their responses (non-canonical DER SET ordering in the embedded certificates).
  Their tokens verify as `invalid`, which fails closed. This is a limitation of the parser, not a
  statement about the tokens.
* Requesting a token never needs the extra; only verification does.
