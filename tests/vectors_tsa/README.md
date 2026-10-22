# Real RFC 3161 fixtures

`freetsa_events.json` holds two deterministic events (one AISS-2.1, one AISS-1) with **real**
RFC 3161 tokens obtained from the public TSA freetsa.org on 2026-10-22, and `freetsa_cacert.pem` is
the public root certificate of that TSA. Everything here is public data. No secret is involved.

* `tsa_url`: where the tokens were requested (`https://freetsa.org/tsr`).
* `captured_at`: UTC date of the capture.
* `root.file_sha256`: SHA-256 of `freetsa_cacert.pem`; `root.published_file_sha256`: the value that
  freetsa.org published for that file at capture time (they are equal). `root.der_sha256` is the
  SHA-256 fingerprint of the certificate itself.
* The tokens commit to the recomputed digest of each event: SHA-512 chain hash for the AISS-2.1
  event, SHA-256 of the canonical form for the AISS-1 event.

The tests never contact the network: requests are replayed against the stored responses, and the
nonce used at capture time is restored with a mock. `capture_fixture.py` documents how the fixtures
were produced; it is not run by the tests.

Certificates are checked at the token's genTime, so the fixtures stay valid as long as the root
(valid until 2041-03-07) is trusted. freetsa.org is not a qualified trust service provider.
