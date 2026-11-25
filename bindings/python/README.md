# Python SDK

This package exposes the reusable Rust client library as the `confido-client`
wheel with offline `verify` and `inspect_requirements` functions. For live work
it accepts a caller-selected HTTPS origin and verifier policy bytes,
collects and appraises evidence, and can authenticate the live HTTPS peer.
It does not choose application policy, user identity or application admission.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | Python `appraise`, live `Attempt` and scoped `Session` wrappers. |
| [`src/verifier.rs`](src/verifier.rs) | Offline verification and untrusted requirement inspection. |
| [`python/confido_client/__init__.py`](python/confido_client/__init__.py) | Public Python import. |
| [`python/confido_client/httpx_transport.py`](python/confido_client/httpx_transport.py) | Optional synchronous `httpx` adapter for a peer-checked session. |
| [`python/confido_client/console.py`](python/confido_client/console.py) | Explicit terminal rendering of verification checks, IMA comparisons and caller events. |
| [`Cargo.toml`](Cargo.toml), [`pyproject.toml`](pyproject.toml) | Native and wheel dependencies. |
| [`Makefile`](Makefile) | Prepares attribution and builds the wheel. |

`Attempt.result` is an evidence-only verifier result. `Attempt.archive`
contains caller-held raw inputs and should be saved privately if needed.
`Attempt.authenticate_peer()` consumes the attempt and returns a `Session`
only after a fresh peer check. The caller separately decides whether to send
application credentials or requests through that session. A saved archive
cannot be loaded as a live attempt.

```python
from pathlib import Path

import confido_client
from confido_client import console

policy = Path("verifier-policy.json").read_bytes()  # Locally chosen and pinned.
attempt = confido_client.appraise("https://example.test", policy)
console.print_verification(attempt)  # Optional output; does not consume the attempt.
result = attempt.result
if result["status"] != "verified":
    raise RuntimeError("Evidence rejected")

session = attempt.authenticate_peer()
# Application policy determines whether to send a request or credential.
# session.request("GET", "https://example.test/v1/models", [], b"")
```

Applications that use `httpx` can install `confido-client[httpx]` and pass
`ScopedTransport(session)` from `confido_client.httpx_transport` to an
`httpx.Client`. The adapter forwards bytes and headers unchanged; the native
session enforces the checked origin and rejects redirects. The application
still decides whether a user is authenticated and which credentials to send.

For independently collected evidence, use `confido_client.verify(...)` with
the [explicit evidence and context inputs](../../README.md#python-api).
Invalid offline inputs raise `ValueError`; evidence rejection returns a
structured result. Live collection and session failures raise `RuntimeError`.
The wheel contains both the Rust verifier and client. The former standalone
`confido-verifier` distribution is retired; change its import to `confido_client`.

`console.print_verification(attempt)` reads the result and the archived report;
applications do not need to decode evidence for display. The renderer preserves
the verifier's check order and evaluation time. Received IMA entries are labeled
`MATCH`/`MISMATCH` only from the native `ima_reference.ima_matches` values after
the reference stage passes; absent details, including older results, display
`UNVERIFIED`. No reference comparison is performed by Python presentation code.
Printing does not authenticate the TLS peer or decide application admission.

Use `console.log(message)` for a real caller event with the current timestamp;
completed verification checks do not acquire fabricated timestamps. Terminal
control characters in evidence are escaped. `CONFIDO_COLOR=always|auto|never`
controls ANSI output, with `NO_COLOR` respected in automatic mode. Importing the
module and appraising evidence do not print automatically.
