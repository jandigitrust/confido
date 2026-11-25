# Python client adapter

This package exposes the reusable Rust client library as the `confido-client`
wheel. It accepts a caller-selected HTTPS origin and verifier policy bytes,
collects and appraises evidence, and can authenticate the live HTTPS peer.
It does not choose application policy, user identity or application admission.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | Python `appraise`, live `Attempt` and scoped `Session` wrappers. |
| [`python/confido_client/__init__.py`](python/confido_client/__init__.py) | Public Python import. |
| [`python/confido_client/httpx_transport.py`](python/confido_client/httpx_transport.py) | Optional synchronous `httpx` adapter for a peer-checked session. |
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

policy = Path("verifier-policy.json").read_bytes()  # Locally chosen and pinned.
attempt = confido_client.appraise("https://example.test", policy)
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

The client wheel contains the Rust verifier. It does not depend on the separate
`confido-verifier` wheel, whose Python API remains useful for offline or
independently collected evidence.
