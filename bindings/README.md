# Language bindings

Each runtime has one SDK containing offline verification and live collection.
Both use the portable [Confido verifier](../verifier/README.md).
Application admission stays with the application.

| Directory | Purpose |
| --- | --- |
| [`python/`](python/) | `confido-client` wheel, imported as `confido_client`; also provides native peer authentication. |
| [`wasm/`](wasm/) | WASM and JavaScript SDK, consumed by the browser extension; uses ordinary browser TLS. |

The serialized inputs and results are described in the
[schema catalog](../schemas/README.md).
