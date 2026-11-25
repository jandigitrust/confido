# Language bindings

The verifier bindings call the same portable [Confido verifier](../lib/).
The separate Python client binding wraps the caller-side [client library](../client/README.md).
Application admission stays with the application.
The client wheel embeds the Rust verifier, so a live caller does not need to
install both Python distributions. The verifier wheel remains the standalone
offline and bring-your-own-evidence API.

| Directory | Purpose |
| --- | --- |
| [`python/`](python/) | PyO3 wheel published as `confido-verifier`. |
| [`wasm/`](wasm/) | `wasm-bindgen` interface packaged by the browser extension. |
| [`client-python/`](client-python/) | PyO3 wheel for live collection and peer-checked HTTPS. |

The serialized inputs and results are described in the
[schema catalog](../schemas/README.md).
