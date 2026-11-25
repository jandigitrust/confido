# Confido native client library

This crate provides the reusable caller-side `confido-client` library.
The library collects evidence, AMD endorsements and a pinned reference, then
calls the portable verifier in [`verifier/`](../verifier/). A successful live attempt can
check that the intended HTTPS peer presents the certificate bound into the
verified evidence. Neither the library nor the CLI grants application access.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | Caller configuration, bounded collection, appraisal and live attempt state. |
| [`src/peer.rs`](src/peer.rs) | Exact-certificate HTTPS peer checks and origin-scoped requests. |
| [`build.rs`](build.rs) | Stamps client build metadata and source fingerprint. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock` | Crate dependencies and the locked build graph. |

Test from the repository root with
`cargo test --locked --manifest-path client/Cargo.toml`. The separate
[`cli/`](../cli/README.md) package adapts this library to commands and file I/O.
The client API accepts an HTTPS origin and caller-selected verifier policy
bytes separately. The CLI reads the cooperating example's application policy
as an input convenience; the library does not own that application's policy
schema. The Python adapter is under
[`bindings/python/`](../bindings/python/README.md).

The live attempt is consumed by peer authentication. A saved archive can be
replayed for analysis but cannot recreate the live deadline or an authenticated
peer client. The peer client validates the certificate and hostname on each
TLS connection, rejects cross-origin requests and redirects, and sends no
application traffic until its caller explicitly invokes `request`. Certificate
matching does not bind evidence to a specific TLS session or establish
post-attestation state assurance.
