# One SDK per runtime

Status: accepted for the 0.2 development target.

## Context

Separate Python verifier and client distributions exposed the same verifier
through two installation paths. CLI argument handling and file I/O lived in the
native client crate. Browser collection lived inside the extension, although
another browser caller would need the same protocol and retrieval constraints.

## Decision

Keep the deterministic Rust `confido` crate in `verifier/`. Keep native network
and live attempt state in `client/` (`confido-client`); move process and archive
file I/O into `cli/`. Publish one Python package, `confido-client`, from
`bindings/python/`, exporting offline verification and native live APIs.

Package one browser SDK from `bindings/wasm/`: the same verifier compiled to WASM
plus JavaScript collection. The extension owns its UI, permissions and worker
adapter. Each SDK client owns its selected origins and policy snapshot. Browser
TLS does not expose the attested certificate check available to native clients.

## Alternatives and consequences

Keeping a minimal verifier wheel would avoid native networking dependencies for
offline Python consumers, but would retain duplicate package and release surfaces.
The unified wheel deliberately accepts those dependencies. Rust consumers can
still depend on the portable verifier alone. Merging network I/O into that core
would prevent its use as a synchronous offline and WASM verifier, so the core
boundary remains separate.

Offline verification must produce the same structured result through installed
Python, CLI replay and browser WASM for identical bytes and context. Existing
parity checks exercise this boundary. A browser client's unconfigured origin
must fail before a fetch; client allowlists must not share mutable state.
The browser harness checks these constraints. Native peer authentication cannot
be reconstructed from an archive. Application identity and admission remain
outside every verifier result.

The distribution and import names, existing client wheel artifact names, wire
profile and JSON schemas are retained. Source paths and the old standalone
Python import change as described in the [migration guide](migration-0.2.md).
