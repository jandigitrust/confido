# Migrating to Confido 0.2

Confido 0.2.0 is the current JAN development target. This guide covers changes
from the original attested-client API; dated acceptance records retain the
identifiers of the artifacts actually tested.

This revision separates the portable `evidence_only` verifier from client I/O.
One SDK per runtime exposes both offline and live work. The evidence profile `azure-snp-vtpm-ima/1` and quote
transcript remain at wire version 1. Policy, result, input and archive JSON
schemas use version 2; the verifier pipeline has revision 2. See the
[schema catalog](../schemas/README.md) and [protocol contract](https://github.com/teraveri/evidence/blob/main/protocol/README.md)
for the distinct version boundaries.

## Update callers

| Earlier development API | Confido 0.2 replacement |
| --- | --- |
| `confido-atls`, `import confido` | `confido-client`, `import confido_client` |
| `confido-verifier`, `import confido_verifier` | Install `confido-client`; change the import to `confido_client`. Offline signatures and results are retained. |
| `discover_py` | Caller selects the HTTPS origin and verifier policy locally; `inspect_requirements` only provides an untrusted selector for public KDS retrieval. |
| `connect_py`, `AttestedSession`, `aTLS_connect_py` | Caller collects evidence, runs `verify`, authenticates the actual TLS peer, then makes its own admission decision. |
| `appraise_offline_py` | `verify` with archived evidence bytes and independently chosen policy, expected nonce and evaluation time. |
| `AppraisalConfig` with an origin | Separate caller-owned application policy and [verifier policy](../schemas/verifier-policy-v2.json). The cooperating demo defines its application policy in `confidential-ai-example/schemas/`. |
| `application_admitted` in the verifier result | Separate application-owned decision record. The cooperating demo defines its decision schema in `confidential-ai-example/schemas/`. |
| `timings_ms` and live/session/freshness claims in the result | Caller run metadata; the verifier reports only evidence appraisal. |

For a live run, the caller chooses an origin and locally approved verifier
policy, generates an unpredictable 32-byte challenge and sends it to
`POST /tee-report`. It supplies the exact report JSON, AMD ASK+ARK PEM, VCEK
DER, reference and policy bytes to `verify`, together with the independently
held challenge and an explicit Unix evaluation time. The Python wrapper
returns a dict; the browser SDK returns an object. The [root README](../README.md#python-api)
shows the call. Schema validation does not replace the verifier's semantic
policy and cryptographic checks.

A `verified` result does not authenticate the observed TLS connection or grant
application access. The caller owns deadlines and challenge reuse prevention.
Native clients use the single-use live attempt's `authenticate_peer()` method
before sending application credentials through the resulting scoped session.
Browser extension verification is local, but its transport and
admission behavior is separate. The [scope and limitations](../README.md#assurance-boundary)
apply to both.

## Migrate archives and result consumers

For an old schema-v1 archive, run
`confido-cli migrate-archive OLD NEW UNIX_SECONDS` to create a schema-v2
archive for **historical replay**. The adapter reserializes the legacy report
JSON: its raw-byte `report_sha256` may change, while the wire-v1 quote binding over
the parsed IMA entries does not. Replay still needs a separately selected
policy and explicit evaluation time. A saved result is never a substitute for
running the verifier and never authorizes live application access.

Result consumers should use `status`, `reason` and the ordered `checks`, not a
legacy boolean or an archived verdict. A successful revision-2 run reports
these 12 checks in order:

```text
endorsements → snp_signature → vcek_correspondence → platform_policy
→ hcl_key → quote_signature → quote_binding → quoted_pcrs → reference
→ ima_reference → boot_aggregate → pcr10
```

Input/profile parsing and certificate parsing can fail before or between those
checks; they do not add successful checks. The certificate is parsed after the
quote signature, so an unsupported CA fails at `certificate` with
`ca_certificate_unsupported`. Reported/committed TCB disagreement fails at
`vcek_correspondence` with `snp_tcb_inconsistent`. Quote-stage failures use
`quote_binding_invalid`; the stage identifies the failing dependency. IMA,
boot aggregate and PCR-10 failures use `measurement_mismatch`. No later check
passes after an earlier failure.

`quote_binding` confirms the combined nonce/certificate/IMA transcript.
`challenge_matches`, `certificate_bound` and `ima_log_bound` remain false
until it passes; `quoted_pcrs` separately authenticates the supplied PCR
banks. `verified_artifacts` may contain an authenticated vTPM key before the
certificate binds. Confirmed IMA coverage remains zero until all measurement
checks pass. The optional `coverage.pcr10_method` records an attempted
`enrolled_sha256` comparison or `template_digest_replay`; check `pcr10` for
the verdict. Render old combined `quote`/`measurements` checks as legacy, or
replay original inputs to obtain current checks.

Current development builds can add `ima_matches` to the `ima_reference` check:
one boolean per received IMA entry in collector order, after reference
authentication. A received list shorter than the reference still fails the count
check even when every received entry matches; later boot/PCR checks can also fail. Consumers
must retain the overall `status`. Older results omit this field and should
display individual entries as unverified.

Update strict result and archive validators with the current schemas before
consuming these builds; older schemas reject the new check field. Rust callers
that construct public `Check` values must add `ima_matches: None`. This is a
source compatibility change within the 0.2 development target; the evidence
wire protocol and JSON schema version remain unchanged. Rebuild the Python,
CLI and WASM consumers together. Python packages now require CPython 3.15;
the [build guide](../BUILDING.md) describes environment migration.

## Build and rollout

The Rust verifier directory is now `verifier/`; its crate name remains `confido`.
The reusable native crate in `client/` is named `confido-client`. The CLI moved
to `cli/`; build it with `--manifest-path cli/Cargo.toml` and update binary paths
to `cli/target/debug/confido-cli`. Rust library consumers must update their Cargo
dependency package from `confido-cli` to `confido-client`; the library import
remains `confido_client`. Python builds use `bindings/python/` only;
`bindings/client-python/` and the standalone verifier wheel are removed.
Browser consumers import `confido.js` from the complete SDK build directory;
the generated `_native.js` module is an internal adapter. Extension builds now
package SDK assets under `sdk/`. Rebuild rather than mixing old and new assets.

See the [SDK layout decision](sdk-layout.md) for ownership and runtime limits.

Use matched verifier, caller and application transport builds. Python
`confido_client.build_info()`, WASM `build_info()` and
`confido-cli --build-info` expose core `pipeline_revision = 2` plus source,
wrapper, toolchain, target and build-profile fingerprints. These are
diagnostic build identities, not evidence claims. The example app's runtime
manifest and the extension's `runtime-manifest.json` check packaged assets
against their sources; rebuild after changes. Safari packaging alone does not
constitute Safari runtime acceptance.

The [build guide](../BUILDING.md) covers locked builds and wheel attribution.
If invoking maturin directly for a downstream build, first run
`make -C bindings/python licenses`; the normal
`make -C bindings/python wheel` entry point does this automatically.
Production certificate provisioning, package publication and public deployment
promotion are separate operations. Current local acceptance and unresolved
limitations are recorded in the [revision plan](revision-0.2.md) and
[coverage matrix](revision/coverage.md).
