# Confido 0.2 revision in JAN

The 0.2 revision is integrated in JAN DIGITRUST's `main`. Its target is a
reproducible portable evidence verifier. The compatible native collector lives
in [JAN Attestor](https://github.com/jandigitrust/attestor), forked from a
shared signed checkpoint. Version 0.2.0 is a development target; it has not
been released or validated for production deployment.

## Scope and repository boundary

The active Confido tree contains the portable verifier, CLI, Python binding,
WASM worker and browser extension at 0.2.0. Attestor separately owns the native
collector and `/tee-report`. The dated validation below identifies which
pre-extraction source revisions were exercised; it does not validate the split.

The pre-extraction checkpoint is fixed by signed Confido commit
`89f2c288ca3cddeb5840f3b107b06d5568f2a81d`, following the source
checkpoint `075364083ac982be1f38945a30b615d61a475f67`; the paired
confidential-ai-example commit is `c174f34da57ca5823aa6b512c484dfd42d47d967`,
and the published Evidence dependency is
`900d420b0928c4693e1143aa33a33ab670147e3c`. Attestor starts from the
signed Confido checkpoint with shared history. Confido and Attestor have
separate active source trees, build graphs and release workflows. Their
integration passed the isolated post-split Genoa checks recorded below; public
deployment remains pending. Propose substantive verifier changes upstream to
GENXT from JAN; continue collector development in JAN. The published research
baseline remains fixed.

## Inputs and provenance

| Input | Commit | Treatment |
|---|---|---|
| Published attestation revision | `28471a04c4af23a4765c4584757685ba56245664` | Direct ancestor of `main` |
| Licensed JAN/GENXT master | `1faf101bc5595699e2ad37828cad1692a2ae7d71` | Merged with licence packaging retained |
| Local review series | `4406996`, `0c33604`, `f8a9b2f`, `e0061e0`, `1b33d6e` | Merged with original commit identities |
| Original research baseline | `2112b49ed248ac40dcdb819b63ea9739d055d138` | Published as `archive/research-baseline` |

Current packages target 0.2.0. Wire/binding v1 and policy/result/archive
schema v2 have separate compatibility rules; see the [migration guide](migration-0.2.md).

## Component boundaries

| Component | Current responsibility | Destination |
|---|---|---|
| `verifier/` | Deterministic bytes/policy/nonce/time verification | Confido, then GENXT upstream |
| `evidence-protocol` Git crate | Shared evidence wire and binding types | Teraveri Evidence repository |
| `evidence-core` Git crate | Shared bounded parsing and snapshot consistency checks | Teraveri Evidence repository |
| `bindings/python/`, `bindings/wasm/` | SDKs for offline verification and live collection | Confido |
| [JAN Attestor](https://github.com/jandigitrust/attestor) | Native SNP/vTPM/IMA collection and report endpoint | Separate repository |
| `client/` | Evidence retrieval, offline verification and replay | Confido caller |
| `extension/` | Browser caller with local WASM verification | Confido consumer |

The native chat transport belongs to `confidential-ai-example`. New integration
results must identify the actual revisions used; historical cross-repository
reports are not current acceptance evidence.

The collector and verifier use two Git crates pinned to one published Evidence
commit; no sibling checkout is required. The collector does not depend on the
full Confido verifier. The wire/binding contract tests remain with Evidence and
its consumers.

Docker inventory and dmesg are absent from the Attestor collector path and are
not authenticated evidence in the supported profile. Any later Attestor
diagnostic support needs an explicit access policy and a separate claim boundary.

## Acceptance criteria

- Current core and wrapper versions agree; locked builds succeed.
- Core and WASM normal dependency graphs contain no TPM, network or TLS runtime.
- Native core checks cover signature/binding/PCR/reference rejection cases.
- Installed Python, CLI and browser callers return consistent evidence results.
- Collector tests cover bounded input, certificate configuration and safe launcher
  behavior using isolated resources.
- Binary packages retain Apache licensing and dependency attribution.
- Hardware replay/live acceptance and downstream transport integration are
  recorded separately from unit tests. Unavailable checks remain explicit.
- The split retains the shared signed checkpoint and independent repository tests.

## Dated validation

The pre-extraction local baseline is Confido
`402f252bf4a49da83c9bc91eaa12d6eb3a6c37fa` and
`confidential-ai-example` `54813aca0047d780177eac5930223b030fd0d318`
on kernel `6.8.0-1071-azure-fde`. The
[direct-endpoint acceptance](revision/acceptance-genoa-direct-20261123.md)
pins the source, policies, binaries, wheels and run artifacts; the earlier
[manual-reference acceptance](revision/acceptance-genoa-manual-20261123.md)
records the initial publisher path. These records validate their pinned
revisions, not later edits in this working tree.

The [shared evidence core acceptance](revision/acceptance-shared-core-genoa-20261123.md)
records a later isolated Genoa match/mismatch and 27-case replay after the
collector stopped depending on the full verifier. It validates the installed
wheel path, but does not repeat the earlier container or browser runs.

At that baseline, locked native and Python tests, dependency guards, CLI/Python
and Chromium/Firefox parity, native transport, and downstream application
tests passed. The live Genoa match passed all 12 verifier checks; the mismatched
reference was rejected before application traffic. The rebuilt local
container passed the same positive/negative route. The 27-case archive replay
and local timing are recorded in the direct-endpoint acceptance. The
[coverage matrix](revision/coverage.md) maps each claim to its test and limit.

The [latest local review run](revision/acceptance-genoa-review-20261124.md)
repeated live Genoa match/mismatch against the published Evidence pin with
rebuilt 0.2.0 wheels and container. It also repeated the 27-case hardware
replay and seven-case CLI/Python/Chromium/Firefox parity. The source trees
still had uncommitted edits, so this is an artifact-identified local result,
not yet a signed, clean release checkpoint.

The [post-split Genoa run](revision/acceptance-post-split-genoa-20261124.md)
then checked separate, signed Confido and Attestor commits with the client-only
example and freshly rebuilt installed wheels. Match/mismatch, hostname and
origin rejection, and credential withholding passed on isolated listeners.
Container and browser acceptance were not repeated after the split.

The isolated run used a synthetic downstream responder. Its 45 IMA entries
cover a boot aggregate and 44 kernel modules, not application, model or GPU
state. Public deployment, external inference, Safari runtime and independent
reproduction remain untested. The manual GENXT stage endorsement is pinned;
the automated Actions OIDC path remains pending. See the
[reference registry record](revision/reference-registry-stage.md) and
[independent rerun checklist](revision/rerun.md).

The signed checkpoint records the reviewed source and the Linux attribution
archives. RPM creation and independent acceptance still require their own
checks before publication. Attestor retains shared history from this checkpoint;
a release tag and package publication are separate steps. The dated
acceptance records identify the source fingerprints used in those runs and do
not certify later executable edits.

## Later execution trust work

Veraison, CoCo/Trustee and Keylime integration follows a defined evidence/result
contract with explicit trust boundaries. Formal execution contexts, capability
issuance/enforcement, invalidation and restoration belong to subsequent 0.x work.
The 1.0 milestone requires a stable execution-trust contract and a tested lifecycle
for declared profiles, including machine-enforced processing constraints within
the controlled system. The present verifier returns `evidence_only`.
