# Confido documentation

Confido **0.2.0** is the current development target, not a published release.
For an external review, start with the security model, then compare its claims
with the coverage matrix and the dated acceptance records.

The local test platform is **Genoa**, an AMD EPYC processor generation. Milan
is an earlier generation with a separate platform enrollment; the
[security model](security-model.md) explains why this matters for policy selection.

| Read this | For |
| --- | --- |
| [Security model](security-model.md) | Roles, trust choices, verification steps, terminology and limits. |
| [Coverage matrix](revision/coverage.md) | Claims mapped to implementation, tests and remaining limits. |
| [Public browser acceptance](revision/acceptance-browser-live-20261125.md) | Genoa live match/mismatch and native Chromium permission grant/deny on 2026-11-25. |
| [Latest local review run](revision/acceptance-genoa-review-20261124.md) | Fresh Genoa hardware, wheels, container, replay and browser parity; source was not yet committed. |
| [Acceptance: direct endpoint](revision/acceptance-genoa-direct-20261123.md), [shared Evidence core](revision/acceptance-shared-core-genoa-20261123.md) | Dated local run records with exact source and artifact identifiers. |
| [Independent rerun](revision/rerun.md) | Reproduction steps and evidence to retain. |
| [Migration to 0.2](migration-0.2.md) | Caller API changes, archive conversion and result semantics. |
| [Revision plan](revision-0.2.md) | Current scope, component boundaries and Attestor extraction checkpoint. |
| [Reference registry stage](revision/reference-registry-stage.md) | Manual GENXT endorsement and future OIDC publication path. |
| [Acceptance: manual reference](revision/acceptance-genoa-manual-20261123.md) | Earlier publisher-path run and its limitations. |
| [Decisions 001](revision/decisions/001-bounded-profile.md), [002](revision/decisions/002-api-and-references.md), [003](revision/decisions/003-contract-and-build.md), [004](revision/decisions/004-amd-product-selection.md) | Bounded profile, API/reference boundary, endpoint, and AMD product selection. |
| [Walkthrough](revision/walkthrough.md), [roadmap](revision/roadmap.md) | Demonstration narrative and future work. |

Acceptance records describe particular sources, environments and run intervals.
The 2026-11-25 browser record covers the named public stage services; earlier
records cover isolated local runs. None establishes later deployment state or
application admission. For older caller APIs and
version boundaries, see the [migration guide](migration-0.2.md). For serialized
contracts, see the [schema catalog](../schemas/README.md); for the
quote-binding transcript, see the
[Evidence protocol README](https://github.com/teraveri/evidence/blob/main/protocol/README.md).
