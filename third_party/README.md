# Preserved third-party attribution

This directory holds licence material needed to document upstream code and
resolved dependencies. It is not a vendored source tree.

| Path | Purpose |
| --- | --- |
| [`asn1-rs-impl-0.2.0/`](asn1-rs-impl-0.2.0/) | Preserved upstream licences and pinned provenance for dependency attribution. |
| [`system-configuration-0.5.1/`](system-configuration-0.5.1/) | Reviewed macOS dependency attribution for the native client wheel. |
| [`system-configuration-sys-0.5.0/`](system-configuration-sys-0.5.0/) | Reviewed macOS dependency attribution for the native client wheel. |

[`scripts/collect_licenses.py`](../scripts/collect_licenses.py) verifies the
recorded hashes when it uses supplemental licence files. The release-level
attribution and its limits are described in the
[third-party notices](../THIRD_PARTY_NOTICES.md).
