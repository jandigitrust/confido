//! Deterministic, local evidence verification. No connection or admission API.
mod crypto;
mod pcr;
mod reference;
mod result;
mod verify;
pub(crate) use evidence_core::formats;
pub use evidence_core::verify_snapshot;
pub use evidence_protocol as protocol;
pub use result::{Check, Status, VerificationError, VerificationResult};
pub use verify::*;

/// Build identity is separate from deterministic verification results.
pub fn build_info() -> serde_json::Value {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pipeline_revision": 2,
        "source_sha256": env!("CONFIDO_SOURCE_SHA256"),
        "target": env!("CONFIDO_TARGET"),
        "rustc": env!("CONFIDO_RUSTC"),
        "flags": env!("CONFIDO_BUILD_FLAGS"),
        "features": env!("CONFIDO_BUILD_FEATURES"),
        "build_profile": env!("CONFIDO_BUILD_PROFILE"),
    })
}
