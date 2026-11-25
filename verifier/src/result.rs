use crate::Reference;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Stage {
    Input,
    Profile,
    Evidence,
    SnpReport,
    Endorsements,
    SnpSignature,
    VcekCorrespondence,
    PlatformPolicy,
    HclKey,
    Certificate,
    QuoteSignature,
    QuoteBinding,
    QuotedPcrs,
    Reference,
    ImaReference,
    BootAggregate,
    Pcr10,
}
impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Profile => "profile",
            Self::Evidence => "evidence",
            Self::SnpReport => "snp_report",
            Self::Endorsements => "endorsements",
            Self::SnpSignature => "snp_signature",
            Self::VcekCorrespondence => "vcek_correspondence",
            Self::PlatformPolicy => "platform_policy",
            Self::HclKey => "hcl_key",
            Self::Certificate => "certificate",
            Self::QuoteSignature => "quote_signature",
            Self::QuoteBinding => "quote_binding",
            Self::QuotedPcrs => "quoted_pcrs",
            Self::Reference => "reference",
            Self::ImaReference => "ima_reference",
            Self::BootAggregate => "boot_aggregate",
            Self::Pcr10 => "pcr10",
        }
    }
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Verified,
    InvalidEvidence,
    PolicyMismatch,
    UnsupportedProfile,
    IncompleteInput,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub stage: String,
    pub status: String,
    pub reason: String,
    pub detail: String,
    /// Per received IMA entry, in collector order, after reference authentication.
    /// Only `ima_reference` sets this field; count and later checks can still fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ima_matches: Option<Vec<bool>>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    pub schema_version: u32,
    pub scope: String,
    pub status: Status,
    pub reason: String,
    pub profile: String,
    pub wire_version: u32,
    pub evaluated_at: i64,
    pub expected_nonce_base64: String,
    pub report_sha256: String,
    pub policy_sha256: String,
    pub input_sha256: Value,
    pub reference: Reference,
    pub checks: Vec<Check>,
    pub verified_claims: Value,
    pub verified_artifacts: Value,
    pub bindings: Value,
    pub coverage: Value,
    pub limitations: Vec<String>,
}
#[derive(Debug)]
pub struct VerificationError(pub String);
impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for VerificationError {}
impl VerificationResult {
    pub(crate) fn pass(&mut self, stage: Stage, detail: &str) {
        self.checks.push(Check {
            stage: stage.as_str().into(),
            status: "passed".into(),
            reason: "ok".into(),
            detail: detail.into(),
            ima_matches: None,
        });
    }
    pub(crate) fn fail(&mut self, stage: Stage, status: Status, reason: &str, detail: String) {
        self.status = status;
        self.reason = reason.into();
        self.checks.push(Check {
            stage: stage.as_str().into(),
            status: "failed".into(),
            reason: reason.into(),
            detail,
            ima_matches: None,
        });
    }
}
