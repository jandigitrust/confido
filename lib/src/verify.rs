use crate::{
    crypto, formats, reference::ReferenceValues, result::Stage, Status, VerificationError,
    VerificationResult,
};
use evidence_protocol::{AttestationResponse, EvidenceEnvelope, PROFILE, WIRE_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::json;
pub const MAX_BODY: usize = 4 * 1024 * 1024;
pub const MAX_METADATA: usize = 64 * 1024;
pub const MAX_BUNDLE: usize = 16 * 1024 * 1024;
pub fn sha256(b: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, b).as_ref())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub repository: String,
    pub commit: String,
    pub path: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformPolicy {
    pub product: String,
    pub ark_sha256: String,
    pub minimum_tcb: [u8; 4],
    pub launch_measurement: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierPolicy {
    pub schema_version: u32,
    pub profile: String,
    pub platform: PlatformPolicy,
    pub reference: Reference,
}
impl VerifierPolicy {
    pub fn validate(&self) -> Result<(), String> {
        fn hex(s: &str, n: usize) -> bool {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        fn safe(s: &str) -> bool {
            !s.is_empty()
                && s != "."
                && s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        }
        if self.schema_version != 2
            || self.profile != PROFILE
            || !["Milan", "Genoa"].contains(&self.platform.product.as_str())
        {
            return Err("Unsupported verifier policy/profile".into());
        }
        if !hex(&self.platform.ark_sha256, 64)
            || !hex(&self.platform.launch_measurement, 96)
            || !hex(&self.reference.sha256, 64)
            || !hex(&self.reference.commit, 40)
            || self.reference.repository.split('/').count() != 2
            || !self.reference.repository.split('/').all(safe)
            || !self.reference.path.split('/').all(safe)
        {
            return Err("Invalid root/platform/reference enrollment".into());
        }
        Ok(())
    }
}
pub struct VerificationInput<'a> {
    pub report_json: &'a [u8],
    pub amd_chain_pem: &'a [u8],
    pub vcek_der: &'a [u8],
    pub reference_json: &'a [u8],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationContext {
    pub expected_nonce: [u8; 32],
    pub evaluation_unix_seconds: i64,
}
#[derive(Serialize)]
pub struct Requirements {
    pub trusted: bool,
    pub profile: String,
    pub product: Option<String>,
    pub chip_id: String,
    pub tcb: [u8; 4],
}
pub fn inspect_requirements(report_json: &[u8]) -> Result<Requirements, VerificationError> {
    if report_json.len() > MAX_BODY {
        return Err(VerificationError("Report exceeds limit".into()));
    }
    let response: AttestationResponse =
        serde_json::from_slice(report_json).map_err(|e| VerificationError(e.to_string()))?;
    if !response.envelope.is_supported() {
        return Err(VerificationError(
            "Unsupported report profile/version".into(),
        ));
    }
    let snp = formats::snp(&response.evidence.report).map_err(VerificationError)?;
    let product = snp.product_hint().map_err(VerificationError)?;
    Ok(Requirements {
        trusted: false,
        profile: PROFILE.into(),
        product: product.map(str::to_owned),
        chip_id: hex::encode(snp.chip),
        tcb: snp.tcb,
    })
}
pub fn verify(
    input: VerificationInput<'_>,
    policy_json: &[u8],
    context: &VerificationContext,
) -> Result<VerificationResult, VerificationError> {
    if input.report_json.len() > MAX_BODY
        || input.reference_json.len() > MAX_BODY
        || input.amd_chain_pem.len() > MAX_METADATA
        || input.vcek_der.len() > MAX_METADATA
        || policy_json.len() > MAX_METADATA
    {
        return Err(VerificationError("Input exceeds size limit".into()));
    }
    if !(0..=253402300799).contains(&context.evaluation_unix_seconds) {
        return Err(VerificationError(
            "Evaluation time outside supported range".into(),
        ));
    }
    let p: VerifierPolicy =
        serde_json::from_slice(policy_json).map_err(|e| VerificationError(e.to_string()))?;
    p.validate().map_err(VerificationError)?;
    let mut r = VerificationResult {
        schema_version: 2,
        scope: "evidence_only".into(),
        status: Status::InvalidEvidence,
        reason: "not_evaluated".into(),
        profile: PROFILE.into(),
        wire_version: WIRE_VERSION,
        evaluated_at: context.evaluation_unix_seconds,
        expected_nonce_base64: base64::encode(context.expected_nonce),
        report_sha256: sha256(input.report_json),
        policy_sha256: sha256(policy_json),
        input_sha256: json!({
            "amd_chain_pem": sha256(input.amd_chain_pem),
            "vcek_der": sha256(input.vcek_der),
            "reference_json": sha256(input.reference_json),
        }),
        reference: p.reference.clone(),
        checks: vec![],
        verified_claims: json!({}),
        verified_artifacts: json!({}),
        bindings: json!({
            "challenge_matches": false,
            "certificate_bound": false,
            "ima_log_bound": false,
        }),
        coverage: json!({
            "ima_entries": 0,
            "description": "Enrolled boot aggregate and kernel modules; no application/model/GPU coverage",
        }),
        limitations: vec![
            "Evidence only: transport peer, service identity and application admission are not evaluated".into(),
            "Challenge equality is not an independent freshness assertion".into(),
            "No TLS session binding or relay resistance claim".into(),
            "AMD revocation/security-advisory updates are not automatically checked".into(),
            "TCB floor and launch measurement are operator enrollments, not vulnerability-free certification".into(),
            "Guest collector/key custody and subsequent state changes remain assumptions".into(),
            "GPU and external inference are not appraised".into(),
        ],
    };
    verify_inner(input, &p, context, &mut r);
    Ok(r)
}
fn verify_inner(
    i: VerificationInput<'_>,
    p: &VerifierPolicy,
    c: &VerificationContext,
    r: &mut VerificationResult,
) {
    macro_rules! check {
        ($stage:expr,$status:expr,$reason:expr,$expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => {
                    r.fail($stage, $status, $reason, e.to_string());
                    return;
                }
            }
        };
    }
    for (name, data) in [
        ("report", i.report_json),
        ("amd_chain", i.amd_chain_pem),
        ("vcek", i.vcek_der),
        ("reference", i.reference_json),
    ] {
        if data.is_empty() {
            r.fail(
                Stage::Input,
                Status::IncompleteInput,
                "missing_input",
                name.into(),
            );
            return;
        }
    }
    let envelope: EvidenceEnvelope = check!(
        Stage::Profile,
        Status::InvalidEvidence,
        "malformed_evidence",
        serde_json::from_slice(i.report_json)
    );
    if !envelope.is_supported() {
        r.fail(
            Stage::Profile,
            Status::UnsupportedProfile,
            "unsupported_wire_version",
            "Unsupported report profile/version".into(),
        );
        return;
    }
    let response: AttestationResponse = check!(
        Stage::Evidence,
        Status::InvalidEvidence,
        "malformed_evidence",
        serde_json::from_slice(i.report_json)
    );
    if response.certificate.len() > MAX_METADATA
        || response.evidence.ima_measurements.len() > 16384
        || response.evidence.module_load_order.order.len() > 16384
    {
        r.fail(
            Stage::Input,
            Status::InvalidEvidence,
            "input_too_large",
            "Certificate/IMA limits exceeded".into(),
        );
        return;
    }
    let snp = check!(
        Stage::SnpReport,
        Status::InvalidEvidence,
        "malformed_hcl",
        formats::snp(&response.evidence.report)
    );
    let product_hint = check!(
        Stage::SnpReport,
        Status::UnsupportedProfile,
        "unsupported_processor",
        snp.product_hint()
    );
    if product_hint.is_some_and(|product| product != p.platform.product) {
        r.fail(
            Stage::SnpReport,
            Status::PolicyMismatch,
            "platform_product_mismatch",
            "Signed SNP processor differs from enrolled product".into(),
        );
        return;
    }
    let chain = check!(
        Stage::Endorsements,
        Status::InvalidEvidence,
        "invalid_endorsements",
        crypto::pem(i.amd_chain_pem, 2)
    );
    if sha256(&chain[1]) != p.platform.ark_sha256 {
        r.fail(
            Stage::Endorsements,
            Status::InvalidEvidence,
            "endorsement_chain_invalid",
            "AMD root differs from enrolled anchor".into(),
        );
        return;
    }
    let ask = check!(
        Stage::Endorsements,
        Status::InvalidEvidence,
        "invalid_endorsements",
        crypto::cert(&chain[0])
    );
    let ark = check!(
        Stage::Endorsements,
        Status::InvalidEvidence,
        "invalid_endorsements",
        crypto::cert(&chain[1])
    );
    let vcek = check!(
        Stage::Endorsements,
        Status::InvalidEvidence,
        "invalid_endorsements",
        crypto::cert(i.vcek_der)
    );
    check!(
        Stage::Endorsements,
        Status::InvalidEvidence,
        "endorsement_chain_invalid",
        crypto::chain(&ark, &ask, &vcek, c.evaluation_unix_seconds)
    );
    r.pass(
        Stage::Endorsements,
        "Pinned AMD ARK → ASK → VCEK chain and certificate validity verified",
    );
    check!(
        Stage::SnpSignature,
        Status::InvalidEvidence,
        "snp_signature_invalid",
        crypto::snp_signature(&snp, &vcek)
    );
    r.pass(
        Stage::SnpSignature,
        "VCEK verified the SNP report signature",
    );
    if snp.tcb != snp.committed {
        r.fail(
            Stage::VcekCorrespondence,
            Status::InvalidEvidence,
            "snp_tcb_inconsistent",
            "Reported/committed TCB mismatch".into(),
        );
        return;
    }
    check!(
        Stage::VcekCorrespondence,
        Status::InvalidEvidence,
        "endorsement_report_mismatch",
        correspondence(&snp, &vcek, &p.platform.product)
    );
    r.pass(
        Stage::VcekCorrespondence,
        "Signed SNP product, chip ID and TCB match VCEK extensions",
    );
    if snp.vmpl != 0
        || snp.policy & (1 << 19 | 1 << 18) != 0
        || hex::encode(snp.measurement) != p.platform.launch_measurement
        || snp
            .tcb
            .iter()
            .zip(p.platform.minimum_tcb)
            .any(|(a, b)| *a < b)
    {
        r.fail(
            Stage::PlatformPolicy,
            Status::PolicyMismatch,
            "platform_policy_mismatch",
            "VMPL/debug/migration/launch measurement/TCB policy mismatch".into(),
        );
        return;
    }
    r.pass(
        Stage::PlatformPolicy,
        "Enrolled launch measurement and minimum TCB; VMPL 0, debug/migration disabled",
    );
    r.verified_claims = json!({
        "platform": {
            "stage": "snp_signature",
            "product": p.platform.product,
            "reported_tcb": snp.tcb,
            "launch_measurement": hex::encode(snp.measurement),
        },
    });
    let h = check!(
        Stage::HclKey,
        Status::InvalidEvidence,
        "malformed_hcl",
        formats::hcl(&response.evidence.report)
    );
    if h.var_hash != h.snp.report_data[..32] {
        r.fail(
            Stage::HclKey,
            Status::InvalidEvidence,
            "hcl_binding_invalid",
            "HCL hash differs from SNP report_data".into(),
        );
        return;
    }
    r.pass(
        Stage::HclKey,
        "AK extracted from SNP-authenticated HCL metadata",
    );
    r.verified_artifacts["vtpm_key_sha256"] = json!(sha256(&h.spki));
    let quote = check!(
        Stage::QuoteSignature,
        Status::InvalidEvidence,
        "quote_binding_invalid",
        formats::quote_signature(&response.evidence.quote, &h.n, &h.e)
    );
    r.pass(
        Stage::QuoteSignature,
        "AK signature and TPM quote header verified",
    );
    let cert_der = check!(
        Stage::Certificate,
        Status::InvalidEvidence,
        "invalid_certificate",
        crypto::pem(&response.certificate, 1)
    )
    .remove(0);
    let cert = check!(
        Stage::Certificate,
        Status::InvalidEvidence,
        "invalid_certificate",
        crypto::cert(&cert_der)
    );
    if cert.is_ca() {
        r.fail(
            Stage::Certificate,
            Status::UnsupportedProfile,
            "ca_certificate_unsupported",
            "Expected leaf certificate".into(),
        );
        return;
    }
    check!(
        Stage::QuoteBinding,
        Status::InvalidEvidence,
        "quote_binding_invalid",
        formats::snapshot_binding(&quote, &response.evidence, &c.expected_nonce, &cert_der)
    );
    r.pass(
        Stage::QuoteBinding,
        "Signed transcript matches expected nonce, certificate DER and exact IMA entries",
    );
    r.bindings = json!({"challenge_matches":true,"certificate_bound":true,"ima_log_bound":true});
    r.verified_artifacts["certificate_der_base64"] = json!(base64::encode(&cert_der));
    r.verified_artifacts["certificate_sha256"] = json!(sha256(&cert_der));
    check!(
        Stage::QuotedPcrs,
        Status::InvalidEvidence,
        "quote_binding_invalid",
        formats::quoted_pcrs(&quote, &response.evidence.quote)
    );
    r.pass(
        Stage::QuotedPcrs,
        "Signed PCR banks, selection, positions and digest verified",
    );
    let Some(reference) = appraise_ima_reference(
        i.reference_json,
        &p.reference.sha256,
        &response.evidence.ima_measurements,
        r,
    ) else {
        return;
    };
    let algo = check!(
        Stage::BootAggregate,
        Status::PolicyMismatch,
        "measurement_mismatch",
        reference.verify_boot_aggregate(&response.evidence.quote)
    );
    r.pass(
        Stage::BootAggregate,
        "Boot aggregate matches authenticated boot PCR values",
    );
    let method = if reference.pcr10_sha256.is_some() {
        "enrolled_sha256"
    } else {
        "template_digest_replay"
    };
    r.coverage["pcr10_method"] = json!(method);
    let bank = response
        .evidence
        .quote
        .get_pcr_bank(algo)
        .expect("bank validated by boot aggregate");
    check!(
        Stage::Pcr10,
        Status::PolicyMismatch,
        "measurement_mismatch",
        reference.verify_pcr10(
            &response.evidence.module_load_order,
            algo,
            bank.pcr_values.get(10).map(Vec::as_slice).unwrap_or(&[])
        )
    );
    r.pass(Stage::Pcr10, &format!("PCR 10 verified using {method}"));
    r.coverage["ima_entries"] = json!(response.evidence.ima_measurements.len());
    r.status = Status::Verified;
    r.reason = "reference_match".into();
}
/// Authenticate reference bytes and compare the already quote-bound IMA list.
///
/// Per-entry verdicts are emitted only after the selected digest and reference
/// format have passed. A count mismatch still rejects an otherwise matching prefix.
fn appraise_ima_reference(
    reference_bytes: &[u8],
    expected_digest: &str,
    entries: &[evidence_protocol::IMALogEntry],
    result: &mut VerificationResult,
) -> Option<ReferenceValues> {
    if sha256(reference_bytes) != expected_digest {
        result.fail(
            Stage::Reference,
            Status::PolicyMismatch,
            "reference_digest_mismatch",
            "Reference bytes differ from pinned digest".into(),
        );
        return None;
    }
    let reference: ReferenceValues = match serde_json::from_slice(reference_bytes) {
        Ok(reference) => reference,
        Err(error) => {
            result.fail(
                Stage::Reference,
                Status::PolicyMismatch,
                "reference_invalid",
                error.to_string(),
            );
            return None;
        }
    };
    result.pass(
        Stage::Reference,
        "Exact reference bytes match locally selected immutable reference",
    );
    let differences = reference.compare_measurements(entries);
    let matches = reference.measurement_matches(entries);
    if differences.is_empty() {
        result.pass(
            Stage::ImaReference,
            "Exact IMA entry count, content and order match the pinned reference",
        );
    } else {
        result.fail(
            Stage::ImaReference,
            Status::PolicyMismatch,
            "measurement_mismatch",
            format!(
                "{} differences: {}",
                differences.len(),
                differences
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        );
    }
    result
        .checks
        .last_mut()
        .expect("IMA comparison recorded")
        .ima_matches = Some(matches);
    if differences.is_empty() {
        Some(reference)
    } else {
        None
    }
}

#[cfg(test)]
mod tests;

fn correspondence(
    s: &formats::Snp<'_>,
    v: &x509_parser::certificate::X509Certificate<'_>,
    expected_product: &str,
) -> Result<(), String> {
    let value = |suffix: &str| -> Result<&[u8], String> {
        let oid = format!("1.3.6.1.4.1.3704.1.{suffix}");
        let matches: Vec<_> = v
            .extensions()
            .iter()
            .filter(|e| e.oid.to_id_string() == oid)
            .collect();
        if matches.len() != 1 {
            return Err(format!("Missing/duplicate AMD extension {oid}"));
        }
        Ok(matches[0].value)
    };
    fn spl(b: &[u8]) -> Result<u8, String> {
        match b {
            [2, 1, n @ 0..=127] => Ok(*n),
            [2, 2, 0, n @ 128..=255] => Ok(*n),
            _ => Err("Invalid SPL DER integer".into()),
        }
    }
    if spl(value("1")?)? != 0 {
        return Err("Unsupported VCEK version".into());
    }
    let product = value("2")?;
    let name = product.get(2..).unwrap_or_default();
    let expected = expected_product.as_bytes();
    let revision = name.strip_prefix(expected).unwrap_or_default();
    if product.len() < 2
        || product[0] != 0x16
        || product[1] as usize != name.len()
        || !(name == expected
            || (revision.starts_with(b"-")
                && revision.len() > 1
                && revision[1..].iter().all(u8::is_ascii_alphanumeric)))
    {
        return Err("VCEK product mismatch".into());
    }
    if value("4")? != s.chip {
        return Err("VCEK chip mismatch".into());
    }
    for (oid, n) in [
        ("3.1", s.tcb[0]),
        ("3.2", s.tcb[1]),
        ("3.3", s.tcb[2]),
        ("3.8", s.tcb[3]),
        ("3.4", 0),
        ("3.5", 0),
        ("3.6", 0),
        ("3.7", 0),
    ] {
        if spl(value(oid)?)? != n {
            return Err("VCEK TCB mismatch".into());
        }
    }
    Ok(())
}
