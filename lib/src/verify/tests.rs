//! Reference-stage verdicts and their serialized presentation contract.

use super::*;
use evidence_protocol::IMALogEntry;

fn inputs() -> (Vec<u8>, Vec<IMALogEntry>, VerificationResult) {
    let entries: Vec<IMALogEntry> = serde_json::from_value(json!([
        {
            "name": "boot_aggregate", "PCR": 10, "ima_template": "ima-ng",
            "template_hash": "11".repeat(32), "filedata_alg": "sha256",
            "filedata_hash": "22".repeat(32), "filename_hint": "boot_aggregate"
        },
        {
            "name": "module.ko", "PCR": 10, "ima_template": "ima-ng",
            "template_hash": "33".repeat(32), "filedata_alg": "sha256",
            "filedata_hash": "44".repeat(32), "filename_hint": "module.ko"
        }
    ]))
    .unwrap();
    let reference = serde_json::to_vec(&json!({"ima_measurements": entries})).unwrap();
    let mut result = verify(
        VerificationInput {
            report_json: b"",
            amd_chain_pem: b"",
            vcek_der: b"",
            reference_json: b"",
        },
        include_bytes!("../../tests/fixtures/verifier-policy-v2.json"),
        &VerificationContext {
            expected_nonce: [0; 32],
            evaluation_unix_seconds: 1750000000,
        },
    )
    .unwrap();
    // Exercise the reference component without fabricating signed evidence.
    result.checks.clear();
    (reference, entries, result)
}

#[test]
fn unauthenticated_or_malformed_reference_never_emits_entry_verdicts() {
    let (reference, entries, mut result) = inputs();
    assert!(appraise_ima_reference(&reference, &"00".repeat(32), &entries, &mut result).is_none());
    assert_eq!(result.reason, "reference_digest_mismatch");
    assert_eq!(result.checks.len(), 1);
    assert!(result.checks[0].ima_matches.is_none());

    result.checks.clear();
    assert!(appraise_ima_reference(b"{}", &sha256(b"{}"), &entries, &mut result).is_none());
    assert_eq!(result.reason, "reference_invalid");
    assert_eq!(result.checks.len(), 1);
    assert!(result.checks[0].ima_matches.is_none());
}

#[test]
fn authenticated_reference_emits_matches_on_only_the_comparison_check() {
    let (reference, entries, mut result) = inputs();
    assert!(
        appraise_ima_reference(&reference, &sha256(&reference), &entries, &mut result).is_some()
    );
    assert_eq!(result.checks.len(), 2);
    assert_eq!(result.checks[0].stage, "reference");
    assert!(result.checks[0].ima_matches.is_none());
    let comparison = &result.checks[1];
    assert_eq!(comparison.stage, "ima_reference");
    assert_eq!(comparison.status, "passed");
    assert_eq!(comparison.ima_matches, Some(vec![true, true]));
    let serialized = serde_json::to_value(&result.checks).unwrap();
    assert!(serialized[0].get("ima_matches").is_none());
    assert_eq!(serialized[1]["ima_matches"], json!([true, true]));

    let old_check =
        json!({"stage": "ima_reference", "status": "passed", "reason": "ok", "detail": "legacy"});
    let decoded: crate::Check = serde_json::from_value(old_check.clone()).unwrap();
    assert!(decoded.ima_matches.is_none());
    assert_eq!(serde_json::to_value(decoded).unwrap(), old_check);
}

#[test]
fn comparison_reports_each_received_entry_but_rejects_a_missing_suffix() {
    let (reference, entries, _) = inputs();
    let mut changed = entries.clone();
    changed[1].filedata_hash = "55".repeat(32);
    let mut reordered = entries.clone();
    reordered.reverse();
    let mut extra = entries.clone();
    extra.push(entries[1].clone());
    for (observed, expected) in [
        (changed, vec![true, false]),
        (reordered, vec![false, false]),
        (extra, vec![true, true, false]),
        (entries[..1].to_vec(), vec![true]),
    ] {
        let (_, _, mut result) = inputs();
        assert!(
            appraise_ima_reference(&reference, &sha256(&reference), &observed, &mut result)
                .is_none()
        );
        assert_eq!(result.status, Status::PolicyMismatch);
        assert_eq!(result.reason, "measurement_mismatch");
        assert_eq!(result.checks[1].status, "failed");
        assert_eq!(result.checks[1].ima_matches, Some(expected));
    }
}
