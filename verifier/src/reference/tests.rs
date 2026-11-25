use super::*;

fn record(template: &str, algo: vtpm::Algorithm) -> (ReferenceValues, ModuleLoadOrder) {
    let measurements = ["boot_aggregate", "module.ko"]
        .iter()
        .enumerate()
        .map(|(i, name)| IMALogEntry {
            name: name.to_string(),
            pcr: 10,
            template_hash: hex::encode(vec![i as u8 + 1; algo.length()]),
            ima_template: template.to_string(),
            filedata_alg: algo.to_str().to_string(),
            filedata_hash: hex::encode(vec![3; algo.length()]),
            filename_hint: name.to_string(),
        })
        .collect::<Vec<_>>();
    let order = ModuleLoadOrder {
        kernel: String::new(),
        order: measurements
            .iter()
            .map(|entry| entry.name.clone())
            .collect(),
    };
    (
        ReferenceValues {
            ima_measurements: measurements,
            pcr10_sha256: None,
        },
        order,
    )
}

#[test]
fn replays_both_templates_with_the_selected_bank() {
    // Independent vectors: H(H(zero-PCR || 0x01...) || 0x02...).
    for template in ["ima-ng", "ima-sig"] {
        for (algo, expected) in [
            (
                vtpm::Algorithm::Sha1,
                "0e88991a168f26482d5b6e381824271fdb496df9",
            ),
            (
                vtpm::Algorithm::Sha256,
                "a7f2fad943905535b10ccf63c832802ed84eaffb15e4fb6bee86a817c35eb833",
            ),
        ] {
            let (trs, order) = record(template, algo);
            let (reported_algo, digest) = trs.ima_calculate(&order, algo).unwrap();
            assert_eq!(reported_algo, algo);
            assert_eq!(hex::encode(&digest), expected);
            trs.verify_pcr10(&order, algo, &digest).unwrap();
            let mut changed = digest;
            changed[0] ^= 1;
            assert_eq!(
                trs.verify_pcr10(&order, algo, &changed),
                Err("PCR 10 mismatch")
            );
        }
    }
}

#[test]
fn detects_measurement_mutations_including_duplicates_and_order() {
    let (trs, _) = record("ima-ng", vtpm::Algorithm::Sha256);
    assert!(trs.compare_measurements(&trs.ima_measurements).is_empty());
    assert_eq!(trs.measurement_matches(&trs.ima_measurements), [true, true]);
    let mut changed = trs.ima_measurements.clone();
    changed[1].filedata_hash = "ff".repeat(32);
    assert_eq!(trs.measurement_matches(&changed), [true, false]);
    assert!(!trs.compare_measurements(&changed).is_empty());
    changed = trs.ima_measurements.clone();
    changed.reverse();
    assert_eq!(trs.measurement_matches(&changed), [false, false]);
    assert!(!trs.compare_measurements(&changed).is_empty());
    assert_eq!(trs.measurement_matches(&trs.ima_measurements[..1]), [true]);
    assert!(!trs.compare_measurements(&changed[..1]).is_empty());
    changed = trs.ima_measurements.clone();
    changed.push(changed[1].clone());
    assert_eq!(trs.measurement_matches(&changed), [true, true, false]);
    assert!(!trs.compare_measurements(&changed).is_empty());
}

#[test]
fn refuses_invalid_replay_inputs() {
    for template in ["ima-ng", "ima-sig"] {
        let (mut trs, mut order) = record(template, vtpm::Algorithm::Sha256);
        order.order.reverse();
        assert!(trs.ima_calculate(&order, vtpm::Algorithm::Sha256).is_err());
        order.order.reverse();
        for hash in ["zz".repeat(32), "01".repeat(20), String::new()] {
            trs.ima_measurements[0].template_hash = hash;
            assert!(trs.ima_calculate(&order, vtpm::Algorithm::Sha256).is_err());
        }
        trs.ima_measurements[0].template_hash = "01".repeat(32);
        trs.ima_measurements[0].pcr = 9;
        assert!(trs.ima_calculate(&order, vtpm::Algorithm::Sha256).is_err());
        trs.ima_measurements[0].pcr = 10;
        trs.ima_measurements[0].ima_template = "unsupported".into();
        assert!(trs.ima_calculate(&order, vtpm::Algorithm::Sha256).is_err());
        trs.ima_measurements[0].ima_template = if template == "ima-ng" {
            "ima-sig"
        } else {
            "ima-ng"
        }
        .into();
        assert!(trs.ima_calculate(&order, vtpm::Algorithm::Sha256).is_err());
        trs.ima_measurements.clear();
        order.order.clear();
        assert!(trs.ima_calculate(&order, vtpm::Algorithm::Sha256).is_err());
    }
}

#[test]
fn validates_pinned_sha256_pcr_and_still_checks_order() {
    let (mut trs, mut order) = record("ima-ng", vtpm::Algorithm::Sha256);
    trs.pcr10_sha256 = Some("AB".repeat(32));
    trs.verify_pcr10(&order, vtpm::Algorithm::Sha256, &[0xab; 32])
        .unwrap();
    assert!(trs
        .verify_pcr10(&order, vtpm::Algorithm::Sha1, &[0xab; 20])
        .is_err());
    assert!(trs
        .verify_pcr10(&order, vtpm::Algorithm::Sha256, &[0xab; 20])
        .is_err());
    assert!(trs
        .verify_pcr10(&order, vtpm::Algorithm::Sha256, &[0xac; 32])
        .is_err());
    order.order.reverse();
    assert!(trs
        .verify_pcr10(&order, vtpm::Algorithm::Sha256, &[0xab; 32])
        .is_err());
    order.order.reverse();
    for value in ["zz".repeat(32), "ab".repeat(31), String::new()] {
        trs.pcr10_sha256 = Some(value);
        assert!(trs
            .verify_pcr10(&order, vtpm::Algorithm::Sha256, &[0xab; 32])
            .is_err());
    }
}

#[test]
fn boot_aggregate_selects_the_bank_and_validates_its_digest() {
    for algo in [vtpm::Algorithm::Sha1, vtpm::Algorithm::Sha256] {
        let (mut trs, _) = record("ima-ng", algo);
        assert_eq!(trs.boot_aggregate_algorithm().unwrap(), algo);
        trs.ima_measurements[0].filedata_hash = "00".into();
        assert!(trs.boot_aggregate_algorithm().is_err());
        trs.ima_measurements[0].filedata_alg = "sha512".into();
        assert!(trs.boot_aggregate_algorithm().is_err());
        trs.ima_measurements.clear();
        assert!(trs.boot_aggregate_algorithm().is_err());
    }
}

#[test]
fn boot_aggregate_compares_authenticated_boot_pcrs() {
    let (mut trs, _) = record("ima-ng", vtpm::Algorithm::Sha256);
    trs.ima_measurements[0].filedata_hash =
        hex::encode(ring::digest::digest(&ring::digest::SHA256, &[0; 32 * 10]));
    let mut quote: vtpm::Quote = serde_json::from_value(serde_json::json!({
        "message":[], "signature":[], "pcr_banks":[{"algo":"Sha256","pcr_values":vec![vec![0u8;32];11]}]
    })).unwrap();
    assert_eq!(
        trs.verify_boot_aggregate(&quote).unwrap(),
        vtpm::Algorithm::Sha256
    );
    quote.pcr_banks[0].pcr_values[0][0] = 1;
    assert_eq!(
        trs.verify_boot_aggregate(&quote).unwrap_err(),
        "Boot aggregate mismatch"
    );
}
