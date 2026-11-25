//! Fixed pinned ARK -> ASK -> VCEK path validation for the bounded profile.
use crate::formats::Result;
use ring::signature;
use x509_parser::extensions::ParsedExtension;
use x509_parser::{prelude::*, signature_algorithm::RsaSsaPssParams};
pub(crate) fn cert(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    let (rest, c) = parse_x509_certificate(bytes).map_err(|e| e.to_string())?;
    if !rest.is_empty()
        || c.signature_value.unused_bits != 0
        || c.public_key().subject_public_key.unused_bits != 0
    {
        return Err("Invalid DER certificate/bit string".into());
    }
    Ok(c)
}
pub(crate) fn pem(bytes: &[u8], count: usize) -> Result<Vec<Vec<u8>>> {
    let mut rest = bytes;
    let mut out = vec![];
    while !rest.is_empty() {
        rest = rest.trim_ascii();
        if rest.is_empty() {
            break;
        }
        if !rest.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err("Unexpected PEM data".into());
        }
        let (r, p) = x509_parser::pem::parse_x509_pem(rest).map_err(|e| e.to_string())?;
        if p.label != "CERTIFICATE" || out.len() >= count {
            return Err("Unexpected PEM certificate count".into());
        }
        out.push(p.contents);
        rest = r;
    }
    if out.len() != count {
        return Err("Missing certificate".into());
    }
    Ok(out)
}
fn signature(c: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<()> {
    if c.signature_algorithm != c.tbs_certificate.signature {
        return Err("Certificate signature parameters disagree".into());
    }
    let oid = c.signature_algorithm.algorithm.to_id_string();
    if oid == "1.2.840.113549.1.1.10" {
        if issuer.public_key().algorithm.algorithm.to_id_string() != "1.2.840.113549.1.1.1" {
            return Err("Unsupported PSS issuer key".into());
        }
        let p = RsaSsaPssParams::try_from(
            c.signature_algorithm
                .parameters
                .as_ref()
                .ok_or("Missing PSS parameters")?,
        )
        .map_err(|e| e.to_string())?;
        let mgf = p.mask_gen_algorithm().map_err(|e| e.to_string())?;
        let hash = p.hash_algorithm_oid().to_id_string();
        if mgf.mgf.to_id_string() != "1.2.840.113549.1.1.8"
            || mgf.hash.to_id_string() != hash
            || p.trailer_field() != 1
        {
            return Err("Unsupported PSS parameters".into());
        }
        let (alg, len): (&dyn signature::VerificationAlgorithm, u32) = match hash.as_str() {
            "2.16.840.1.101.3.4.2.1" => (&signature::RSA_PSS_2048_8192_SHA256, 32),
            "2.16.840.1.101.3.4.2.2" => (&signature::RSA_PSS_2048_8192_SHA384, 48),
            "2.16.840.1.101.3.4.2.3" => (&signature::RSA_PSS_2048_8192_SHA512, 64),
            _ => return Err("Unsupported PSS hash".into()),
        };
        if p.salt_length() != len {
            return Err("Unsupported PSS salt length".into());
        }
        signature::UnparsedPublicKey::new(alg, issuer.public_key().subject_public_key.data.as_ref())
            .verify(c.tbs_certificate.as_ref(), &c.signature_value.data)
            .map_err(|_| "Certificate PSS signature invalid".into())
    } else {
        if ![
            "1.2.840.113549.1.1.11",
            "1.2.840.113549.1.1.12",
            "1.2.840.113549.1.1.13",
            "1.2.840.10045.4.3.2",
            "1.2.840.10045.4.3.3",
        ]
        .contains(&oid.as_str())
        {
            return Err("Unsupported certificate signature".into());
        }
        c.verify_signature(Some(issuer.public_key()))
            .map_err(|e| e.to_string())
    }
}
fn constraints(c: &X509Certificate<'_>, ca: bool, below: u32, at: i64) -> Result<()> {
    if c.validity().not_before.timestamp() > at || c.validity().not_after.timestamp() < at {
        return Err("Endorsement outside validity interval".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for ext in c.extensions() {
        if matches!(ext.parsed_extension(), ParsedExtension::ParseError { .. }) {
            return Err("Malformed certificate extension".into());
        }
        let oid = ext.oid.to_id_string();
        if !seen.insert(oid.clone()) {
            return Err("Duplicate certificate extension".into());
        }
        // No unimplemented path/policy constraints, including noncritical ones.
        if [
            "2.5.29.30",
            "2.5.29.32",
            "2.5.29.33",
            "2.5.29.36",
            "2.5.29.37",
            "2.5.29.54",
        ]
        .contains(&oid.as_str())
        {
            return Err("Unsupported certificate constraint".into());
        }
        if ext.critical && !["2.5.29.19", "2.5.29.15"].contains(&oid.as_str()) {
            return Err("Unsupported critical certificate extension".into());
        }
    }
    let bc = c.basic_constraints().map_err(|e| e.to_string())?;
    if bc.as_ref().is_some_and(|b| b.value.ca) != ca {
        return Err("Invalid CA constraint".into());
    }
    if ca && bc.is_none() {
        return Err("Missing CA constraint".into());
    }
    if bc.is_some_and(|b| b.value.path_len_constraint.is_some_and(|n| n < below)) {
        return Err("Path length exceeded".into());
    }
    let ku = c.key_usage().map_err(|e| e.to_string())?;
    if ca && !ku.as_ref().is_some_and(|k| k.value.key_cert_sign()) {
        return Err("Issuer lacks keyCertSign".into());
    }
    if !ca && ku.as_ref().is_some_and(|k| !k.value.digital_signature()) {
        return Err("Leaf lacks digitalSignature".into());
    }
    Ok(())
}
fn key_identifier(child: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> Result<()> {
    let ski = issuer
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => Some(&k.0),
            _ => None,
        });
    for ext in child.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
            if let (Some(wanted), Some(actual)) = (&aki.key_identifier, ski) {
                if &wanted.0 != actual {
                    return Err("Authority key identifier mismatch".into());
                }
            }
            if aki
                .authority_cert_serial
                .is_some_and(|s| s != issuer.raw_serial())
            {
                return Err("Authority certificate serial mismatch".into());
            }
            if let Some(names) = &aki.authority_cert_issuer {
                if !names.iter().any(|name| {
                    matches!(
                        name,
                        x509_parser::extensions::GeneralName::DirectoryName(value)
                            if value == issuer.issuer()
                    )
                }) {
                    return Err("Authority certificate issuer mismatch".into());
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn chain(
    ark: &X509Certificate<'_>,
    ask: &X509Certificate<'_>,
    vcek: &X509Certificate<'_>,
    at: i64,
) -> Result<()> {
    constraints(ark, true, 1, at)?;
    constraints(ask, true, 0, at)?;
    constraints(vcek, false, 0, at)?;
    if ark.issuer() != ark.subject()
        || ask.issuer() != ark.subject()
        || vcek.issuer() != ask.subject()
    {
        return Err("Certificate issuer mismatch".into());
    }
    key_identifier(ark, ark)?;
    key_identifier(ask, ark)?;
    key_identifier(vcek, ask)?;
    signature(ark, ark)?;
    signature(ask, ark)?;
    signature(vcek, ask)?;
    Ok(())
}
pub(crate) fn snp_signature(s: &crate::formats::Snp<'_>, vcek: &X509Certificate<'_>) -> Result<()> {
    let pk = vcek.public_key();
    if pk.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || pk
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|o| o.to_id_string())
            .as_deref()
            != Some("1.3.132.0.34")
    {
        return Err("VCEK is not P-384".into());
    }
    let mut sig = Vec::with_capacity(96);
    for start in [672, 744] {
        if s.raw[start + 48..start + 72].iter().any(|&b| b != 0) {
            return Err("Invalid SNP signature padding".into());
        }
        sig.extend(s.raw[start..start + 48].iter().rev());
    }
    signature::UnparsedPublicKey::new(
        &signature::ECDSA_P384_SHA384_FIXED,
        pk.subject_public_key.data.as_ref(),
    )
    .verify(&s.raw[..672], &sig)
    .map_err(|_| "SNP signature invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{
            extension::{BasicConstraints, KeyUsage},
            X509NameBuilder, X509,
        },
    };
    fn make(
        name: &str,
        key: &PKey<Private>,
        issuer: Option<(&X509, &PKey<Private>)>,
        ca: bool,
        path: u32,
    ) -> X509 {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", name).unwrap();
        let n = n.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&n).unwrap();
        b.set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&n))
            .unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&Asn1Time::from_unix(1700000000).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::from_unix(1800000000).unwrap())
            .unwrap();
        if ca {
            b.append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .pathlen(path)
                    .build()
                    .unwrap(),
            )
            .unwrap();
            b.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        } else {
            b.append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            b.append_extension(KeyUsage::new().digital_signature().build().unwrap())
                .unwrap();
        }
        b.sign(
            issuer.map(|(_, k)| k).unwrap_or(key),
            MessageDigest::sha256(),
        )
        .unwrap();
        b.build()
    }
    #[test]
    fn pinned_path_rejects_bad_signature_expiry_and_path_length() {
        let k = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let root = make("root", &k, None, true, 1);
        let ask = make("ask", &k, Some((&root, &k)), true, 0);
        let leaf = make("leaf", &leaf_key, Some((&ask, &k)), false, 0);
        let rd = root.to_der().unwrap();
        let ad = ask.to_der().unwrap();
        let ld = leaf.to_der().unwrap();
        chain(
            &cert(&rd).unwrap(),
            &cert(&ad).unwrap(),
            &cert(&ld).unwrap(),
            1750000000,
        )
        .unwrap();
        assert!(chain(
            &cert(&rd).unwrap(),
            &cert(&ad).unwrap(),
            &cert(&ld).unwrap(),
            1800000001
        )
        .is_err());
        let mut bad = ld.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(chain(
            &cert(&rd).unwrap(),
            &cert(&ad).unwrap(),
            &cert(&bad).unwrap(),
            1750000000
        )
        .is_err());
        let short = make("root", &k, None, true, 0).to_der().unwrap();
        assert!(chain(
            &cert(&short).unwrap(),
            &cert(&ad).unwrap(),
            &cert(&ld).unwrap(),
            1750000000
        )
        .is_err());
        let wrong_ca = make("ask", &k, Some((&root, &k)), false, 0)
            .to_der()
            .unwrap();
        assert!(chain(
            &cert(&rd).unwrap(),
            &cert(&wrong_ca).unwrap(),
            &cert(&ld).unwrap(),
            1750000000
        )
        .is_err());
    }

    #[test]
    fn snp_signature_covers_supported_report_versions() {
        use openssl::{
            ec::{EcGroup, EcKey},
            ecdsa::EcdsaSig,
            nid::Nid,
        };

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec.clone()).unwrap();
        // This certificate tests report signature encoding, not AMD trust.
        let cert_der = make("synthetic SNP signer", &key, None, false, 0)
            .to_der()
            .unwrap();
        let signer = cert(&cert_der).unwrap();
        let mut report = vec![0; 1236];
        report[1224..1228].copy_from_slice(&2u32.to_le_bytes());
        report[1228..1232].copy_from_slice(&1u32.to_le_bytes());
        report[32 + 52..32 + 56].copy_from_slice(&1u32.to_le_bytes());

        for version in [2u32, 3, 5] {
            report[32..36].copy_from_slice(&version.to_le_bytes());
            let sig = EcdsaSig::sign(&openssl::sha::sha384(&report[32..32 + 672]), &ec).unwrap();
            for (at, value) in [(672, sig.r()), (744, sig.s())] {
                let mut little_endian = value.to_vec_padded(48).unwrap();
                little_endian.reverse();
                report[32 + at..32 + at + 48].copy_from_slice(&little_endian);
            }
            let parsed = crate::formats::snp(&report).unwrap();
            snp_signature(&parsed, &signer).unwrap();

            // Fields through byte 671 are signed; signature fields are checked too.
            for offset in [0, 80, 144, 384, 416, 480, 504, 512, 671, 672, 744] {
                let mut changed = report.clone();
                changed[32 + offset] ^= 1;
                assert!(crate::formats::snp(&changed)
                    .and_then(|parsed| snp_signature(&parsed, &signer))
                    .is_err());
            }
        }
    }
}
