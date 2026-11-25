//! Reusable caller-side evidence collection and appraisal.
//!
//! The portable verifier remains in `confido`; application admission belongs
//! to the caller of this library.
mod cli;
mod peer;
pub use cli::run_cli;
use confido::{
    Status, VerificationContext, VerificationInput, VerifierPolicy, MAX_BODY, MAX_BUNDLE,
    MAX_METADATA,
};
pub use peer::PeerCheckedClient;
use serde_json::{json, Value};
use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn build_info() -> Value {
    json!({
        "core": confido::build_info(),
        "wrapper": {
            "version": env!("CARGO_PKG_VERSION"),
            "source_sha256": env!("CONFIDO_SOURCE_SHA256"),
            "target": env!("CONFIDO_TARGET"),
            "rustc": env!("CONFIDO_RUSTC"),
            "flags": env!("CONFIDO_BUILD_FLAGS"),
            "features": env!("CONFIDO_BUILD_FEATURES"),
            "build_profile": env!("CONFIDO_BUILD_PROFILE")
        }
    })
}

const CHALLENGE_DEADLINE: Duration = Duration::from_secs(120);
pub struct ClientConfig {
    origin: reqwest::Url,
    verifier_policy_bytes: Vec<u8>,
    verifier_policy: VerifierPolicy,
    allow_untrusted_bootstrap: bool,
}

/// A single live appraisal. Serialization of its archive does not preserve
/// the monotonic deadline or authorize a future network connection.
pub struct LiveAttempt {
    result: confido::VerificationResult,
    archive: Value,
    origin: reqwest::Url,
    deadline: tokio::time::Instant,
}

impl LiveAttempt {
    pub fn result(&self) -> &confido::VerificationResult {
        &self.result
    }

    pub fn archive(&self) -> &Value {
        &self.archive
    }

    pub fn into_result_and_archive(self) -> (confido::VerificationResult, Value) {
        (self.result, self.archive)
    }

    /// Authenticate the actual HTTPS peer with the certificate in this verified
    /// live result. Consuming the attempt prevents reuse of its challenge state.
    /// This does not authorize application traffic or bind evidence to a TLS session.
    pub async fn authenticate_peer(self) -> Result<PeerCheckedClient> {
        if self.result.status != Status::Verified
            || self.result.scope != "evidence_only"
            || self.result.bindings["certificate_bound"] != true
        {
            return Err("Evidence verification did not pass".into());
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err("Challenge deadline expired".into());
        }
        if self.archive["origin"] != self.origin.as_str()
            || self.archive["context"]["expected_nonce_base64"] != self.result.expected_nonce_base64
        {
            return Err("Live appraisal context differs from result".into());
        }
        let certificate = self.result.verified_artifacts["certificate_der_base64"]
            .as_str()
            .ok_or("Verified certificate missing")?;
        let certificate = base64::decode(certificate)?;
        let client = PeerCheckedClient::new(self.origin.clone(), &certificate)?;
        let url = self.origin.join("/tee-report")?;
        let (status, _, _) = client.request("HEAD", url.as_str(), &[], vec![]).await?;
        if status != 204 {
            return Err("Attestation endpoint unavailable on appraised HTTPS peer".into());
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err("Challenge deadline expired during peer check".into());
        }
        Ok(client)
    }
}

impl ClientConfig {
    pub fn new(
        origin: &str,
        verifier_policy_bytes: Vec<u8>,
        allow_untrusted_bootstrap: bool,
    ) -> Result<Self> {
        let origin = peer::origin_url(origin)?;
        if verifier_policy_bytes.len() > MAX_METADATA {
            return Err("Verifier policy exceeds size limit".into());
        }
        let verifier_policy: VerifierPolicy = serde_json::from_slice(&verifier_policy_bytes)?;
        verifier_policy.validate()?;
        Ok(Self {
            origin,
            verifier_policy_bytes,
            verifier_policy,
            allow_untrusted_bootstrap,
        })
    }

    pub fn origin(&self) -> &reqwest::Url {
        &self.origin
    }
}

struct ArchiveInputs {
    report: Vec<u8>,
    amd_chain: Vec<u8>,
    vcek: Vec<u8>,
    reference: Vec<u8>,
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("Missing string {field}").into())
}

fn now_unix_seconds() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn http_client(allow_untrusted_certificates: bool) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(allow_untrusted_certificates)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

async fn read_response_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            return Err("HTTP body exceeds limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_kds(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(60), async {
        for attempt in 0..3 {
            let response = client.get(url).send().await?;
            if ![429, 500, 502, 503, 504].contains(&response.status().as_u16()) || attempt == 2 {
                return read_response_body(response, MAX_METADATA).await;
            }
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| {
                    value
                        .parse::<u64>()
                        .ok()
                        .map(Duration::from_secs)
                        .or_else(|| {
                            httpdate::parse_http_date(value).ok().map(|time| {
                                time.duration_since(SystemTime::now()).unwrap_or_default()
                            })
                        })
                })
                .unwrap_or(Duration::from_secs(1 << attempt));
            if delay >= Duration::from_secs(60) {
                return Err("KDS retry exceeds deadline".into());
            }
            tokio::time::sleep(delay).await;
        }
        Err("KDS unavailable".into())
    })
    .await?
}
async fn fetch_reference(client: &reqwest::Client, policy: &VerifierPolicy) -> Result<Vec<u8>> {
    let mut request = client
        .get(format!(
            "https://api.github.com/repos/{}/contents/{}?ref={}",
            policy.reference.repository, policy.reference.path, policy.reference.commit
        ))
        .header("Accept", "application/vnd.github.raw+json")
        .header(
            "User-Agent",
            concat!("confido-caller/", env!("CARGO_PKG_VERSION")),
        );
    if let Ok(token) = env::var("CONFIDO_TRS_TOKEN") {
        request = request.bearer_auth(token);
    }
    read_response_body(request.send().await?, MAX_BODY).await
}

async fn collect_live_inputs(loaded: &ClientConfig) -> Result<(Value, tokio::time::Instant)> {
    let started = tokio::time::Instant::now();
    let bootstrap = http_client(loaded.allow_untrusted_bootstrap)?;
    let public = http_client(false)?;
    let nonce: [u8; 32] = rand::random();

    let response = bootstrap
        .post(loaded.origin.join("/tee-report")?)
        .json(&json!({"nonce":base64::encode(nonce)}))
        .send()
        .await?;
    if !response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("no-store"))
        })
    {
        return Err("Missing no-store".into());
    }
    let report = read_response_body(response, MAX_BODY).await?;

    // These report fields select the KDS certificate; the verifier checks them later.
    let requirements = confido::inspect_requirements(&report)?;
    let product = requirements
        .product
        .as_deref()
        .unwrap_or(&loaded.verifier_policy.platform.product);
    if product != loaded.verifier_policy.platform.product {
        return Err("Signed SNP processor differs from enrolled product".into());
    }
    let base = format!("https://kdsintf.amd.com/vcek/v1/{product}");
    let amd_chain = fetch_kds(&public, &format!("{base}/cert_chain")).await?;
    let vcek = fetch_kds(
        &public,
        &format!(
            "{base}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            requirements.chip_id,
            requirements.tcb[0],
            requirements.tcb[1],
            requirements.tcb[2],
            requirements.tcb[3]
        ),
    )
    .await?;
    let reference = fetch_reference(&public, &loaded.verifier_policy).await?;
    if started.elapsed() > CHALLENGE_DEADLINE {
        return Err("Challenge deadline expired".into());
    }

    Ok((
        json!({
            "schema_version": 2,
            "mode": "live_collection",
            "origin": loaded.origin.as_str(),
            "inputs": {
                "report": base64::encode(report),
                "amd_chain": base64::encode(amd_chain),
                "vcek": base64::encode(vcek),
                "reference": base64::encode(reference)
            },
            "context": {
                "expected_nonce_base64": base64::encode(nonce),
                "evaluation_unix_seconds": now_unix_seconds()?
            }
        }),
        started + CHALLENGE_DEADLINE,
    ))
}
fn archive_inputs(archive: &Value) -> Result<ArchiveInputs> {
    match archive["schema_version"].as_i64() {
        Some(1) => Ok(ArchiveInputs {
            report: serde_json::to_vec(&archive["report"])?,
            amd_chain: required_string(archive, "amd_chain_pem")?
                .as_bytes()
                .to_vec(),
            vcek: serde_json::from_value::<Vec<u8>>(archive["vcek_der"].clone())?,
            reference: required_string(archive, "reference_json")?
                .as_bytes()
                .to_vec(),
        }),
        Some(2) => {
            let inputs = &archive["inputs"];
            Ok(ArchiveInputs {
                report: base64::decode(required_string(inputs, "report")?)?,
                amd_chain: base64::decode(required_string(inputs, "amd_chain")?)?,
                vcek: base64::decode(required_string(inputs, "vcek")?)?,
                reference: base64::decode(required_string(inputs, "reference")?)?,
            })
        }
        _ => Err("Unsupported archive schema".into()),
    }
}

fn evaluate_archive(
    archive: &Value,
    policy: &[u8],
    nonce: [u8; 32],
    at: i64,
) -> Result<confido::VerificationResult> {
    let inputs = archive_inputs(archive)?;
    Ok(confido::verify(
        VerificationInput {
            report_json: &inputs.report,
            amd_chain_pem: &inputs.amd_chain,
            vcek_der: &inputs.vcek,
            reference_json: &inputs.reference,
        },
        policy,
        &VerificationContext {
            expected_nonce: nonce,
            evaluation_unix_seconds: at,
        },
    )?)
}

fn decode_nonce(encoded: &str) -> Result<[u8; 32]> {
    base64::decode(encoded)?
        .try_into()
        .map_err(|_| "Expected 32-byte nonce".into())
}

/// Collect inputs and appraise them against the caller-selected local policy.
/// A failed evidence result is returned as data, never as a peer session.
pub async fn appraise(config: &ClientConfig) -> Result<LiveAttempt> {
    let (mut archive, deadline) = collect_live_inputs(config).await?;
    let nonce = decode_nonce(required_string(
        &archive["context"],
        "expected_nonce_base64",
    )?)?;
    let evaluation_time = archive["context"]["evaluation_unix_seconds"]
        .as_i64()
        .ok_or("Missing time")?;
    let result = evaluate_archive(
        &archive,
        &config.verifier_policy_bytes,
        nonce,
        evaluation_time,
    )?;
    if tokio::time::Instant::now() >= deadline {
        return Err("Challenge deadline expired during appraisal".into());
    }
    archive["verification"] = serde_json::to_value(&result)?;
    Ok(LiveAttempt {
        result,
        archive,
        origin: config.origin.clone(),
        deadline,
    })
}

#[cfg(test)]
mod tests {
    use super::ClientConfig;

    const POLICY: &[u8] = include_bytes!("../../lib/tests/fixtures/verifier-policy-v2.json");

    #[test]
    fn client_config_requires_local_policy_and_bare_https_origin() {
        assert!(ClientConfig::new("https://example.test", POLICY.to_vec(), false).is_ok());
        for origin in [
            "http://example.test",
            "https://user@example.test",
            "https://example.test/path",
            "https://example.test/?x=1",
            "https://example.test/#fragment",
        ] {
            assert!(ClientConfig::new(origin, POLICY.to_vec(), false).is_err());
        }
        assert!(ClientConfig::new("https://example.test", b"{}".to_vec(), false).is_err());
    }
}
