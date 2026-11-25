//! Command-line commands built on the reusable caller-side library.
use super::*;

const USAGE: &str = "Usage:
  confido-cli collect APP_POLICY NEW_ARCHIVE
  confido-cli appraise APP_POLICY NEW_ARCHIVE
  confido-cli verify VERIFIER_POLICY ARCHIVE EXPECTED_NONCE TIME
  confido-cli replay VERIFIER_POLICY ARCHIVE TIME
  confido-cli migrate-archive LEGACY_ARCHIVE NEW_ARCHIVE TIME";

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("File exceeds size limit".into());
    }
    Ok(bytes)
}

fn write_new_archive(path: &str, value: &Value) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn load_application_policy(path: &Path) -> Result<ClientConfig> {
    let application: Value = serde_json::from_slice(&read_limited(path, MAX_METADATA)?)?;
    if application["schema_version"] != 2 {
        return Err("Application policy v2 required".into());
    }

    let parent = path.parent().unwrap_or(Path::new(".")).canonicalize()?;
    let policy_path = parent
        .join(required_string(&application, "verifier_policy")?)
        .canonicalize()?;
    if !policy_path.starts_with(&parent) {
        return Err("Policy must be local".into());
    }
    let policy_bytes = read_limited(&policy_path, MAX_METADATA)?;
    ClientConfig::new(
        required_string(&application, "origin")?,
        policy_bytes,
        application["allow_untrusted_bootstrap"]
            .as_bool()
            .unwrap_or(false),
    )
}

fn migrate_legacy_archive(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err("Usage: migrate-archive LEGACY_ARCHIVE NEW_ARCHIVE TIME".into());
    }
    let old: Value = serde_json::from_slice(&read_limited(Path::new(&args[2]), MAX_BUNDLE)?)?;
    if old["schema_version"] != 1 {
        return Err("Expected legacy archive v1".into());
    }
    let nonce = required_string(&old, "nonce")?;
    decode_nonce(nonce)?;
    let evaluation_time: i64 = args[4].parse()?;

    let migrated = json!({
        "schema_version": 2,
        "mode": "historical_replay",
        "inputs": {
            "report": base64::encode(serde_json::to_vec(&old["report"])?),
            "amd_chain": base64::encode(required_string(&old, "amd_chain_pem")?),
            "vcek": base64::encode(serde_json::from_value::<Vec<u8>>(old["vcek_der"].clone())?),
            "reference": base64::encode(required_string(&old, "reference_json")?)
        },
        "context": {
            "expected_nonce_base64": nonce,
            "evaluation_unix_seconds": evaluation_time
        }
    });
    write_new_archive(&args[3], &migrated)
}

async fn run_collect(args: &[String]) -> Result<()> {
    let config = load_application_policy(Path::new(&args[2]))?;
    let (archive, _) = collect_live_inputs(&config).await?;
    write_new_archive(&args[3], &archive)
}

async fn run_appraise(args: &[String]) -> Result<confido::VerificationResult> {
    let config = load_application_policy(Path::new(&args[2]))?;
    let (result, archive) = appraise(&config).await?.into_result_and_archive();
    write_new_archive(&args[3], &archive)?;
    Ok(result)
}

fn run_archive_check(args: &[String]) -> Result<confido::VerificationResult> {
    let archive: Value = serde_json::from_slice(&read_limited(Path::new(&args[3]), MAX_BUNDLE)?)?;
    let policy = read_limited(Path::new(&args[2]), MAX_METADATA)?;

    let (nonce, evaluation_time) = if args[1] == "replay" {
        let nonce = if archive["schema_version"] == 1 {
            required_string(&archive, "nonce")?
        } else {
            required_string(&archive["context"], "expected_nonce_base64")?
        };
        (
            nonce,
            args.get(4)
                .ok_or("Explicit replay evaluation time required")?,
        )
    } else {
        (
            args.get(4).ok_or("Independent nonce required")?.as_str(),
            args.get(5).ok_or("Evaluation time required")?,
        )
    };

    evaluate_archive(
        &archive,
        &policy,
        decode_nonce(nonce)?,
        evaluation_time.parse()?,
    )
}

pub async fn run_cli(args: &[String]) -> Result<i32> {
    if args.get(1).map(String::as_str) == Some("--build-info") {
        println!("{}", build_info());
        return Ok(0);
    }

    if args.get(1).map(String::as_str) == Some("--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if args.get(1).map(String::as_str) == Some("migrate-archive") {
        migrate_legacy_archive(args)?;
        return Ok(0);
    }
    if args.len() < 4 {
        return Err(USAGE.into());
    }
    let result = match args[1].as_str() {
        "collect" => {
            run_collect(&args).await?;
            return Ok(0);
        }
        "appraise" => run_appraise(&args).await?,
        "replay" | "verify" => run_archive_check(&args)?,
        _ => return Err("Unknown command".into()),
    };

    println!("{}", serde_json::to_string_pretty(&result)?);
    if result.status != Status::Verified {
        return Ok(2);
    }
    Ok(0)
}
