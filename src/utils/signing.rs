use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
pub struct SignedManifest {
    pub generated_at: String,
    pub outputs: Vec<SignedEntry>,
}

#[derive(Debug, Serialize)]
pub struct SignedEntry {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct ProvenanceOptions {
    pub project_name: String,
    pub container_image: Option<String>,
    pub cosign: bool,
    pub cosign_key: Option<String>,
}

pub fn sign_outputs(
    output_root: &Path,
    outputs: &[PathBuf],
    key_env: &str,
) -> Result<(PathBuf, PathBuf)> {
    let key =
        std::env::var(key_env).with_context(|| format!("missing signing key env: {key_env}"))?;
    if key.trim().is_empty() {
        bail!("signing key env is empty: {key_env}");
    }

    let mut entries = Vec::new();
    for output in outputs {
        collect_hashes(output_root, output, &mut entries)?;
    }

    let manifest = SignedManifest {
        generated_at: chrono::Local::now().to_rfc3339(),
        outputs: entries,
    };
    let manifest_path = output_root.join("artifact-manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)?;

    let mut mac = HmacSha256::new_from_slice(key.as_bytes())?;
    mac.update(&manifest_bytes);
    let signature = hex::encode(mac.finalize().into_bytes());
    let sig_path = output_root.join("artifact-manifest.sig");
    fs::write(&sig_path, signature.as_bytes())?;

    Ok((manifest_path, sig_path))
}

pub fn write_provenance(
    output_root: &Path,
    outputs: &[PathBuf],
    options: &ProvenanceOptions,
) -> Result<PathBuf> {
    let digest_entries = outputs
        .iter()
        .filter_map(|p| file_sha256(output_root, p).ok())
        .collect::<Vec<_>>();

    let statement = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": digest_entries,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/sendbuilds/build",
                "externalParameters": {
                    "project": options.project_name,
                    "container_image": options.container_image,
                }
            },
            "runDetails": {
                "builder": {
                    "id": "io.sendbuilds.builder"
                },
                "metadata": {
                    "invocationId": format!("sendbuilds-{}", chrono::Local::now().timestamp_millis()),
                    "startedOn": chrono::Local::now().to_rfc3339(),
                    "finishedOn": chrono::Local::now().to_rfc3339(),
                }
            }
        }
    });

    let out = output_root.join("provenance.intoto.jsonl");
    fs::write(&out, serde_json::to_vec_pretty(&statement)?)?;

    if options.cosign {
        let image = options.container_image.as_deref().ok_or_else(|| {
            anyhow::anyhow!("cosign enabled but deploy.container_image is not set")
        })?;
        run_cosign_sign(image, options.cosign_key.as_deref())?;
        run_cosign_attest(image, &out, options.cosign_key.as_deref())?;
    }

    Ok(out)
}

fn collect_hashes(root: &Path, path: &Path, entries: &mut Vec<SignedEntry>) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let meta = fs::metadata(path)?;
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            collect_hashes(root, &entry.path(), entries)?;
        }
    } else if meta.is_file() {
        let data = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hex::encode(hasher.finalize());
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        entries.push(SignedEntry {
            path: rel,
            sha256: hash,
        });
    }
    Ok(())
}

fn file_sha256(root: &Path, path: &Path) -> Result<serde_json::Value> {
    if !path.exists() {
        bail!("file not found for provenance digest: {}", path.display());
    }
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hex::encode(hasher.finalize());
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    Ok(json!({
        "name": rel,
        "digest": {
            "sha256": digest
        }
    }))
}

fn run_cosign_sign(image: &str, key: Option<&str>) -> Result<()> {
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("sign").arg("--yes");
    if let Some(k) = key {
        cmd.arg("--key").arg(k);
    } else {
        cmd.arg("--key").arg("env://COSIGN_PRIVATE_KEY");
    }
    let status = cmd.arg(image).status()?;
    if !status.success() {
        bail!("cosign sign failed for image {image}");
    }
    Ok(())
}

fn run_cosign_attest(image: &str, predicate_path: &Path, key: Option<&str>) -> Result<()> {
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("attest")
        .arg("--yes")
        .arg("--predicate")
        .arg(predicate_path)
        .arg("--type")
        .arg("slsaprovenance");
    if let Some(k) = key {
        cmd.arg("--key").arg(k);
    } else {
        cmd.arg("--key").arg("env://COSIGN_PRIVATE_KEY");
    }
    let status = cmd.arg(image).status()?;
    if !status.success() {
        bail!("cosign attest failed for image {image}");
    }
    Ok(())
}

fn ensure_cosign_available() -> Result<()> {
    let available = Command::new("cosign")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available {
        bail!("cosign not available in PATH");
    }
    Ok(())
}
