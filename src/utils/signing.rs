use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

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
