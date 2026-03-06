use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
    pub cosign_keyless: bool,
    pub verify_after_sign: bool,
    pub verify_certificate_identity: Option<String>,
    pub verify_certificate_oidc_issuer: Option<String>,
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
    let started = chrono::Local::now();
    let digest_entries = subject_digests(output_root, outputs)?;
    let resolved_dependencies = resolved_dependencies(output_root)?;
    let builder_dependencies = builder_dependencies();
    let byproducts = byproducts(output_root);
    let finished = chrono::Local::now();

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
                },
                "internalParameters": {},
                "resolvedDependencies": resolved_dependencies
            },
            "runDetails": {
                "builder": {
                    "id": "io.sendbuilds.builder",
                    "version": env!("CARGO_PKG_VERSION"),
                    "builderDependencies": builder_dependencies
                },
                "metadata": {
                    "invocationId": format!("sendbuilds-{}", finished.timestamp_millis()),
                    "startedOn": started.to_rfc3339(),
                    "finishedOn": finished.to_rfc3339(),
                },
                "byproducts": byproducts
            }
        }
    });

    let out = output_root.join("provenance.intoto.jsonl");
    fs::write(&out, serde_json::to_vec_pretty(&statement)?)?;

    if options.cosign {
        let image = options.container_image.as_deref().ok_or_else(|| {
            anyhow::anyhow!("cosign enabled but deploy.container_image is not set")
        })?;
        run_cosign_sign(image, options)?;
        run_cosign_attest(image, &out, options)?;
        if options.verify_after_sign {
            run_cosign_verify(image, options)?;
            run_cosign_verify_attestation(image, options)?;
        }
    }

    Ok(out)
}

pub fn sign_manifest_with_cosign(
    manifest_path: &Path,
    options: &ProvenanceOptions,
) -> Result<Option<(PathBuf, PathBuf)>> {
    if !options.cosign {
        return Ok(None);
    }
    ensure_cosign_available()?;
    let sig_path = manifest_path.with_extension("cosign.sig");
    let cert_path = manifest_path.with_extension("cosign.crt");
    let mut cmd = Command::new("cosign");
    cmd.arg("sign-blob")
        .arg("--yes")
        .arg("--output-signature")
        .arg(&sig_path)
        .arg("--output-certificate")
        .arg(&cert_path);
    apply_cosign_signing_flags(&mut cmd, options);
    let status = cmd.arg(manifest_path).status()?;
    if !status.success() {
        bail!(
            "cosign sign-blob failed for artifact manifest {}",
            manifest_path.display()
        );
    }
    Ok(Some((sig_path, cert_path)))
}

pub fn verify_manifest_with_cosign(
    manifest_path: &Path,
    sig_path: &Path,
    cert_path: Option<&Path>,
    options: &ProvenanceOptions,
) -> Result<()> {
    if !options.cosign || !options.verify_after_sign {
        return Ok(());
    }
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("verify-blob").arg("--signature").arg(sig_path);
    apply_cosign_verify_blob_flags(&mut cmd, cert_path, options)?;
    let status = cmd.arg(manifest_path).status()?;
    if !status.success() {
        bail!(
            "cosign verify-blob failed for artifact manifest {}",
            manifest_path.display()
        );
    }
    Ok(())
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

fn subject_digests(root: &Path, outputs: &[PathBuf]) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for output in outputs {
        if !output.exists() {
            continue;
        }
        let meta = fs::metadata(output)?;
        if meta.is_file() {
            out.push(file_sha256(root, output)?);
            continue;
        }
        if meta.is_dir() {
            out.push(dir_sha256(root, output)?);
        }
    }
    Ok(out)
}

fn dir_sha256(root: &Path, dir: &Path) -> Result<serde_json::Value> {
    let mut entries = Vec::new();
    collect_dir_entries_for_digest(dir, dir, &mut entries)?;
    entries.sort();
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hex::encode(hasher.finalize());
    let rel = dir
        .strip_prefix(root)
        .unwrap_or(dir)
        .to_string_lossy()
        .replace('\\', "/");
    Ok(json!({
        "name": rel,
        "digest": {
            "sha256": digest
        }
    }))
}

fn collect_dir_entries_for_digest(
    base: &Path,
    current: &Path,
    out: &mut Vec<String>,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_dir_entries_for_digest(base, &path, out)?;
        } else if ty.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let digest = sha256_file(&path)?;
            out.push(format!("{rel}:{digest}"));
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

fn resolved_dependencies(output_root: &Path) -> Result<Vec<serde_json::Value>> {
    let lockfile_names = [
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Cargo.lock",
        "poetry.lock",
        "requirements.txt",
        "Gemfile.lock",
        "composer.lock",
        "go.sum",
        "packages.lock.json",
    ];
    let files = find_files_by_name(output_root, &lockfile_names)?;
    let mut out = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(output_root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let digest = sha256_file(&file)?;
        out.push(json!({
            "uri": format!("file://{rel}"),
            "digest": { "sha256": digest }
        }));
    }
    Ok(out)
}

fn find_files_by_name(root: &Path, names: &[&str]) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let wanted = names
        .iter()
        .map(|v| v.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut out = Vec::new();
    find_files_by_name_recursive(root, root, &wanted, &mut out)?;
    out.sort();
    Ok(out)
}

fn find_files_by_name_recursive(
    _root: &Path,
    current: &Path,
    wanted: &BTreeSet<String>,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            find_files_by_name_recursive(_root, &path, wanted, out)?;
        } else if ty.is_file() {
            let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
                continue;
            };
            if wanted.contains(&name.to_ascii_lowercase()) {
                out.push(path);
            }
        }
    }
    Ok(())
}

fn builder_dependencies() -> Vec<serde_json::Value> {
    let mut out = vec![json!({
        "uri": "pkg:generic/sendbuilds",
        "digest": { "sha256": hex::encode(Sha256::digest(env!("CARGO_PKG_VERSION").as_bytes())) },
        "version": env!("CARGO_PKG_VERSION"),
    })];
    if let Some(ver) = command_version("docker", &["--version"]) {
        out.push(version_dependency("docker", &ver));
    }
    if let Some(ver) = command_version("cosign", &["version"]) {
        out.push(version_dependency("cosign", &ver));
    }
    out
}

fn version_dependency(name: &str, version: &str) -> serde_json::Value {
    json!({
        "uri": format!("pkg:generic/{name}"),
        "digest": { "sha256": hex::encode(Sha256::digest(version.as_bytes())) },
        "version": version,
    })
}

fn command_version(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Some(stdout.lines().next().unwrap_or_default().to_string());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if stderr.is_empty() {
        None
    } else {
        Some(stderr.lines().next().unwrap_or_default().to_string())
    }
}

fn byproducts(output_root: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for rel in [
        "artifact-manifest.json",
        "artifact-manifest.sig",
        "build-metrics.json",
        "security-report.json",
        "sbom.json",
        "supply-chain-metadata.json",
        "cnb/lifecycle-contract.json",
        "cnb/lifecycle-metadata.json",
    ] {
        let path = output_root.join(rel);
        if path.exists() {
            out.push(json!({
                "path": rel.replace('\\', "/")
            }));
        }
    }
    out
}

fn run_cosign_sign(image: &str, options: &ProvenanceOptions) -> Result<()> {
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("sign").arg("--yes");
    apply_cosign_signing_flags(&mut cmd, options);
    let status = cmd.arg(image).status()?;
    if !status.success() {
        bail!("cosign sign failed for image {image}");
    }
    Ok(())
}

fn run_cosign_attest(
    image: &str,
    predicate_path: &Path,
    options: &ProvenanceOptions,
) -> Result<()> {
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("attest")
        .arg("--yes")
        .arg("--predicate")
        .arg(predicate_path)
        .arg("--type")
        .arg("slsaprovenance");
    apply_cosign_signing_flags(&mut cmd, options);
    let status = cmd.arg(image).status()?;
    if !status.success() {
        bail!("cosign attest failed for image {image}");
    }
    Ok(())
}

fn run_cosign_verify(image: &str, options: &ProvenanceOptions) -> Result<()> {
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("verify");
    apply_cosign_verify_identity_or_key_flags(&mut cmd, options)?;
    let status = cmd.arg(image).status()?;
    if !status.success() {
        bail!("cosign verify failed for image {image}");
    }
    Ok(())
}

fn run_cosign_verify_attestation(image: &str, options: &ProvenanceOptions) -> Result<()> {
    ensure_cosign_available()?;
    let mut cmd = Command::new("cosign");
    cmd.arg("verify-attestation")
        .arg("--type")
        .arg("slsaprovenance");
    apply_cosign_verify_identity_or_key_flags(&mut cmd, options)?;
    let status = cmd.arg(image).status()?;
    if !status.success() {
        bail!("cosign verify-attestation failed for image {image}");
    }
    Ok(())
}

fn apply_cosign_signing_flags(cmd: &mut Command, options: &ProvenanceOptions) {
    if options.cosign_keyless {
        cmd.arg("--keyless");
    } else if let Some(k) = options.cosign_key.as_deref() {
        cmd.arg("--key").arg(k);
    } else {
        cmd.arg("--key").arg("env://COSIGN_PRIVATE_KEY");
    }
}

fn apply_cosign_verify_identity_or_key_flags(
    cmd: &mut Command,
    options: &ProvenanceOptions,
) -> Result<()> {
    if options.cosign_keyless {
        let identity = options
            .verify_certificate_identity
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cosign keyless verification requires signing.verify_certificate_identity"
                )
            })?;
        let issuer = options
            .verify_certificate_oidc_issuer
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cosign keyless verification requires signing.verify_certificate_oidc_issuer"
                )
            })?;
        cmd.arg("--certificate-identity")
            .arg(identity)
            .arg("--certificate-oidc-issuer")
            .arg(issuer);
        return Ok(());
    }

    if let Some(k) = options.cosign_key.as_deref() {
        cmd.arg("--key").arg(k);
    } else {
        cmd.arg("--key").arg("env://COSIGN_PUBLIC_KEY");
    }
    Ok(())
}

fn apply_cosign_verify_blob_flags(
    cmd: &mut Command,
    cert_path: Option<&Path>,
    options: &ProvenanceOptions,
) -> Result<()> {
    if options.cosign_keyless {
        let cert = cert_path.ok_or_else(|| {
            anyhow::anyhow!("cosign keyless blob verification requires a certificate path")
        })?;
        let identity = options
            .verify_certificate_identity
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cosign keyless verification requires signing.verify_certificate_identity"
                )
            })?;
        let issuer = options
            .verify_certificate_oidc_issuer
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "cosign keyless verification requires signing.verify_certificate_oidc_issuer"
                )
            })?;
        cmd.arg("--certificate")
            .arg(cert)
            .arg("--certificate-identity")
            .arg(identity)
            .arg("--certificate-oidc-issuer")
            .arg(issuer);
        return Ok(());
    }

    if let Some(k) = options.cosign_key.as_deref() {
        cmd.arg("--key").arg(k);
    } else {
        cmd.arg("--key").arg("env://COSIGN_PUBLIC_KEY");
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
