use crate::core::config::{GarbageCollectionConfig, KubernetesConfig};
use anyhow::{Context, Result};
use chrono::Local;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};
use tar::Builder;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[derive(Debug, Clone)]
pub struct PublishResult {
    pub root: PathBuf,
    pub outputs: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GarbageCollectResult {
    pub removed_dirs: usize,
    pub kept_dirs: usize,
}

pub fn make_workdir(project: &str) -> Result<PathBuf> {
    let stamp = Local::now().format("%Y%m%d_%H%M%S%3f");
    let dir = std::env::temp_dir()
        .join("sendbuild")
        .join(format!("{project}_{stamp}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn copy_workspace(src: &Path, dst: &Path) -> Result<()> {
    copy_workspace_recursive(src, dst)
}

pub fn publish(
    src: &Path,
    base_dir: &Path,
    project_name: &str,
    targets: &[String],
    container_image: Option<&str>,
    kubernetes: Option<&KubernetesConfig>,
) -> Result<PublishResult> {
    let stamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let root = base_dir.join(stamp);
    fs::create_dir_all(&root)?;

    let selected = if targets.is_empty() {
        vec!["directory".to_string()]
    } else {
        targets.to_vec()
    };

    let mut outputs = Vec::new();
    let mut warnings = Vec::new();

    for target in selected {
        match target.as_str() {
            "directory" | "static_site" | "static" => {
                let out = root.join("directory");
                fs::create_dir_all(&out)?;
                copy_recursive(src, &out)?;
                outputs.push(out);
            }
            "tarball" => {
                let out = root.join("artifact.tar.gz");
                create_tarball(src, &out)?;
                outputs.push(out);
            }
            "serverless" | "serverless_zip" | "serverless_function" | "zip" => {
                let out = root.join("serverless.zip");
                create_zip(src, &out)?;
                outputs.push(out);
            }
            "container" | "container_image" => {
                let image = container_image.unwrap_or("sendbuild:latest");
                match build_container_image(src, image) {
                    Ok(()) => outputs.push(root.join(format!("container-image-{image}.txt"))),
                    Err(err) => warnings.push(format!("container image build skipped: {err}")),
                }
            }
            "kubernetes" | "k8s" | "kubernetes_deployment" => {
                let image = container_image.unwrap_or("sendbuild:latest");
                let out = create_kubernetes_manifests(&root, project_name, image, kubernetes)?;
                outputs.push(out);
            }
            other => warnings.push(format!("unknown output target: {other}")),
        }
    }

    Ok(PublishResult {
        root,
        outputs,
        warnings,
    })
}

pub fn garbage_collect_artifacts(
    base_dir: &Path,
    current_root: &Path,
    settings: Option<&GarbageCollectionConfig>,
) -> Result<GarbageCollectResult> {
    let enabled = settings.and_then(|g| g.enabled).unwrap_or(false);
    if !enabled || !base_dir.exists() {
        return Ok(GarbageCollectResult::default());
    }

    let keep_last = settings.and_then(|g| g.keep_last).unwrap_or(5);
    let max_age_days = settings.and_then(|g| g.max_age_days);
    let now = SystemTime::now();

    let mut dirs = Vec::new();
    for entry in fs::read_dir(base_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let path = entry.path();
            if path != current_root {
                let modified = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                dirs.push((path, modified));
            }
        }
    }

    dirs.sort_by(|a, b| b.1.cmp(&a.1));

    let mut removed_dirs = 0usize;
    let mut kept_dirs = 0usize;

    for (idx, (path, modified)) in dirs.iter().enumerate() {
        let stale = max_age_days
            .and_then(|days| {
                now.duration_since(*modified)
                    .ok()
                    .map(|d| d > Duration::from_secs(days * 86_400))
            })
            .unwrap_or(false);
        let over_limit = idx >= keep_last;
        if stale || over_limit {
            fs::remove_dir_all(path).with_context(|| {
                format!("failed to remove old artifact directory {}", path.display())
            })?;
            removed_dirs += 1;
        } else {
            kept_dirs += 1;
        }
    }

    Ok(GarbageCollectResult {
        removed_dirs,
        kept_dirs,
    })
}

fn create_tarball(src: &Path, out: &Path) -> Result<()> {
    let file = fs::File::create(out)?;
    let gz = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(gz);
    tar.append_dir_all(".", src)?;
    tar.finish()?;
    Ok(())
}

fn create_zip(src: &Path, out: &Path) -> Result<()> {
    let file = fs::File::create(out)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip_dir(src, src, &mut zip, options)?;
    zip.finish()?;
    Ok(())
}

fn zip_dir(
    base: &Path,
    current: &Path,
    zip: &mut ZipWriter<fs::File>,
    options: SimpleFileOptions,
) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("cant read {}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let ty = entry.file_type()?;
        if ty.is_dir() {
            let dir_name = if rel.ends_with('/') {
                rel.clone()
            } else {
                format!("{rel}/")
            };
            zip.add_directory(dir_name, options)?;
            zip_dir(base, &path, zip, options)?;
        } else if ty.is_file() {
            zip.start_file(rel, options)?;
            let data = fs::read(path)?;
            zip.write_all(&data)?;
        }
    }
    Ok(())
}

fn build_container_image(src: &Path, image: &str) -> Result<()> {
    let docker_available = Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !docker_available {
        anyhow::bail!("docker not available");
    }

    let status = Command::new("docker")
        .args(["build", "-t", image, "."])
        .current_dir(src)
        .status()?;
    if !status.success() {
        anyhow::bail!("docker build failed");
    }
    Ok(())
}

fn create_kubernetes_manifests(
    root: &Path,
    project_name: &str,
    container_image: &str,
    kubernetes: Option<&KubernetesConfig>,
) -> Result<PathBuf> {
    let enabled = kubernetes.and_then(|k| k.enabled).unwrap_or(true);
    if !enabled {
        let disabled = root.join("kubernetes-disabled.txt");
        fs::write(
            &disabled,
            "kubernetes manifest generation disabled by config\n",
        )?;
        return Ok(disabled);
    }

    let name = sanitize_k8s_name(project_name);
    let namespace = kubernetes
        .and_then(|k| k.namespace.as_deref())
        .unwrap_or("default");
    let replicas = kubernetes.and_then(|k| k.replicas).unwrap_or(1);
    let container_port = kubernetes.and_then(|k| k.container_port).unwrap_or(8080);
    let service_port = kubernetes.and_then(|k| k.service_port).unwrap_or(80);
    let image_pull_policy = kubernetes
        .and_then(|k| k.image_pull_policy.as_deref())
        .unwrap_or("IfNotPresent");

    let out_dir = root.join("kubernetes");
    fs::create_dir_all(&out_dir)?;

    let deployment = format!(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {name}\n  namespace: {namespace}\nspec:\n  replicas: {replicas}\n  selector:\n    matchLabels:\n      app: {name}\n  template:\n    metadata:\n      labels:\n        app: {name}\n    spec:\n      containers:\n        - name: {name}\n          image: {container_image}\n          imagePullPolicy: {image_pull_policy}\n          ports:\n            - containerPort: {container_port}\n"
    );

    let service = format!(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: {name}\n  namespace: {namespace}\nspec:\n  selector:\n    app: {name}\n  ports:\n    - protocol: TCP\n      port: {service_port}\n      targetPort: {container_port}\n  type: ClusterIP\n"
    );

    fs::write(out_dir.join("deployment.yaml"), deployment)?;
    fs::write(out_dir.join("service.yaml"), service)?;

    Ok(out_dir)
}

fn sanitize_k8s_name(input: &str) -> String {
    let mut out = String::new();
    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if c == '-' || c == '_' || c == ' ' || c == '.' {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "sendbuilds-app".to_string()
    } else {
        trimmed
    }
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("cant read {}", src.display()))? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());

        if ty.is_dir() {
            fs::create_dir_all(&dest_path)?;
            copy_recursive(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

fn copy_workspace_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("cant read {}", src.display()))? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().to_string();

        if ty.is_dir() && should_skip_workspace_dir(&name) {
            continue;
        }

        let dest_path = dst.join(&name);
        if ty.is_dir() {
            fs::create_dir_all(&dest_path)?;
            copy_workspace_recursive(&entry.path(), &dest_path)?;
        } else if ty.is_file() {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

fn should_skip_workspace_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".next"
            | "node_modules"
            | "target"
            | "artifacts"
            | ".sendbuild-cache"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".gradle"
            | "build"
            | ".idea"
            | ".vscode"
    )
}
