use anyhow::{Context, Result};
use chrono::Local;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Builder;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

#[derive(Debug, Clone)]
pub struct PublishResult {
    pub root: PathBuf,
    pub outputs: Vec<PathBuf>,
    pub warnings: Vec<String>,
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
    targets: &[String],
    container_image: Option<&str>,
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
            other => warnings.push(format!("unknown output target: {other}")),
        }
    }

    Ok(PublishResult {
        root,
        outputs,
        warnings,
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

fn zip_dir(base: &Path, current: &Path, zip: &mut ZipWriter<fs::File>, options: SimpleFileOptions) -> Result<()> {
    for entry in fs::read_dir(current).with_context(|| format!("cant read {}", current.display()))? {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let ty = entry.file_type()?;
        if ty.is_dir() {
            let dir_name = if rel.ends_with('/') { rel.clone() } else { format!("{rel}/") };
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
