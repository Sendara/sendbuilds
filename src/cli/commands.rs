use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use getrandom::getrandom;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::config::{
    CacheConfig, DeployConfig, OutputConfig, ProjectConfig, SandboxConfig, ScanConfig,
    SecurityConfig, SigningConfig, SourceConfig,
};
use crate::core::BuildConfig;
use crate::engine::BuildEngine;

#[derive(Parser)]
#[command(name = "sendbuilds", about = "send it. build it.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Build {
        #[arg(short, long, default_value = "sendbuild.toml")]
        config: String,
        #[arg(long, value_parser = clap::builder::BoolishValueParser::new())]
        events: Option<bool>,
        #[arg(long)]
        in_place: bool,
        #[arg(long)]
        git: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        docker: bool,
        #[arg(long)]
        image: Option<String>,
    },
    Init {
        #[arg(long)]
        template: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    Cache {
        #[command(subcommand)]
        cmd: CacheCmd,
        #[arg(short, long, default_value = "sendbuild.toml")]
        config: String,
    },
    Clean {
        #[arg(short, long, default_value = "sendbuild.toml")]
        config: String,
        #[arg(long)]
        all: bool,
        #[arg(long = "cache-only")]
        cache_only: bool,
    },
    Info {
        #[arg(short, long, default_value = "sendbuild.toml")]
        config: String,
        #[arg(long)]
        env: bool,
        #[arg(long)]
        dependencies: bool,
    },
}

#[derive(Subcommand)]
enum CacheCmd {
    Save,
    Restore,
    Clear,
    Status,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            config,
            events,
            in_place,
            git,
            branch,
            docker,
            image,
        } => {
            if git.is_some() || docker {
                return run_quick_build(git, branch, docker, image, in_place, events);
            }
            if BuildConfig::exists(&config) {
                let cfg = BuildConfig::from_file(&config)?;
                prepare_signing_key(cfg.signing.as_ref())?;
                BuildEngine::from_config(cfg)
                    .with_in_place(in_place)
                    .with_events(events)
                    .run()
            } else {
                println!(
                    "No config file found at '{}'. Running smart local build mode.",
                    config
                );
                let cfg = BuildConfig::for_local_workspace()?;
                BuildEngine::from_config(cfg)
                    .with_in_place(true)
                    .with_events(events)
                    .run()
            }
        }
        Cmd::Init { template, yes } => init_project(template.as_deref(), yes),
        Cmd::Cache { cmd, config } => run_cache(cmd, &config),
        Cmd::Clean {
            config,
            all,
            cache_only,
        } => clean(&config, all, cache_only),
        Cmd::Info {
            config,
            env,
            dependencies,
        } => info(&config, env, dependencies),
    }
}

fn run_quick_build(
    git_repo: Option<String>,
    git_branch: Option<String>,
    docker: bool,
    image: Option<String>,
    in_place: bool,
    events: Option<bool>,
) -> Result<()> {
    let has_git = git_repo.is_some();
    let name = git_repo
        .as_deref()
        .map(project_name_from_repo)
        .unwrap_or_else(|| local_project_name());
    let image_tag = image.unwrap_or_else(|| format!("{name}:latest"));
    let mut targets = vec!["directory".to_string()];
    if docker {
        targets.push("container_image".to_string());
    }

    let cfg = BuildConfig {
        project: ProjectConfig {
            name: name.clone(),
            language: None,
        },
        source: git_repo.map(|repo| SourceConfig {
            repo,
            branch: git_branch,
            commit: None,
        }),
        build: None,
        deploy: DeployConfig {
            artifact_dir: "./artifacts".to_string(),
            targets: Some(targets),
            container_image: Some(image_tag),
            container_platforms: None,
            // quick builds ofc
            push_container: Some(false),
            rebase_base: None,
            kubernetes: None,
            gc: None,
        },
        output: Some(OutputConfig { events }),
        cache: Some(CacheConfig {
            enabled: Some(true),
            dir: None,
            registry_ref: None,
        }),
        scan: Some(ScanConfig {
            enabled: Some(false),
            command: None,
        }),
        security: Some(SecurityConfig {
            enabled: Some(true),
            fail_on_critical: Some(true),
            critical_threshold: Some(0),
            fail_on_scanner_unavailable: Some(true),
            generate_sbom: Some(true),
            auto_distroless: Some(true),
            distroless_base: None,
            rewrite_dockerfile_in_place: Some(false),
        }),
        env: None,
        env_from_host: None,
        sandbox: Some(SandboxConfig {
            enabled: Some(true),
            strict: Some(true),
        }),
        signing: Some(SigningConfig {
            enabled: Some(true),
            key_env: Some("SENDBUILD_SIGNING_KEY".to_string()),
            auto_generate_key: Some(true),
            key_file: Some(".sendbuild/signing.key".to_string()),
            generate_provenance: Some(true),
            cosign: Some(false),
            cosign_key: None,
            cosign_keyless: None,
            verify_after_sign: None,
            verify_certificate_identity: None,
            verify_certificate_oidc_issuer: None,
        }),
        compatibility: None,
    };

    prepare_signing_key(cfg.signing.as_ref())?;

    BuildEngine::from_config(cfg)
        .with_in_place(in_place || !has_git)
        .with_events(events)
        .run()
}

fn local_project_name() -> String {
    env::current_dir()
        .ok()
        .and_then(|cwd| {
            cwd.file_name()
                .and_then(|n| n.to_str().map(ToString::to_string))
        })
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "local-app".to_string())
}

fn project_name_from_repo(repo: &str) -> String {
    let trimmed = repo.trim_end_matches('/').trim();
    let last = trimmed.rsplit('/').next().unwrap_or("app");
    let no_git = last.strip_suffix(".git").unwrap_or(last);
    let mut out = String::new();
    for ch in no_git.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' || ch == '.' {
            out.push('-');
        }
    }
    let normalized = out.trim_matches('-').to_string();
    if normalized.is_empty() {
        "app".to_string()
    } else {
        normalized
    }
}

fn prepare_signing_key(signing: Option<&SigningConfig>) -> Result<()> {
    let Some(cfg) = signing else {
        return Ok(());
    };
    if !cfg.enabled.unwrap_or(false) {
        return Ok(());
    }

    let key_env = cfg
        .key_env
        .as_deref()
        .unwrap_or("SENDBUILD_SIGNING_KEY")
        .to_string();

    match env::var(&key_env) {
        Ok(value) => {
            validate_signing_key(&value, &key_env)?;
            return Ok(());
        }
        Err(env::VarError::NotUnicode(_)) => {
            bail!("signing key env `{key_env}` is not valid unicode")
        }
        Err(env::VarError::NotPresent) => {}
    }

    if !cfg.auto_generate_key.unwrap_or(true) {
        bail!(
            "missing required signing key env: {key_env}. set it or enable [signing].auto_generate_key = true"
        );
    }

    let key_file = cfg
        .key_file
        .as_deref()
        .unwrap_or(".sendbuild/signing.key")
        .to_string();
    let key_path = PathBuf::from(&key_file);
    let key = if key_path.exists() {
        let existing = fs::read_to_string(&key_path)
            .with_context(|| format!("failed to read signing key file: {}", key_path.display()))?;
        let trimmed = existing.trim().to_string();
        if trimmed.len() >= 32 {
            trimmed
        } else {
            generate_and_store_signing_key(&key_path)?
        }
    } else {
        generate_and_store_signing_key(&key_path)?
    };
    validate_signing_key(&key, &key_env)?;
    env::set_var(&key_env, key);
    Ok(())
}

fn validate_signing_key(value: &str, key_env: &str) -> Result<()> {
    if value.trim().len() < 32 {
        bail!("signing key env `{key_env}` must be at least 32 characters");
    }
    Ok(())
}

fn generate_and_store_signing_key(path: &Path) -> Result<String> {
    let mut key_bytes = [0u8; 32];
    getrandom(&mut key_bytes)
        .map_err(|e| anyhow::anyhow!("failed to gather secure randomness: {e}"))?;
    let key = hex::encode(key_bytes);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create signing key directory: {}",
                    parent.display()
                )
            })?;
        }
    }
    fs::write(path, format!("{key}\n"))
        .with_context(|| format!("failed to write signing key file: {}", path.display()))?;

    Ok(key)
}

fn init_project(template: Option<&str>, _yes: bool) -> Result<()> {
    let cwd = env::current_dir()?;
    let project_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-app")
        .to_string();
    let repo_default = "https://github.com/you/repo".to_string();

    let framework = template
        .map(|v| v.to_string())
        .unwrap_or_else(|| detect_framework(&cwd).unwrap_or_else(|| "generic".to_string()));

    let config = match framework.as_str() {
        "nextjs" => format!(
            r#"[project]
name = "{project_name}"
# language = "nodejs" # optional override

[source]
repo = "{repo_default}"
branch = "main"

[build]
output_dir = ".next"

[deploy]
artifact_dir = "./artifacts"
targets = ["static_site", "tarball", "kubernetes"]
container_image = "{project_name}:latest"

[deploy.kubernetes]
enabled = true
namespace = "default"
replicas = 2
container_port = 3000
service_port = 80

[deploy.gc]
enabled = true
keep_last = 5
max_age_days = 14
"#
        ),
        "rails" => format!(
            r#"[project]
name = "{project_name}"
# language = "ruby"

[source]
repo = "{repo_default}"
branch = "main"

[deploy]
artifact_dir = "./artifacts"
targets = ["tarball", "container_image", "kubernetes"]
container_image = "{project_name}:latest"

[deploy.kubernetes]
enabled = true
namespace = "default"
replicas = 2
container_port = 3000
service_port = 80

[deploy.gc]
enabled = true
keep_last = 5
max_age_days = 14
"#
        ),
        "django" => format!(
            r#"[project]
name = "{project_name}"
# language = "python"

[source]
repo = "{repo_default}"
branch = "main"

[build]
output_dir = "staticfiles"

[deploy]
artifact_dir = "./artifacts"
targets = ["static_site", "serverless_function", "kubernetes"]
container_image = "{project_name}:latest"

[deploy.kubernetes]
enabled = true
namespace = "default"
replicas = 2
container_port = 8000
service_port = 80

[deploy.gc]
enabled = true
keep_last = 5
max_age_days = 14
"#
        ),
        _ => format!(
            r#"[project]
name = "{project_name}"
# language = "nodejs" # optional override

[source]
repo = "{repo_default}"
branch = "main"

[deploy]
artifact_dir = "./artifacts"
targets = ["directory", "kubernetes"]
container_image = "{project_name}:latest"

[deploy.kubernetes]
enabled = true
namespace = "default"
replicas = 1
container_port = 8080
service_port = 80

[deploy.gc]
enabled = true
keep_last = 5
max_age_days = 14
"#
        ),
    };

    fs::write("sendbuild.toml", config)?;
    println!("Initialized sendbuild.toml (template={framework})");
    Ok(())
}

fn run_cache(cmd: CacheCmd, config_path: &str) -> Result<()> {
    let cfg = BuildConfig::from_file(config_path)?;
    let cache_root = resolve_cache_root(&cfg);
    let project_cache = cache_root.join(&cfg.project.name);
    let deps = project_cache.join("deps");
    let artifact = project_cache.join("artifact");

    match cmd {
        CacheCmd::Save => {
            fs::create_dir_all(&project_cache)?;
            println!("Cache save placeholder at {}", project_cache.display());
        }
        CacheCmd::Restore => {
            if project_cache.exists() {
                println!("Cache restore available at {}", project_cache.display());
            } else {
                println!("No cache found at {}", project_cache.display());
            }
        }
        CacheCmd::Clear => {
            if project_cache.exists() {
                fs::remove_dir_all(&project_cache)?;
            }
            println!("Cache cleared: {}", project_cache.display());
        }
        CacheCmd::Status => {
            println!("Cache root: {}", project_cache.display());
            println!(
                "deps: {}",
                if deps.exists() { "present" } else { "missing" }
            );
            println!(
                "artifact: {}",
                if artifact.exists() {
                    "present"
                } else {
                    "missing"
                }
            );
            println!(
                "state: {}",
                if project_cache.join("state.txt").exists() {
                    "present"
                } else {
                    "missing"
                }
            );
        }
    }

    Ok(())
}

fn clean(config_path: &str, all: bool, cache_only: bool) -> Result<()> {
    let cfg = BuildConfig::from_file(config_path)?;
    let artifact_dir = PathBuf::from(&cfg.deploy.artifact_dir);
    let cache_root = resolve_cache_root(&cfg);
    let project_cache = cache_root.join(&cfg.project.name);

    if cache_only {
        if project_cache.exists() {
            fs::remove_dir_all(&project_cache)?;
        }
        println!("Cleaned cache only: {}", project_cache.display());
        return Ok(());
    }

    if artifact_dir.exists() {
        fs::remove_dir_all(&artifact_dir)?;
    }
    println!("Cleaned artifacts: {}", artifact_dir.display());

    if all {
        if project_cache.exists() {
            fs::remove_dir_all(&project_cache)?;
        }
        let temp = env::temp_dir().join("sendbuild");
        if temp.exists() {
            fs::remove_dir_all(&temp)?;
        }
        println!("Cleaned cache: {}", project_cache.display());
        println!("Cleaned temp workdirs: {}", temp.display());
    }

    Ok(())
}

fn info(config_path: &str, show_env: bool, show_deps: bool) -> Result<()> {
    let cfg = BuildConfig::from_file(config_path).ok();
    println!("sendbuilds version {}", env!("CARGO_PKG_VERSION"));

    if let Some(c) = &cfg {
        println!("project: {}", c.project.name);
        match &c.source {
            Some(s) => println!("repo: {}", s.repo),
            None => println!("source: local workspace"),
        }
        println!("artifact_dir: {}", c.deploy.artifact_dir);
    }

    if show_env {
        println!("os: {}", env::consts::OS);
        println!("arch: {}", env::consts::ARCH);
        println!("cwd: {}", env::current_dir()?.display());
    }

    if show_deps {
        for (name, args) in [
            ("node", vec!["--version"]),
            ("python", vec!["--version"]),
            ("ruby", vec!["--version"]),
            ("go", vec!["version"]),
            ("java", vec!["-version"]),
            ("php", vec!["--version"]),
            ("cargo", vec!["--version"]),
            ("dotnet", vec!["--version"]),
            ("deno", vec!["--version"]),
            ("gleam", vec!["--version"]),
            ("elixir", vec!["--version"]),
        ] {
            let out = Command::new(name).args(&args).output();
            match out {
                Ok(o) if o.status.success() => {
                    let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    let val = if !stdout.is_empty() { stdout } else { stderr };
                    println!("{name}: {}", val.lines().next().unwrap_or("ok"));
                }
                _ => println!("{name}: not found"),
            }
        }
    }

    Ok(())
}

fn detect_framework(cwd: &Path) -> Option<String> {
    if cwd.join("next.config.js").exists()
        || cwd.join("next.config.mjs").exists()
        || cwd.join("next.config.ts").exists()
    {
        return Some("nextjs".to_string());
    }
    if cwd.join("Gemfile").exists() && file_contains(&cwd.join("Gemfile"), "rails") {
        return Some("rails".to_string());
    }
    if cwd.join("manage.py").exists() {
        return Some("django".to_string());
    }
    None
}

fn resolve_cache_root(cfg: &BuildConfig) -> PathBuf {
    cfg.cache
        .as_ref()
        .and_then(|c| c.dir.as_ref())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&cfg.deploy.artifact_dir).join(".sendbuild-cache"))
}

fn file_contains(path: &Path, needle: &str) -> bool {
    fs::read_to_string(path)
        .map(|v| v.to_lowercase().contains(&needle.to_lowercase()))
        .unwrap_or(false)
}
