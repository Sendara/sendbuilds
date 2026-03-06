use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use getrandom::getrandom;
use serde_json::Value;
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
        reproducible: bool,
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
    Deploy {
        repo: Option<String>,
        #[arg(long)]
        local: bool,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        docker: bool,
        #[arg(long = "target", value_delimiter = ',')]
        targets: Vec<String>,
        #[arg(long)]
        image: Option<String>,
        #[arg(long = "dry-run")]
        dry_run: bool,
        #[arg(long)]
        remote: bool,
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
    Rebase {
        #[arg(short, long, default_value = "sendbuild.toml")]
        config: String,
        #[arg(long)]
        git: bool,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value = ".")]
        context: String,
        #[arg(long)]
        dockerfile: Option<String>,
        #[arg(long)]
        image: Option<String>,
        #[arg(long = "from-image")]
        from_image: Option<String>,
        #[arg(long = "base")]
        base: Option<String>,
        #[arg(long = "platform", value_delimiter = ',')]
        platforms: Vec<String>,
        #[arg(long)]
        push: bool,
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
            reproducible,
            in_place,
            git,
            branch,
            docker,
            image,
        } => {
            if git.is_some() || docker {
                return run_quick_build(git, branch, docker, image, in_place, events, reproducible);
            }
            if BuildConfig::exists(&config) {
                let cfg = BuildConfig::from_file(&config)?;
                prepare_signing_key(cfg.signing.as_ref())?;
                BuildEngine::from_config(cfg)
                    .with_in_place(in_place)
                    .with_events(events)
                    .with_reproducible(reproducible)
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
                    .with_reproducible(reproducible)
                    .run()
            }
        }
        Cmd::Deploy {
            repo,
            local,
            branch,
            docker,
            targets,
            image,
            dry_run,
            remote,
        } => run_deploy(repo, local, branch, docker, targets, image, dry_run, remote),
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
        Cmd::Rebase {
            config,
            git,
            repo,
            branch,
            context,
            dockerfile,
            image,
            from_image,
            base,
            platforms,
            push,
        } => run_rebase(
            &config, git, repo, branch, &context, dockerfile, image, from_image, base, platforms,
            push,
        ),
    }
}

fn run_deploy(
    repo: Option<String>,
    local: bool,
    branch: Option<String>,
    docker: bool,
    targets: Vec<String>,
    image: Option<String>,
    dry_run: bool,
    remote: bool,
) -> Result<()> {
    if local && repo.is_some() {
        bail!("use either positional <repo> or --local, not both");
    }
    if branch.is_some() && (local || repo.is_none()) {
        bail!("--branch requires a git repo deploy target");
    }

    let git_repo = if local { None } else { repo };
    let project_name = git_repo
        .as_deref()
        .map(project_name_from_repo)
        .unwrap_or_else(local_project_name);

    let explicit_targets = !targets.is_empty();
    let mut normalized_targets = if targets.is_empty() {
        vec!["directory".to_string()]
    } else {
        targets
            .iter()
            .map(|t| normalize_target(t))
            .collect::<Vec<_>>()
    };
    let target_requires_container = normalized_targets
        .iter()
        .any(|t| t == "container_image" || t == "kubernetes");
    let inferred_container = infer_deploy_container_need(git_repo.as_deref())?;
    let should_use_container =
        docker || target_requires_container || (!docker && !explicit_targets && inferred_container);

    if should_use_container && !normalized_targets.iter().any(|t| t == "container_image") {
        normalized_targets.push("container_image".to_string());
    }
    if normalized_targets.is_empty() {
        normalized_targets.push("directory".to_string());
    }

    if dry_run {
        println!("sendbuilds deploy dry-run");
        println!("repo: {}", git_repo.as_deref().unwrap_or("local-workspace"));
        println!("branch: {}", branch.as_deref().unwrap_or("default"));
        println!("remote: {}", if remote { "requested" } else { "disabled" });
        println!("project: {}", project_name);
        let image_tag = image.unwrap_or_else(|| format!("{project_name}:latest"));
        println!("image: {}", image_tag);
        println!("targets: {}", normalized_targets.join(", "));
        println!(
            "container mode: {}",
            if should_use_container {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!("planned steps:");
        for step in [
            "clone repo",
            "detect language/framework",
            "install dependencies",
            "build project",
            "generate SBOM + supply-chain metadata",
            "run vulnerability/security scan",
            "build container image (if target includes container_image)",
            "sign artifacts/provenance",
            "publish artifacts/deploy targets",
        ] {
            println!("- {step}");
        }
        return Ok(());
    }

    if remote {
        println!("--remote requested; cloud workers are not configured yet, running locally.");
    }

    let image_tag = image.unwrap_or_else(|| format!("{project_name}:latest"));
    let in_place = git_repo.is_none();
    run_quick_build_with_options(
        git_repo,
        branch,
        should_use_container,
        Some(image_tag),
        in_place,
        None,
        None,
        Some(false),
        Some(normalized_targets),
        false,
    )
}

fn infer_deploy_container_need(git_repo: Option<&str>) -> Result<bool> {
    if let Ok(cfg) = BuildConfig::from_file("sendbuild.toml") {
        let from_cfg = cfg
            .deploy
            .targets
            .as_ref()
            .map(|targets| {
                targets.iter().any(|t| {
                    let n = normalize_target(t);
                    n == "container_image" || n == "kubernetes"
                })
            })
            .unwrap_or(false);
        if from_cfg {
            return Ok(true);
        }
    }

    if git_repo.is_none() {
        let cwd = env::current_dir()?;
        if cwd.join("Dockerfile").exists() || cwd.join("docker-compose.yml").exists() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn run_quick_build(
    git_repo: Option<String>,
    git_branch: Option<String>,
    docker: bool,
    image: Option<String>,
    in_place: bool,
    events: Option<bool>,
    reproducible: bool,
) -> Result<()> {
    run_quick_build_with_options(
        git_repo,
        git_branch,
        docker,
        image,
        in_place,
        events,
        None,
        None,
        None,
        reproducible,
    )
}

fn run_quick_build_with_options(
    git_repo: Option<String>,
    git_branch: Option<String>,
    docker: bool,
    image: Option<String>,
    in_place: bool,
    events: Option<bool>,
    rebase_base: Option<String>,
    fail_on_scanner_unavailable: Option<bool>,
    explicit_targets: Option<Vec<String>>,
    reproducible: bool,
) -> Result<()> {
    let has_git = git_repo.is_some();
    let name = git_repo
        .as_deref()
        .map(project_name_from_repo)
        .unwrap_or_else(|| local_project_name());
    let mut targets = explicit_targets.unwrap_or_else(|| vec!["directory".to_string()]);
    if docker && !targets.iter().any(|t| t == "container_image") {
        targets.push("container_image".to_string());
    }
    let wants_container = targets.iter().any(|t| t == "container_image");
    let image_tag = image.unwrap_or_else(|| format!("{name}:latest"));

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
            container_image: if wants_container {
                Some(image_tag)
            } else {
                None
            },
            container_platforms: None,
            // quick builds ofc
            push_container: Some(false),
            rebase_base,
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
            fail_on_scanner_unavailable: Some(fail_on_scanner_unavailable.unwrap_or(true)),
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
        .with_reproducible(reproducible)
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

fn normalize_target(raw: &str) -> String {
    match raw.trim().to_lowercase().as_str() {
        "docker" | "container" | "container-image" => "container_image".to_string(),
        "k8s" => "kubernetes".to_string(),
        "zip" | "serverless" => "serverless_zip".to_string(),
        "dir" => "directory".to_string(),
        other => other.to_string(),
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
    write_signing_key(path, &key)?;

    Ok(key)
}

fn write_signing_key(path: &Path, key: &str) -> Result<()> {
    let content = format!("{key}\n");

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to write signing key file: {}", path.display()))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("failed to write signing key file: {}", path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush signing key file: {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "failed to set secure permissions on signing key file: {}",
                path.display()
            )
        })?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, content)
            .with_context(|| format!("failed to write signing key file: {}", path.display()))?;
        Ok(())
    }
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

fn run_rebase(
    config_path: &str,
    git: bool,
    repo: Option<String>,
    branch: Option<String>,
    context: &str,
    dockerfile: Option<String>,
    image: Option<String>,
    from_image: Option<String>,
    base: Option<String>,
    platforms: Vec<String>,
    push: bool,
) -> Result<()> {
    let cfg = BuildConfig::from_file(config_path).ok();

    if git || repo.is_some() {
        let repo_ref = repo
            .or_else(|| cfg.as_ref().and_then(|c| c.source.as_ref().map(|s| s.repo.clone())))
            .or_else(local_git_remote_url)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "rebase --git requires a repository source. set --repo, [source].repo, or configure git remote.origin.url"
                )
            })?;
        let branch_ref = branch.or_else(|| {
            cfg.as_ref()
                .and_then(|c| c.source.as_ref().and_then(|s| s.branch.clone()))
        });
        let target_image = image
            .or_else(|| cfg.as_ref().and_then(|c| c.deploy.container_image.clone()))
            .unwrap_or_else(|| format!("{}:latest", project_name_from_repo(&repo_ref)));
        let runtime_base = base.or_else(|| cfg.as_ref().and_then(|c| c.deploy.rebase_base.clone()));

        ensure_local_image_cache(&target_image);

        println!(
            "Rebase git mode: rebuilding full image from `{}` as `{}`.",
            repo_ref, target_image
        );
        return run_quick_build_with_options(
            Some(repo_ref),
            branch_ref,
            true,
            Some(target_image),
            false,
            None,
            runtime_base,
            Some(false),
            None,
            false,
        );
    }

    let context_path = PathBuf::from(context);
    if !context_path.exists() {
        bail!("rebase context does not exist: {}", context_path.display());
    }

    let target_image = image
        .or_else(|| cfg.as_ref().and_then(|c| c.deploy.container_image.clone()))
        .unwrap_or_else(|| format!("{}:rebased", local_project_name()));
    let cache_from = from_image.or_else(|| Some(target_image.clone()));
    let runtime_base = base
        .or_else(|| cfg.as_ref().and_then(|c| c.deploy.rebase_base.clone()))
        .or_else(|| read_runtime_base_from_plan(&context_path))
        .filter(|v| !v.trim().is_empty() && v != "auto")
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing runtime base. set --base <image>, [deploy].rebase_base, or .sendbuild-rebase-plan.json"
            )
        })?;

    let dockerfile_path = resolve_rebase_dockerfile(&context_path, dockerfile.as_deref())?;

    let docker_available = Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !docker_available {
        bail!("docker not available");
    }

    let normalized_platforms = platforms
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();

    let buildx_available = Command::new("docker")
        .args(["buildx", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    let status = if buildx_available {
        if normalized_platforms.len() > 1 && !push {
            bail!("multi-arch rebase requires --push (buildx cannot --load multiple platforms)");
        }
        let mut cmd = Command::new("docker");
        cmd.arg("buildx")
            .arg("build")
            .arg("--target")
            .arg("launch")
            .arg("--build-arg")
            .arg(format!("RUNTIME_BASE={runtime_base}"))
            .arg("-t")
            .arg(&target_image)
            .arg("--file")
            .arg(&dockerfile_path);
        if let Some(cache) = cache_from.as_deref() {
            cmd.arg("--cache-from").arg(cache);
        }
        if !normalized_platforms.is_empty() {
            cmd.arg("--platform").arg(normalized_platforms.join(","));
        }
        if push {
            cmd.arg("--push");
        } else {
            cmd.arg("--load");
        }
        cmd.arg(&context_path).status()?
    } else {
        if !normalized_platforms.is_empty() || push {
            bail!("docker buildx is required for --platform/--push rebase options");
        }
        let mut cmd = Command::new("docker");
        cmd.arg("build")
            .arg("--target")
            .arg("launch")
            .arg("--build-arg")
            .arg(format!("RUNTIME_BASE={runtime_base}"))
            .arg("-t")
            .arg(&target_image)
            .arg("--file")
            .arg(&dockerfile_path);
        if let Some(cache) = cache_from.as_deref() {
            cmd.arg("--cache-from").arg(cache);
        }
        cmd.arg(&context_path).status()?
    };

    if !status.success() {
        bail!("docker rebase build failed");
    }

    println!(
        "Rebased image `{}` using runtime base `{}` (cache-from: {}).",
        target_image,
        runtime_base,
        cache_from.as_deref().unwrap_or("none")
    );
    Ok(())
}

fn resolve_rebase_dockerfile(context: &Path, provided: Option<&str>) -> Result<PathBuf> {
    if let Some(path) = provided {
        let path = PathBuf::from(path);
        if !path.exists() {
            bail!("dockerfile not found: {}", path.display());
        }
        return Ok(path);
    }

    let layered = context.join("Dockerfile.sendbuild.layered");
    if layered.exists() {
        return Ok(layered);
    }

    let dockerfile = context.join("Dockerfile");
    if dockerfile.exists() {
        let data = fs::read_to_string(&dockerfile).unwrap_or_default();
        if data
            .to_lowercase()
            .contains("# sendbuilds: layered rebase-ready dockerfile")
        {
            return Ok(dockerfile);
        }
    }

    bail!(
        "could not find a sendbuilds layered dockerfile in `{}`. run `sendbuilds build --docker` first or pass --dockerfile",
        context.display()
    )
}

fn read_runtime_base_from_plan(context: &Path) -> Option<String> {
    let plan_path = context.join(".sendbuild-rebase-plan.json");
    let plan = fs::read_to_string(plan_path).ok()?;
    let json: Value = serde_json::from_str(&plan).ok()?;
    json.get("runtime_base")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
}

fn local_git_remote_url() -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if url.is_empty() {
        None
    } else {
        Some(url)
    }
}

fn ensure_local_image_cache(image: &str) {
    let local_exists = Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if local_exists {
        return;
    }
    let _ = Command::new("docker").args(["pull", image]).status();
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
