use anyhow::Result;
use clap::{Parser, Subcommand};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        Cmd::Build { config } => BuildEngine::load(&config)?.run(),
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
targets = ["static_site", "tarball"]
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
targets = ["tarball", "container_image"]
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
targets = ["static_site", "serverless_function"]
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
            println!("deps: {}", if deps.exists() { "present" } else { "missing" });
            println!(
                "artifact: {}",
                if artifact.exists() { "present" } else { "missing" }
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
