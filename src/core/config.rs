use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct BuildConfig {
    pub project: ProjectConfig,
    pub source:  Option<SourceConfig>,
    pub build:   Option<BuildStepConfig>,
    pub deploy:  DeployConfig,
    pub cache:   Option<CacheConfig>,
    pub scan:    Option<ScanConfig>,
    pub env:     Option<HashMap<String, String>>,
    pub env_from_host: Option<Vec<String>>,
    pub sandbox: Option<SandboxConfig>,
    pub signing: Option<SigningConfig>,
    pub compatibility: Option<CompatibilityConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectConfig {
    pub name:     String,
    pub language: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SourceConfig {
    pub repo:   String,
    pub branch: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BuildStepConfig {
    pub install_cmd: Option<String>,
    pub build_cmd:   Option<String>,
    pub parallel_build_cmds: Option<Vec<String>>,
    pub output_dir:  Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeployConfig {
    pub artifact_dir: String,
    pub targets: Option<Vec<String>>,
    pub container_image: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub enabled: Option<bool>,
    pub dir:     Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScanConfig {
    pub enabled: Option<bool>,
    pub command: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SandboxConfig {
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SigningConfig {
    pub enabled: Option<bool>,
    pub key_env: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompatibilityConfig {
    pub target_os: Option<String>,
    pub target_arch: Option<String>,
    pub target_node_major: Option<u32>,
}

impl BuildConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("cant read config: {path}"))?;

        toml::from_str(&raw).with_context(|| "config parse failed")
    }
}
