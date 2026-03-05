use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct BuildConfig {
    pub project: ProjectConfig,
    pub source: Option<SourceConfig>,
    pub build: Option<BuildStepConfig>,
    pub deploy: DeployConfig,
    pub cache: Option<CacheConfig>,
    pub scan: Option<ScanConfig>,
    pub security: Option<SecurityConfig>,
    pub env: Option<HashMap<String, String>>,
    pub env_from_host: Option<Vec<String>>,
    pub sandbox: Option<SandboxConfig>,
    pub signing: Option<SigningConfig>,
    pub compatibility: Option<CompatibilityConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub language: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SourceConfig {
    pub repo: String,
    pub branch: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BuildStepConfig {
    pub install_cmd: Option<String>,
    pub build_cmd: Option<String>,
    pub parallel_build_cmds: Option<Vec<String>>,
    pub output_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeployConfig {
    pub artifact_dir: String,
    pub targets: Option<Vec<String>>,
    pub container_image: Option<String>,
    pub kubernetes: Option<KubernetesConfig>,
    pub gc: Option<GarbageCollectionConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KubernetesConfig {
    pub enabled: Option<bool>,
    pub namespace: Option<String>,
    pub replicas: Option<u32>,
    pub container_port: Option<u16>,
    pub service_port: Option<u16>,
    pub image_pull_policy: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GarbageCollectionConfig {
    pub enabled: Option<bool>,
    pub keep_last: Option<usize>,
    pub max_age_days: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub enabled: Option<bool>,
    pub dir: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScanConfig {
    pub enabled: Option<bool>,
    pub command: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub enabled: Option<bool>,
    pub fail_on_critical: Option<bool>,
    pub critical_threshold: Option<u32>,
    pub fail_on_scanner_unavailable: Option<bool>,
    pub generate_sbom: Option<bool>,
    pub auto_distroless: Option<bool>,
    pub distroless_base: Option<String>,
    pub rewrite_dockerfile_in_place: Option<bool>,
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
        let raw = fs::read_to_string(path).with_context(|| format!("cant read config: {path}"))?;

        toml::from_str(&raw).with_context(|| "config parse failed")
    }

    pub fn for_local_workspace() -> Result<Self> {
        let cwd = std::env::current_dir().with_context(|| "cant resolve current directory")?;
        let name = cwd
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.trim().is_empty())
            .unwrap_or("local-app")
            .to_string();

        Ok(Self {
            project: ProjectConfig {
                name,
                language: None,
            },
            source: None,
            build: None,
            deploy: DeployConfig {
                artifact_dir: "./artifacts".to_string(),
                targets: Some(vec!["directory".to_string()]),
                container_image: None,
                kubernetes: None,
                gc: None,
            },
            cache: None,
            scan: None,
            security: None,
            env: None,
            env_from_host: None,
            sandbox: None,
            signing: None,
            compatibility: None,
        })
    }

    pub fn exists(path: &str) -> bool {
        Path::new(path).exists()
    }
}
