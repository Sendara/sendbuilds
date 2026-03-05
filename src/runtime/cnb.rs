use anyhow::Result;
use chrono::{DateTime, Duration, Local};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::{Step, StepStatus};

const PHASE_ORDER: [&str; 5] = ["detect", "analyze", "restore", "build", "export"];
const LIFECYCLE_API: &str = "0.20";
const PLATFORM_API: &str = "0.12";

#[derive(Debug, Serialize)]
struct LifecycleContract {
    schema_version: String,
    lifecycle_api: String,
    platform_api: String,
    phases: Vec<ContractPhase>,
}

#[derive(Debug, Serialize)]
struct ContractPhase {
    name: String,
    required: bool,
    step_contract: Vec<String>,
    inputs: Vec<String>,
    outputs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LifecycleMetadata {
    schema_version: String,
    lifecycle_api: String,
    platform_api: String,
    builder: BuilderMetadata,
    project: ProjectMetadata,
    buildpacks: Vec<BuildpackMetadata>,
    phases: Vec<PhaseMetadata>,
    exported_artifacts: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BuilderMetadata {
    id: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct ProjectMetadata {
    name: String,
    generated_at: String,
}

#[derive(Debug, Serialize)]
struct BuildpackMetadata {
    id: String,
    version: String,
    language: String,
}

#[derive(Debug, Serialize)]
struct PhaseMetadata {
    name: String,
    status: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    duration_ms: u64,
    mapped_steps: Vec<String>,
}

pub fn write_lifecycle_contract(root: &Path) -> Result<PathBuf> {
    let cnb_dir = root.join("cnb");
    fs::create_dir_all(&cnb_dir)?;

    let contract = LifecycleContract {
        schema_version: "1".to_string(),
        lifecycle_api: LIFECYCLE_API.to_string(),
        platform_api: PLATFORM_API.to_string(),
        phases: vec![
            ContractPhase {
                name: "detect".to_string(),
                required: true,
                step_contract: vec![
                    "source".to_string(),
                    "detect-build-config".to_string(),
                    "compatibility-check".to_string(),
                ],
                inputs: vec!["source workspace".to_string(), "build env".to_string()],
                outputs: vec![
                    "detected language".to_string(),
                    "resolved build plan".to_string(),
                ],
            },
            ContractPhase {
                name: "analyze".to_string(),
                required: false,
                step_contract: vec!["incremental-prepare".to_string()],
                inputs: vec!["previous build state".to_string()],
                outputs: vec!["analysis metadata".to_string()],
            },
            ContractPhase {
                name: "restore".to_string(),
                required: false,
                step_contract: vec!["install".to_string(), "deps-cache-save".to_string()],
                inputs: vec!["cache layers".to_string()],
                outputs: vec!["restored dependencies".to_string()],
            },
            ContractPhase {
                name: "build".to_string(),
                required: true,
                step_contract: vec!["build".to_string(), "build-task-*".to_string()],
                inputs: vec!["restored workspace".to_string()],
                outputs: vec!["build output".to_string()],
            },
            ContractPhase {
                name: "export".to_string(),
                required: true,
                step_contract: vec![
                    "deploy".to_string(),
                    "sign-artifacts".to_string(),
                    "build-metrics".to_string(),
                ],
                inputs: vec!["build output".to_string()],
                outputs: vec![
                    "artifact payload".to_string(),
                    "lifecycle metadata".to_string(),
                ],
            },
        ],
    };

    let out = cnb_dir.join("lifecycle-contract.json");
    fs::write(out.clone(), serde_json::to_vec_pretty(&contract)?)?;
    Ok(out)
}

pub fn write_lifecycle_metadata(
    root: &Path,
    project_name: &str,
    started_at: DateTime<Local>,
    steps: &[Step],
    outputs: &[PathBuf],
    warnings: &[String],
) -> Result<PathBuf> {
    let cnb_dir = root.join("cnb");
    fs::create_dir_all(&cnb_dir)?;

    let language = infer_language_from_steps(steps).unwrap_or_else(|| "unknown".to_string());
    let buildpack_id = format!("io.sendbuilds.buildpack.{}", language.replace('_', "-"));

    let mut step_ranges = Vec::with_capacity(steps.len());
    let mut cursor = started_at;
    for step in steps {
        let dur_ms = (step.duration_secs.unwrap_or_default() * 1000.0).round() as i64;
        let step_start = cursor;
        let step_end = cursor + Duration::milliseconds(dur_ms.max(0));
        step_ranges.push((step_start, step_end));
        cursor = step_end;
    }

    let phases = PHASE_ORDER
        .iter()
        .map(|phase| build_phase(*phase, steps, &step_ranges))
        .collect::<Vec<_>>();

    let exported = outputs
        .iter()
        .map(|p| {
            p.strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();

    let metadata = LifecycleMetadata {
        schema_version: "1".to_string(),
        lifecycle_api: LIFECYCLE_API.to_string(),
        platform_api: PLATFORM_API.to_string(),
        builder: BuilderMetadata {
            id: "io.sendbuilds.builder".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        project: ProjectMetadata {
            name: project_name.to_string(),
            generated_at: Local::now().to_rfc3339(),
        },
        buildpacks: vec![BuildpackMetadata {
            id: buildpack_id,
            version: env!("CARGO_PKG_VERSION").to_string(),
            language,
        }],
        phases,
        exported_artifacts: exported,
        warnings: warnings.to_vec(),
    };

    let out = cnb_dir.join("lifecycle-metadata.json");
    fs::write(out.clone(), serde_json::to_vec_pretty(&metadata)?)?;
    Ok(out)
}

fn build_phase(
    phase: &str,
    steps: &[Step],
    step_ranges: &[(DateTime<Local>, DateTime<Local>)],
) -> PhaseMetadata {
    let mut mapped_steps = Vec::new();
    let mut status = StepStatus::Pending;
    let mut started_at = None;
    let mut finished_at = None;
    let mut duration_ms = 0u64;

    for (idx, step) in steps.iter().enumerate() {
        if phase_for_step(&step.name) != Some(phase) {
            continue;
        }

        mapped_steps.push(step.name.clone());
        status = merge_status(status, step.status);
        if let Some((s, e)) = step_ranges.get(idx) {
            if started_at.is_none() {
                started_at = Some(*s);
            }
            finished_at = Some(*e);
            duration_ms += (step.duration_secs.unwrap_or_default() * 1000.0).round() as u64;
        }
    }

    PhaseMetadata {
        name: phase.to_string(),
        status: status.as_str().to_string(),
        started_at: started_at.map(|v| v.to_rfc3339()),
        finished_at: finished_at.map(|v| v.to_rfc3339()),
        duration_ms,
        mapped_steps,
    }
}

fn phase_for_step(step_name: &str) -> Option<&'static str> {
    match step_name {
        "source" | "detect-build-config" | "compatibility-check" => Some("detect"),
        "incremental-prepare" => Some("analyze"),
        "install" | "deps-cache-save" => Some("restore"),
        "build" => Some("build"),
        "deploy" | "sign-artifacts" | "build-metrics" | "cache-state-save" | "cnb-lifecycle" => {
            Some("export")
        }
        other if other.starts_with("build-task-") => Some("build"),
        _ => None,
    }
}

fn merge_status(current: StepStatus, next: StepStatus) -> StepStatus {
    match (current, next) {
        (StepStatus::Failed, _) | (_, StepStatus::Failed) => StepStatus::Failed,
        (StepStatus::Completed, _) => StepStatus::Completed,
        (_, StepStatus::Completed) => StepStatus::Completed,
        (StepStatus::Running, _) => StepStatus::Running,
        (_, StepStatus::Running) => StepStatus::Running,
        _ => StepStatus::Pending,
    }
}

fn infer_language_from_steps(steps: &[Step]) -> Option<String> {
    for step in steps {
        for line in &step.logs {
            if let Some(lang) = line.strip_prefix("language=") {
                let trimmed = lang.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
            if let Some(lang) = line.strip_prefix("language:") {
                let trimmed = lang.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{phase_for_step, write_lifecycle_contract};

    #[test]
    fn phase_mapping_known_steps() {
        assert_eq!(phase_for_step("source"), Some("detect"));
        assert_eq!(phase_for_step("incremental-prepare"), Some("analyze"));
        assert_eq!(phase_for_step("build-task-2"), Some("build"));
        assert_eq!(phase_for_step("deploy"), Some("export"));
        assert_eq!(phase_for_step("unknown"), None);
    }

    #[test]
    fn writes_contract_file() {
        let tmp = std::env::temp_dir().join("sendbuild-cnb-contract-test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let out = write_lifecycle_contract(&tmp).expect("write contract");
        assert!(out.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
