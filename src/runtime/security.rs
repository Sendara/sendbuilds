use anyhow::{bail, Result};
use chrono::Local;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::core::{BuildConfig, SecurityConfig};
use crate::runtime::shell;

#[derive(Debug, Clone, Serialize, Default)]
pub struct SecurityReport {
    pub generated_at: String,
    pub language: String,
    pub sbom_generated: bool,
    pub sbom_component_count: usize,
    pub vulnerability_scan: VulnerabilitySummary,
    pub fail_on_critical: bool,
    pub critical_threshold: u32,
    pub distroless: DistrolessSwitchResult,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VulnerabilitySummary {
    pub scanner: String,
    pub scanned: bool,
    pub command: String,
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub moderate: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DistrolessSwitchResult {
    pub enabled: bool,
    pub switched: bool,
    pub dockerfile_path: Option<String>,
    pub from_base: Option<String>,
    pub to_base: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityRunOutput {
    pub report: SecurityReport,
    pub sbom: Value,
    pub supply_chain_metadata: Value,
}

pub fn enabled(config: Option<&SecurityConfig>) -> bool {
    config.and_then(|c| c.enabled).unwrap_or(true)
}

pub fn run(
    language: &str,
    config: Option<&SecurityConfig>,
    build_cfg: &BuildConfig,
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
    in_place_mode: bool,
) -> Result<SecurityRunOutput> {
    let normalized = normalize_language(language);
    let generate_sbom = config.and_then(|c| c.generate_sbom).unwrap_or(true);
    let fail_on_critical = config.and_then(|c| c.fail_on_critical).unwrap_or(true);
    let critical_threshold = config.and_then(|c| c.critical_threshold).unwrap_or(0);
    let auto_distroless = config.and_then(|c| c.auto_distroless).unwrap_or(true);
    let distroless_base = config.and_then(|c| c.distroless_base.clone());
    let rewrite_in_place = config
        .and_then(|c| c.rewrite_dockerfile_in_place)
        .unwrap_or(false);

    let mut report = SecurityReport {
        generated_at: Local::now().to_rfc3339(),
        language: normalized.clone(),
        fail_on_critical,
        critical_threshold,
        ..Default::default()
    };

    let mut sbom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": Local::now().to_rfc3339(),
            "component": {
                "type": "application",
                "name": build_cfg.project.name
            },
            "tools": [{ "vendor": "sendbuilds", "name": "sendbuilds" }]
        },
        "components": []
    });
    if generate_sbom {
        sbom = generate_sbom_document(build_cfg, work_dir, &normalized);
        report.sbom_generated = true;
        report.sbom_component_count = sbom_component_count(&sbom);
    } else {
        report
            .notes
            .push("SBOM generation disabled by config".to_string());
    }

    report.vulnerability_scan = run_vulnerability_scan(&normalized, work_dir, env, sandbox)?;
    report.distroless = maybe_switch_to_distroless(
        &normalized,
        work_dir,
        auto_distroless,
        distroless_base,
        in_place_mode,
        rewrite_in_place,
    )?;
    if in_place_mode && !rewrite_in_place {
        report.notes.push(
            "in-place mode detected: Dockerfile rewrite is skipped by default for safety"
                .to_string(),
        );
    }

    let supply_chain_metadata = generate_supply_chain_metadata(build_cfg, work_dir, &report, &sbom);

    if fail_on_critical && report.vulnerability_scan.critical > critical_threshold {
        bail!(
            "security policy violation: critical vulnerabilities {} exceed threshold {}",
            report.vulnerability_scan.critical,
            critical_threshold
        );
    }

    Ok(SecurityRunOutput {
        report,
        sbom,
        supply_chain_metadata,
    })
}

pub fn to_build_logs(report: &SecurityReport) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "security summary scanner={} scanned={} total={} critical={} high={} moderate={} low={} info={}",
        report.vulnerability_scan.scanner,
        report.vulnerability_scan.scanned,
        report.vulnerability_scan.total,
        report.vulnerability_scan.critical,
        report.vulnerability_scan.high,
        report.vulnerability_scan.moderate,
        report.vulnerability_scan.low,
        report.vulnerability_scan.info
    ));
    lines.push(format!(
        "security policy fail_on_critical={} critical_threshold={}",
        report.fail_on_critical, report.critical_threshold
    ));
    if report.sbom_generated {
        lines.push(format!(
            "sbom generated components={}",
            report.sbom_component_count
        ));
    }
    if report.distroless.enabled {
        lines.push(format!(
            "distroless switched={} from={} to={}",
            report.distroless.switched,
            report
                .distroless
                .from_base
                .clone()
                .unwrap_or_else(|| "n/a".to_string()),
            report
                .distroless
                .to_base
                .clone()
                .unwrap_or_else(|| "n/a".to_string())
        ));
    }
    for note in &report.notes {
        lines.push(format!("note {note}"));
    }
    lines
}

fn run_vulnerability_scan(
    language: &str,
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<VulnerabilitySummary> {
    match language {
        "nodejs" => scan_nodejs(work_dir, env, sandbox),
        "python" => {
            let cmd = "pip-audit -f json";
            let run = shell::run_allow_failure(cmd, work_dir, env, sandbox)?;
            let mut summary = VulnerabilitySummary {
                scanner: "pip-audit".to_string(),
                scanned: true,
                command: cmd.to_string(),
                ..Default::default()
            };
            if let Some(raw) = collect_json(&run.logs) {
                if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                    if let Some(arr) = val.as_array() {
                        summary.total = arr.len() as u32;
                    }
                }
            }
            Ok(summary)
        }
        "rust" => {
            let cmd = "cargo audit --json";
            let run = shell::run_allow_failure(cmd, work_dir, env, sandbox)?;
            let mut summary = VulnerabilitySummary {
                scanner: "cargo-audit".to_string(),
                scanned: true,
                command: cmd.to_string(),
                ..Default::default()
            };
            if let Some(raw) = collect_json(&run.logs) {
                if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                    summary.critical = val
                        .get("vulnerabilities")
                        .and_then(|v| v.get("list"))
                        .and_then(Value::as_array)
                        .map(|a| a.len() as u32)
                        .unwrap_or(0);
                    summary.total = summary.critical;
                }
            }
            Ok(summary)
        }
        _ => Ok(VulnerabilitySummary {
            scanner: "none".to_string(),
            scanned: false,
            command: "n/a".to_string(),
            ..Default::default()
        }),
    }
}

fn scan_nodejs(
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<VulnerabilitySummary> {
    let cmd = "npm audit --json --omit=dev";
    let run = shell::run_allow_failure(cmd, work_dir, env, sandbox)?;
    let mut summary = VulnerabilitySummary {
        scanner: "npm-audit".to_string(),
        scanned: true,
        command: cmd.to_string(),
        ..Default::default()
    };
    if let Some(raw) = collect_json(&run.logs) {
        if let Ok(val) = serde_json::from_str::<Value>(&raw) {
            let meta = val.get("metadata").and_then(|m| m.get("vulnerabilities"));
            summary.critical = to_u32(meta.and_then(|v| v.get("critical")));
            summary.high = to_u32(meta.and_then(|v| v.get("high")));
            summary.moderate = to_u32(meta.and_then(|v| v.get("moderate")));
            summary.low = to_u32(meta.and_then(|v| v.get("low")));
            summary.info = to_u32(meta.and_then(|v| v.get("info")));
            summary.total =
                summary.critical + summary.high + summary.moderate + summary.low + summary.info;
        }
    }
    Ok(summary)
}

fn maybe_switch_to_distroless(
    language: &str,
    work_dir: &Path,
    enabled: bool,
    override_base: Option<String>,
    in_place_mode: bool,
    rewrite_in_place: bool,
) -> Result<DistrolessSwitchResult> {
    let mut out = DistrolessSwitchResult {
        enabled,
        ..Default::default()
    };
    if !enabled {
        return Ok(out);
    }
    if in_place_mode && !rewrite_in_place {
        return Ok(out);
    }

    let dockerfile = work_dir.join("Dockerfile");
    if !dockerfile.exists() {
        return Ok(out);
    }
    out.dockerfile_path = Some(dockerfile.display().to_string());

    let desired = override_base.unwrap_or_else(|| distroless_base_for_language(language));
    let raw = fs::read_to_string(&dockerfile)?;
    let mut lines = raw.lines().map(str::to_string).collect::<Vec<_>>();
    let Some(from_idx) = lines
        .iter()
        .rposition(|line| line.trim_start().to_uppercase().starts_with("FROM "))
    else {
        return Ok(out);
    };

    let old_line = lines[from_idx].trim().to_string();
    let old_tokens = old_line.split_whitespace().collect::<Vec<_>>();
    if old_tokens.len() < 2 {
        return Ok(out);
    }
    let old_base = old_tokens[1].to_string();
    out.from_base = Some(old_base.clone());
    out.to_base = Some(desired.clone());
    if old_base.contains("distroless") {
        return Ok(out);
    }

    let alias = if old_tokens.len() >= 4 && old_tokens[2].eq_ignore_ascii_case("as") {
        Some(old_tokens[3].to_string())
    } else {
        None
    };
    lines[from_idx] = match alias {
        Some(a) => format!("FROM {desired} AS {a}"),
        None => format!("FROM {desired}"),
    };
    fs::write(&dockerfile, lines.join("\n"))?;
    out.switched = true;
    Ok(out)
}

fn generate_sbom_document(build_cfg: &BuildConfig, work_dir: &Path, language: &str) -> Value {
    let mut components = Vec::new();

    let pkg = work_dir.join("package.json");
    if pkg.exists() {
        if let Ok(raw) = fs::read_to_string(&pkg) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                append_components(&val, "dependencies", "library", &mut components);
                append_components(&val, "devDependencies", "library", &mut components);
            }
        }
    }

    let cargo = work_dir.join("Cargo.lock");
    if cargo.exists() {
        if let Ok(raw) = fs::read_to_string(&cargo) {
            append_cargo_components(&raw, &mut components);
        }
    }

    let reqs = work_dir.join("requirements.txt");
    if reqs.exists() {
        if let Ok(raw) = fs::read_to_string(&reqs) {
            append_python_components(&raw, &mut components);
        }
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": Local::now().to_rfc3339(),
            "component": {
                "type": "application",
                "name": build_cfg.project.name,
                "properties": [
                    {"name":"sendbuilds:language", "value":language}
                ]
            },
            "tools": [{ "vendor": "sendbuilds", "name": "sendbuilds" }]
        },
        "components": components
    })
}

fn generate_supply_chain_metadata(
    build_cfg: &BuildConfig,
    work_dir: &Path,
    report: &SecurityReport,
    sbom: &Value,
) -> Value {
    let commit = git_output(work_dir, &["rev-parse", "HEAD"]);
    let branch = git_output(work_dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let lockfiles = [
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Cargo.lock",
        "poetry.lock",
        "requirements.txt",
        "Gemfile.lock",
        "composer.lock",
        "go.sum",
    ]
    .iter()
    .filter(|f| work_dir.join(f).exists())
    .map(|v| v.to_string())
    .collect::<Vec<_>>();

    json!({
        "schema_version":"1",
        "generated_at": Local::now().to_rfc3339(),
        "builder":"sendbuilds",
        "project": build_cfg.project.name,
        "language": report.language,
        "source": {
            "repo": build_cfg.source.as_ref().map(|s| s.repo.clone()),
            "branch": branch,
            "commit": commit
        },
        "security_policy": {
            "fail_on_critical": report.fail_on_critical,
            "critical_threshold": report.critical_threshold
        },
        "distroless": {
            "enabled": report.distroless.enabled,
            "switched": report.distroless.switched,
            "from": report.distroless.from_base,
            "to": report.distroless.to_base
        },
        "dependency_lockfiles": lockfiles,
        "sbom_component_count": sbom_component_count(sbom),
        "vulnerabilities": report.vulnerability_scan
    })
}

fn git_output(work_dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(work_dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn append_components(pkg: &Value, field: &str, component_type: &str, out: &mut Vec<Value>) {
    if let Some(deps) = pkg.get(field).and_then(Value::as_object) {
        for (name, version) in deps {
            out.push(json!({
                "type": component_type,
                "name": name,
                "version": version.as_str().unwrap_or("unknown"),
                "scope": field
            }));
        }
    }
}

fn append_cargo_components(raw: &str, out: &mut Vec<Value>) {
    let mut name = String::new();
    let mut version = String::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if !name.is_empty() {
                out.push(json!({"type":"library","name":name,"version":version,"scope":"cargo"}));
            }
            name.clear();
            version.clear();
            continue;
        }
        if let Some(v) = trimmed.strip_prefix("name = ") {
            name = v.trim_matches('"').to_string();
        }
        if let Some(v) = trimmed.strip_prefix("version = ") {
            version = v.trim_matches('"').to_string();
        }
    }
    if !name.is_empty() {
        out.push(json!({"type":"library","name":name,"version":version,"scope":"cargo"}));
    }
}

fn append_python_components(raw: &str, out: &mut Vec<Value>) {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts = trimmed.split("==").collect::<Vec<_>>();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0].trim();
        let version = parts.get(1).copied().unwrap_or("unknown").trim();
        out.push(json!({"type":"library","name":name,"version":version,"scope":"python"}));
    }
}

fn sbom_component_count(sbom: &Value) -> usize {
    sbom.get("components")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0)
}

fn to_u32(v: Option<&Value>) -> u32 {
    if let Some(n) = v.and_then(Value::as_u64) {
        return n as u32;
    }
    if let Some(s) = v.and_then(Value::as_str) {
        if let Ok(n) = s.parse::<u32>() {
            return n;
        }
    }
    0
}

fn collect_json(logs: &[String]) -> Option<String> {
    let mut body = String::new();
    for line in logs {
        if let Some(rest) = line.strip_prefix("stdout: ") {
            body.push_str(rest);
        } else if let Some(rest) = line.strip_prefix("stderr: ") {
            body.push_str(rest);
        } else {
            body.push_str(line);
        }
        body.push('\n');
    }
    let obj_start = body.find('{');
    let arr_start = body.find('[');
    let (start, end) = match (obj_start, arr_start) {
        (Some(o), Some(a)) if a < o => (a, body.rfind(']')?),
        (Some(o), _) => (o, body.rfind('}')?),
        (None, Some(a)) => (a, body.rfind(']')?),
        (None, None) => return None,
    };
    if end <= start {
        return None;
    }
    Some(body[start..=end].to_string())
}

fn distroless_base_for_language(language: &str) -> String {
    match language {
        "nodejs" => "gcr.io/distroless/nodejs20-debian12".to_string(),
        "python" => "gcr.io/distroless/python3-debian12".to_string(),
        "java" => "gcr.io/distroless/java21-debian12".to_string(),
        "go" | "rust" | "c_cpp" => "gcr.io/distroless/static-debian12".to_string(),
        _ => "gcr.io/distroless/base-debian12".to_string(),
    }
}

fn normalize_language(language: &str) -> String {
    match language.to_lowercase().as_str() {
        "node" | "nodejs" => "nodejs".to_string(),
        "python" | "py" => "python".to_string(),
        "ruby" | "rb" => "ruby".to_string(),
        "go" | "golang" => "go".to_string(),
        "java" | "jvm" => "java".to_string(),
        "php" => "php".to_string(),
        "rust" | "rs" => "rust".to_string(),
        "c" | "cpp" | "c++" | "c_cpp" | "cc" => "c_cpp".to_string(),
        other => other.to_string(),
    }
}
