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

const CYCLONEDX_SPEC_VERSION: &str = "1.7";

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
    pub container_scan: Option<VulnerabilitySummary>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VulnerabilitySummary {
    pub scanner: String,
    pub scanned: bool,
    pub command: String,
    pub scanner_attempts: Vec<String>,
    pub unavailable_reason: Option<String>,
    pub packages: Vec<String>,
    pub suggestions: Vec<String>,
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub moderate: u32,
    pub low: u32,
    pub info: u32,
    pub misconfigurations: u32,
    pub secrets: u32,
    pub detailed_findings: Vec<String>,
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
    let fail_on_scanner_unavailable = config
        .and_then(|c| c.fail_on_scanner_unavailable)
        .unwrap_or(true);
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
        "specVersion": CYCLONEDX_SPEC_VERSION,
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
    if !report.vulnerability_scan.scanned {
        let reason = report
            .vulnerability_scan
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "scanner unavailable".to_string());
        report.notes.push(format!(
            "vulnerability scanner unavailable for language={} scanner={} reason={}",
            normalized, report.vulnerability_scan.scanner, reason
        ));
        if fail_on_scanner_unavailable && scanner_expected_for_language(&normalized) {
            let suggestions = if report.vulnerability_scan.suggestions.is_empty() {
                "none".to_string()
            } else {
                report.vulnerability_scan.suggestions.join(" | ")
            };
            bail!(
                "security policy violation: required scanner unavailable for language={} scanners={} reason={} suggestions={}",
                normalized,
                report.vulnerability_scan.scanner,
                reason,
                suggestions
            );
        }
    }
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
            "{}",
            format_policy_violation_with_findings(&report.vulnerability_scan, critical_threshold)
        );
    }
    if report.vulnerability_scan.high > 0 || report.vulnerability_scan.moderate > 0 {
        bail!(
            "{}",
            format_policy_violation_disallow_high_moderate(&report.vulnerability_scan)
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
        "security summary scanner={} scanned={} total={} critical={} high={} moderate={} low={} info={} misconfigurations={} secrets={} unavailable_reason={}",
        report.vulnerability_scan.scanner,
        report.vulnerability_scan.scanned,
        report.vulnerability_scan.total,
        report.vulnerability_scan.critical,
        report.vulnerability_scan.high,
        report.vulnerability_scan.moderate,
        report.vulnerability_scan.low,
        report.vulnerability_scan.info,
        report.vulnerability_scan.misconfigurations,
        report.vulnerability_scan.secrets,
        report
            .vulnerability_scan
            .unavailable_reason
            .clone()
            .unwrap_or_else(|| "none".to_string())
    ));
    if !report.vulnerability_scan.packages.is_empty() {
        lines.push(format!(
            "security packages {}",
            report.vulnerability_scan.packages.join(", ")
        ));
    }
    if !report.vulnerability_scan.suggestions.is_empty() {
        lines.push(format!(
            "security suggestions {}",
            report.vulnerability_scan.suggestions.join(" | ")
        ));
    }
    for (idx, detail) in report
        .vulnerability_scan
        .detailed_findings
        .iter()
        .take(3)
        .enumerate()
    {
        lines.push(format!("security finding #{}:", idx + 1));
        for part in detail.lines() {
            lines.push(format!("  {part}"));
        }
    }
    let policy_result = if report.vulnerability_scan.critical > report.critical_threshold
        || report.vulnerability_scan.high > 0
        || report.vulnerability_scan.moderate > 0
    {
        "failed"
    } else if report.fail_on_critical {
        "passed"
    } else {
        "disabled"
    };
    lines.push(format!(
        "security policy result={} fail_on_critical={} critical_threshold={} observed_critical={} observed_high={} observed_moderate={}",
        policy_result,
        report.fail_on_critical,
        report.critical_threshold,
        report.vulnerability_scan.critical,
        report.vulnerability_scan.high,
        report.vulnerability_scan.moderate
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
    if let Some(container) = &report.container_scan {
        lines.push(format!(
            "container scan scanner={} scanned={} total={} critical={} high={} moderate={} low={} info={} misconfigurations={} secrets={} unavailable_reason={}",
            container.scanner,
            container.scanned,
            container.total,
            container.critical,
            container.high,
            container.moderate,
            container.low,
            container.info,
            container.misconfigurations,
            container.secrets,
            container
                .unavailable_reason
                .clone()
                .unwrap_or_else(|| "none".to_string())
        ));
    }
    for note in &report.notes {
        lines.push(format!("note {note}"));
    }
    lines
}

pub fn run_container_image_scan(
    image: &str,
    _config: Option<&SecurityConfig>,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<VulnerabilitySummary> {
    let candidates = [
        (
            "trivy-image",
            format!("trivy image --quiet --format json --scanners vuln,misconfig,secret {image}"),
            ScanParser::Trivy,
        ),
        (
            "grype-image",
            format!("grype {image} -o json"),
            ScanParser::GenericJson,
        ),
    ];

    let mut attempts = Vec::new();
    for (scanner, command, parser) in candidates.iter() {
        attempts.push(format!("{scanner}:{command}"));
        let run = shell::run_allow_failure(command, Path::new("."), env, sandbox)?;
        if command_not_found_in_logs(&run.logs) {
            continue;
        }
        let mut summary = VulnerabilitySummary {
            scanner: (*scanner).to_string(),
            scanned: true,
            command: command.clone(),
            scanner_attempts: attempts.clone(),
            suggestions: vec![
                "Install trivy or grype for container vulnerability scanning".to_string(),
                "Pin a patched base image digest and rebuild".to_string(),
                "Apply remediation updates and republish image".to_string(),
            ],
            ..Default::default()
        };
        parse_scan_output(*parser, &run.logs, &mut summary);
        if summary.packages.is_empty() {
            summary.packages = extract_package_names(&run.logs);
        }
        if summary.total == 0 && !summary.packages.is_empty() {
            summary.total = summary.packages.len() as u32;
        }
        return Ok(summary);
    }

    Ok(VulnerabilitySummary {
        scanner: "none".to_string(),
        scanned: false,
        command: candidates
            .iter()
            .map(|(_, c, _)| c.as_str())
            .collect::<Vec<_>>()
            .join(" || "),
        scanner_attempts: attempts,
        unavailable_reason: Some("no container scanner executable found (trivy/grype)".to_string()),
        suggestions: vec![
            "Install trivy or grype and rerun build".to_string(),
            "If unavailable in CI, configure scanner image/tooling in pipeline".to_string(),
        ],
        ..Default::default()
    })
}

pub fn run_container_tar_scan(
    archive_path: &Path,
    _config: Option<&SecurityConfig>,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<VulnerabilitySummary> {
    let escaped = archive_path.display().to_string().replace('"', "\\\"");
    let candidates = [
        (
            "trivy-image-input",
            format!(
                "trivy image --input \"{escaped}\" --quiet --format json --scanners vuln,misconfig,secret"
            ),
            ScanParser::Trivy,
        ),
        (
            "trivy-fs",
            format!(
                "trivy fs \"{escaped}\" --quiet --format json --scanners vuln,misconfig,secret"
            ),
            ScanParser::Trivy,
        ),
    ];

    let mut attempts = Vec::new();
    for (scanner, command, parser) in candidates.iter() {
        attempts.push(format!("{scanner}:{command}"));
        let run = shell::run_allow_failure(command, Path::new("."), env, sandbox)?;
        if command_not_found_in_logs(&run.logs) {
            continue;
        }
        let mut summary = VulnerabilitySummary {
            scanner: (*scanner).to_string(),
            scanned: true,
            command: command.clone(),
            scanner_attempts: attempts.clone(),
            suggestions: vec![
                "Install trivy to scan image/rootfs archives in CI".to_string(),
                "Regenerate tar artifact from a patched base/runtime".to_string(),
                "Review secret and misconfiguration findings before deploy".to_string(),
            ],
            ..Default::default()
        };
        parse_scan_output(*parser, &run.logs, &mut summary);
        if summary.packages.is_empty() {
            summary.packages = extract_package_names(&run.logs);
        }
        if summary.total == 0 && !summary.packages.is_empty() {
            summary.total = summary.packages.len() as u32;
        }
        return Ok(summary);
    }

    Ok(VulnerabilitySummary {
        scanner: "none".to_string(),
        scanned: false,
        command: candidates
            .iter()
            .map(|(_, c, _)| c.as_str())
            .collect::<Vec<_>>()
            .join(" || "),
        scanner_attempts: attempts,
        unavailable_reason: Some("no archive scanner executable found (trivy)".to_string()),
        suggestions: vec![
            "Install trivy and rerun build".to_string(),
            "If unavailable in CI, configure scanner image/tooling in pipeline".to_string(),
        ],
        ..Default::default()
    })
}

pub fn merge_scan_summaries(summaries: &[VulnerabilitySummary]) -> VulnerabilitySummary {
    let mut out = VulnerabilitySummary::default();
    if summaries.is_empty() {
        return out;
    }

    let mut scanners = Vec::new();
    let mut commands = Vec::new();
    let mut attempts = Vec::new();
    let mut packages = Vec::new();
    let mut suggestions = Vec::new();
    let mut unavailable = Vec::new();
    let mut details = Vec::new();

    for s in summaries {
        if !s.scanner.is_empty() && !scanners.contains(&s.scanner) {
            scanners.push(s.scanner.clone());
        }
        if !s.command.is_empty() && !commands.contains(&s.command) {
            commands.push(s.command.clone());
        }
        for a in &s.scanner_attempts {
            if !attempts.contains(a) {
                attempts.push(a.clone());
            }
        }
        for p in &s.packages {
            if !packages.contains(p) {
                packages.push(p.clone());
            }
        }
        for sug in &s.suggestions {
            if !suggestions.contains(sug) {
                suggestions.push(sug.clone());
            }
        }
        for d in &s.detailed_findings {
            if !details.contains(d) {
                details.push(d.clone());
            }
        }
        if let Some(reason) = &s.unavailable_reason {
            if !unavailable.contains(reason) {
                unavailable.push(reason.clone());
            }
        }

        out.scanned |= s.scanned;
        out.total += s.total;
        out.critical += s.critical;
        out.high += s.high;
        out.moderate += s.moderate;
        out.low += s.low;
        out.info += s.info;
        out.misconfigurations += s.misconfigurations;
        out.secrets += s.secrets;
    }

    packages.sort();
    packages.dedup();
    suggestions.sort();
    suggestions.dedup();

    out.scanner = scanners.join(",");
    out.command = commands.join(" || ");
    out.scanner_attempts = attempts;
    out.packages = packages.into_iter().take(25).collect();
    out.suggestions = suggestions;
    out.detailed_findings = details.into_iter().take(12).collect();
    if !out.scanned && !unavailable.is_empty() {
        out.unavailable_reason = Some(unavailable.join(" | "));
    }
    out
}

fn run_vulnerability_scan(
    language: &str,
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<VulnerabilitySummary> {
    let candidates = scanner_candidates(language, work_dir);
    let mut unavailable = Vec::new();
    let mut attempts = Vec::new();

    for candidate in &candidates {
        attempts.push(format!("{}:{}", candidate.scanner, candidate.command));
        let run = shell::run_allow_failure(candidate.command, work_dir, env, sandbox)?;
        if command_not_found_in_logs(&run.logs) {
            unavailable.push(candidate.scanner.to_string());
            continue;
        }
        let mut summary = VulnerabilitySummary {
            scanner: candidate.scanner.to_string(),
            scanned: true,
            command: candidate.command.to_string(),
            scanner_attempts: attempts.clone(),
            suggestions: default_suggestions(language)
                .into_iter()
                .map(str::to_string)
                .collect(),
            ..Default::default()
        };
        parse_scan_output(candidate.parser, &run.logs, &mut summary);
        let has_findings = summary_has_findings(&summary);
        if !run.success && !has_findings {
            unavailable.push(format!("{}(command-failed)", candidate.scanner));
            continue;
        }
        if summary.packages.is_empty() {
            summary.packages = extract_package_names(&run.logs);
        }
        if summary.total == 0 && !summary.packages.is_empty() {
            summary.total = summary.packages.len() as u32;
        }
        return Ok(summary);
    }

    Ok(VulnerabilitySummary {
        scanner: if unavailable.is_empty() {
            "none".to_string()
        } else {
            unavailable.join(",")
        },
        scanned: false,
        command: candidates
            .iter()
            .map(|c| c.command)
            .collect::<Vec<_>>()
            .join(" || "),
        scanner_attempts: attempts,
        unavailable_reason: Some(format!(
            "no scanner executable found for language={} (attempted: {})",
            language,
            candidates
                .iter()
                .map(|c| c.scanner)
                .collect::<Vec<_>>()
                .join(",")
        )),
        suggestions: default_suggestions(language)
            .into_iter()
            .map(str::to_string)
            .collect(),
        ..Default::default()
    })
}

fn summary_has_findings(summary: &VulnerabilitySummary) -> bool {
    summary.total > 0
        || summary.critical > 0
        || summary.high > 0
        || summary.moderate > 0
        || summary.low > 0
        || summary.info > 0
        || summary.misconfigurations > 0
        || summary.secrets > 0
        || !summary.packages.is_empty()
        || !summary.detailed_findings.is_empty()
}

fn scanner_expected_for_language(language: &str) -> bool {
    matches!(
        language,
        "nodejs"
            | "python"
            | "ruby"
            | "go"
            | "java"
            | "php"
            | "rust"
            | "static"
            | "shell"
            | "c_cpp"
            | "gleam"
            | "elixir"
            | "deno"
            | "dotnet"
    )
}

#[derive(Clone, Copy)]
enum ScanParser {
    NpmAudit,
    PipAudit,
    CargoAudit,
    ComposerAudit,
    DotnetAudit,
    Trivy,
    GenericJson,
}

#[derive(Clone, Copy)]
struct ScannerCandidate {
    scanner: &'static str,
    command: &'static str,
    parser: ScanParser,
}

fn scanner_candidates(language: &str, work_dir: &Path) -> Vec<ScannerCandidate> {
    match language {
        "nodejs" => vec![
            ScannerCandidate {
                scanner: "npm-audit",
                command: "npm audit --json --omit=dev",
                parser: ScanParser::NpmAudit,
            },
            ScannerCandidate {
                scanner: "pnpm-audit",
                command: "pnpm audit --json",
                parser: ScanParser::GenericJson,
            },
            ScannerCandidate {
                scanner: "yarn-npm-audit",
                command: "yarn npm audit --json",
                parser: ScanParser::GenericJson,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "python" => vec![
            ScannerCandidate {
                scanner: "pip-audit",
                command: "pip-audit -f json",
                parser: ScanParser::PipAudit,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "ruby" => vec![
            ScannerCandidate {
                scanner: "bundle-audit",
                command: "bundle audit check --update",
                parser: ScanParser::GenericJson,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "go" => vec![
            ScannerCandidate {
                scanner: "govulncheck",
                command: "govulncheck -json ./...",
                parser: ScanParser::GenericJson,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "java" => {
            let mut out = vec![];
            if work_dir.join("pom.xml").exists() {
                out.push(ScannerCandidate {
                    scanner: "maven-dependency-check",
                    command: "mvn -q -DskipTests org.owasp:dependency-check-maven:check -Dformat=JSON -DfailOnError=false",
                    parser: ScanParser::GenericJson,
                });
            }
            if work_dir.join("build.gradle").exists() || work_dir.join("build.gradle.kts").exists()
            {
                out.push(ScannerCandidate {
                    scanner: "gradle-dependency-check",
                    command: "./gradlew dependencyCheckAnalyze --console=plain -Dorg.gradle.daemon=false",
                    parser: ScanParser::GenericJson,
                });
            }
            out.push(ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            });
            out.push(ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            });
            out
        }
        "php" => vec![
            ScannerCandidate {
                scanner: "composer-audit",
                command: "composer audit --format=json",
                parser: ScanParser::ComposerAudit,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "rust" => vec![
            ScannerCandidate {
                scanner: "cargo-audit",
                command: "cargo audit --json",
                parser: ScanParser::CargoAudit,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "dotnet" => vec![
            ScannerCandidate {
                scanner: "dotnet-audit",
                command: "dotnet list package --vulnerable --include-transitive --format json",
                parser: ScanParser::DotnetAudit,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "deno" => vec![
            ScannerCandidate {
                scanner: "deno-audit",
                command: "deno audit --json",
                parser: ScanParser::GenericJson,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "elixir" => vec![
            ScannerCandidate {
                scanner: "mix-hex-audit",
                command: "mix hex.audit",
                parser: ScanParser::GenericJson,
            },
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        "gleam" | "static" | "shell" | "c_cpp" => vec![
            ScannerCandidate {
                scanner: "trivy-fs",
                command: "trivy fs --quiet --format json --scanners vuln,misconfig,secret .",
                parser: ScanParser::Trivy,
            },
            ScannerCandidate {
                scanner: "osv-scanner",
                command: "osv-scanner scan source -r . --format json",
                parser: ScanParser::GenericJson,
            },
        ],
        _ => vec![],
    }
}

fn default_suggestions(language: &str) -> Vec<&'static str> {
    match language {
        "nodejs" => vec![
            "Install npm or pnpm (Node.js toolchain) and rerun build",
            "Run npm audit fix (or pnpm audit --fix) to remediate vulnerable packages",
            "Install trivy for full filesystem dependency/misconfig/secret scan fallback",
            "Ensure lockfile exists and dependencies are installed",
        ],
        "python" => vec![
            "Install pip-audit: pip install pip-audit",
            "Run pip-audit -f json manually and patch vulnerable packages",
            "Install trivy for framework/runtime fallback scanning",
            "Commit updated requirements/lock files",
        ],
        "ruby" => vec![
            "Install bundler-audit gem and run bundle audit check --update",
            "Install trivy for fallback vuln/misconfig/secret scanning",
            "Update Gemfile.lock with safe versions",
        ],
        "go" => vec![
            "Install govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest",
            "Run govulncheck ./... and update vulnerable modules",
            "Install trivy for fallback scanning coverage",
        ],
        "java" => vec![
            "For Maven use OWASP dependency-check plugin; for Gradle use dependencyCheckAnalyze",
            "Install trivy for fallback scanning across Spring/Maven/Gradle projects",
            "Run scanner on pom.xml/gradle dependencies and update vulnerable artifacts",
        ],
        "php" => vec![
            "Use composer audit --format=json and update composer.lock",
            "Install trivy or osv-scanner as fallback scanners",
        ],
        "rust" => vec![
            "Install cargo-audit: cargo install cargo-audit",
            "Run cargo audit --json and patch vulnerable crates",
            "Install trivy for fallback scanning coverage",
        ],
        "dotnet" => vec![
            "Run dotnet list package --vulnerable --include-transitive --format json",
            "Install trivy for fallback scanning across .NET projects",
            "Upgrade vulnerable NuGet packages",
        ],
        _ => vec![
            "Install trivy and/or osv-scanner and rerun build",
            "Provide a custom [scan].command for your ecosystem",
        ],
    }
}

fn parse_scan_output(parser: ScanParser, logs: &[String], summary: &mut VulnerabilitySummary) {
    let raw = collect_json(logs);
    let Some(raw) = raw else {
        return;
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    match parser {
        ScanParser::NpmAudit => parse_npm_audit_value(&val, summary),
        ScanParser::PipAudit => parse_pip_audit_value(&val, summary),
        ScanParser::CargoAudit => parse_cargo_audit_value(&val, summary),
        ScanParser::ComposerAudit => parse_composer_audit_value(&val, summary),
        ScanParser::DotnetAudit => parse_dotnet_audit_value(&val, summary),
        ScanParser::Trivy => parse_trivy_value(&val, summary),
        ScanParser::GenericJson => parse_generic_vuln_json(&val, summary),
    }
}

fn parse_trivy_value(val: &Value, summary: &mut VulnerabilitySummary) {
    let Some(results) = val.get("Results").and_then(Value::as_array) else {
        return;
    };
    let mut packages = Vec::new();

    for result in results {
        if let Some(vulns) = result.get("Vulnerabilities").and_then(Value::as_array) {
            for vuln in vulns {
                summary.total += 1;
                if let Some(sev) = vuln.get("Severity").and_then(Value::as_str) {
                    bump_severity(summary, sev);
                }
                if let Some(name) = vuln
                    .get("PkgName")
                    .and_then(Value::as_str)
                    .or_else(|| vuln.get("PkgID").and_then(Value::as_str))
                {
                    packages.push(name.to_string());
                }
            }
        }
        if let Some(misconfigs) = result.get("Misconfigurations").and_then(Value::as_array) {
            for mis in misconfigs {
                summary.total += 1;
                summary.misconfigurations += 1;
                if let Some(sev) = mis.get("Severity").and_then(Value::as_str) {
                    bump_severity(summary, sev);
                }
                if let Some(id) = mis
                    .get("ID")
                    .and_then(Value::as_str)
                    .or_else(|| mis.get("Type").and_then(Value::as_str))
                {
                    packages.push(id.to_string());
                }
            }
        }
        if let Some(secrets) = result.get("Secrets").and_then(Value::as_array) {
            for secret in secrets {
                summary.total += 1;
                summary.secrets += 1;
                if let Some(sev) = secret.get("Severity").and_then(Value::as_str) {
                    bump_severity(summary, sev);
                } else {
                    summary.high += 1;
                }
                if let Some(rule) = secret.get("RuleID").and_then(Value::as_str) {
                    packages.push(rule.to_string());
                }
            }
        }
    }

    packages.sort();
    packages.dedup();
    summary.packages = packages.into_iter().take(25).collect();
}

fn bump_severity(summary: &mut VulnerabilitySummary, severity: &str) {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => summary.critical += 1,
        "high" => summary.high += 1,
        "medium" | "moderate" => summary.moderate += 1,
        "low" => summary.low += 1,
        "info" | "informational" | "unknown" => summary.info += 1,
        _ => {}
    }
}

fn parse_npm_audit_value(val: &Value, summary: &mut VulnerabilitySummary) {
    let meta = val.get("metadata").and_then(|m| m.get("vulnerabilities"));
    summary.critical = to_u32(meta.and_then(|v| v.get("critical")));
    summary.high = to_u32(meta.and_then(|v| v.get("high")));
    summary.moderate = to_u32(meta.and_then(|v| v.get("moderate")));
    summary.low = to_u32(meta.and_then(|v| v.get("low")));
    summary.info = to_u32(meta.and_then(|v| v.get("info")));
    summary.total = summary.critical + summary.high + summary.moderate + summary.low + summary.info;
    if let Some(vulns) = val.get("vulnerabilities").and_then(Value::as_object) {
        summary.packages = vulns.keys().take(10).map(|k| k.to_string()).collect();
        summary.detailed_findings = render_npm_findings(vulns, 6);
    }
}

fn render_npm_findings(vulns: &serde_json::Map<String, Value>, max_packages: usize) -> Vec<String> {
    let mut out = Vec::new();
    for (name, info) in vulns.iter().take(max_packages) {
        let severity = info
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_uppercase();
        let source = guess_npm_lockfile_source(info);
        let upgrade = npm_upgrade_hint(name, info);
        let vulnerabilities = npm_cve_lines(info, 6);

        let mut entry = format!("{name}\n  Source: {source}\n  Severity: {severity}\n  {upgrade}");
        if !vulnerabilities.is_empty() {
            entry.push_str("\n\n  Vulnerabilities:");
            for line in vulnerabilities {
                entry.push_str(&format!("\n  - {line}"));
            }
        }
        out.push(entry);
    }
    out
}

fn guess_npm_lockfile_source(info: &Value) -> String {
    if info.get("nodes").is_some() || info.get("effects").is_some() {
        return "package-lock.json".to_string();
    }
    "dependency lockfile".to_string()
}

fn npm_upgrade_hint(name: &str, info: &Value) -> String {
    match info.get("fixAvailable") {
        Some(Value::Bool(true)) => format!("Upgrade: npm install {name}@latest"),
        Some(Value::Bool(false)) => "Upgrade: no automatic fix available".to_string(),
        Some(Value::Object(o)) => {
            let fixed_name = o.get("name").and_then(Value::as_str).unwrap_or(name);
            let fixed_ver = o.get("version").and_then(Value::as_str).unwrap_or("latest");
            format!("Upgrade to {fixed_ver}: npm install {fixed_name}@^{fixed_ver}")
        }
        _ => format!("Upgrade: run npm audit fix or npm install {name}@latest"),
    }
}

fn npm_cve_lines(info: &Value, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let Some(via) = info.get("via").and_then(Value::as_array) else {
        return out;
    };
    for item in via.iter().take(max_items) {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let id = obj
            .get("source")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                obj.get("name")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                obj.get("title")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| "advisory".to_string());
        let sev = obj
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_uppercase();
        let url = obj.get("url").and_then(Value::as_str).unwrap_or("no-url");
        out.push(format!("{id} ({sev}): {url}"));
    }
    out
}

fn format_policy_violation_with_findings(
    summary: &VulnerabilitySummary,
    critical_threshold: u32,
) -> String {
    let mut msg = format!(
        "security policy violation: critical vulnerabilities {} exceed threshold {}.",
        summary.critical, critical_threshold
    );
    if !summary.detailed_findings.is_empty() {
        msg.push_str(&format!(
            "\n\nFound {} vulnerable package(s):\n\n",
            summary.detailed_findings.len()
        ));
        for finding in summary.detailed_findings.iter().take(6) {
            msg.push_str(finding);
            msg.push('\n');
            msg.push('\n');
        }
    } else if !summary.packages.is_empty() {
        msg.push_str(&format!("\n\nPackages: {}", summary.packages.join(", ")));
    }
    msg.trim_end().to_string()
}

fn format_policy_violation_disallow_high_moderate(summary: &VulnerabilitySummary) -> String {
    let mut msg = format!(
        "security policy violation: HIGH/MODERATE vulnerabilities are not allowed. observed_high={} observed_moderate={}.",
        summary.high, summary.moderate
    );
    if !summary.detailed_findings.is_empty() {
        msg.push_str(&format!(
            "\n\nFound {} vulnerable package(s):\n\n",
            summary.detailed_findings.len()
        ));
        for finding in summary.detailed_findings.iter().take(6) {
            msg.push_str(finding);
            msg.push('\n');
            msg.push('\n');
        }
    } else if !summary.packages.is_empty() {
        msg.push_str(&format!("\n\nPackages: {}", summary.packages.join(", ")));
    }
    msg.trim_end().to_string()
}

fn parse_pip_audit_value(val: &Value, summary: &mut VulnerabilitySummary) {
    if let Some(arr) = val.as_array() {
        let mut packages = Vec::new();
        let mut total = 0u32;
        for item in arr {
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                packages.push(name.to_string());
            }
            total += item
                .get("vulns")
                .and_then(Value::as_array)
                .map(|v| v.len() as u32)
                .unwrap_or(0);
        }
        packages.sort();
        packages.dedup();
        summary.packages = packages;
        summary.total = total.max(summary.packages.len() as u32);
    }
}

fn parse_cargo_audit_value(val: &Value, summary: &mut VulnerabilitySummary) {
    if let Some(list) = val
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array)
    {
        summary.total = list.len() as u32;
        summary.critical = summary.total;
        let mut packages = Vec::new();
        for item in list {
            if let Some(name) = item
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
            {
                packages.push(name.to_string());
            }
        }
        packages.sort();
        packages.dedup();
        summary.packages = packages;
    }
}

fn parse_composer_audit_value(val: &Value, summary: &mut VulnerabilitySummary) {
    if let Some(advisories) = val.get("advisories").and_then(Value::as_object) {
        summary.packages = advisories.keys().take(10).map(|k| k.to_string()).collect();
        summary.total = advisories
            .values()
            .filter_map(Value::as_array)
            .map(|a| a.len() as u32)
            .sum();
    }
}

fn parse_dotnet_audit_value(val: &Value, summary: &mut VulnerabilitySummary) {
    summary.packages = collect_named_values(val, &["name", "packageName", "id"]);
    let vuln_count = collect_named_values(val, &["severity", "advisoryUrl"]).len() as u32;
    summary.total = vuln_count.max(summary.packages.len() as u32);
    apply_severity_counts_from_json(val, summary);
}

fn parse_generic_vuln_json(val: &Value, summary: &mut VulnerabilitySummary) {
    summary.packages =
        collect_named_values(val, &["package", "name", "module", "crate", "dependency"]);
    summary.total = summary.packages.len() as u32;
    apply_severity_counts_from_json(val, summary);
    if summary.total
        < (summary.critical + summary.high + summary.moderate + summary.low + summary.info)
    {
        summary.total =
            summary.critical + summary.high + summary.moderate + summary.low + summary.info;
    }
}

fn apply_severity_counts_from_json(val: &Value, summary: &mut VulnerabilitySummary) {
    let severities = collect_named_values(val, &["severity"]);
    for sev in severities {
        match sev.to_lowercase().as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" | "moderate" => summary.moderate += 1,
            "low" => summary.low += 1,
            "info" | "informational" => summary.info += 1,
            _ => {}
        }
    }
}

fn extract_package_names(logs: &[String]) -> Vec<String> {
    let raw = collect_json(logs);
    let Some(raw) = raw else {
        return Vec::new();
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    collect_named_values(&val, &["package", "name", "module", "crate", "dependency"])
}

fn collect_named_values(root: &Value, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    collect_named_values_recursive(root, keys, &mut out);
    out.sort();
    out.dedup();
    out.into_iter().take(15).collect()
}

fn collect_named_values_recursive(root: &Value, keys: &[&str], out: &mut Vec<String>) {
    match root {
        Value::Object(map) => {
            for (k, v) in map {
                if keys.iter().any(|needle| k.eq_ignore_ascii_case(needle)) {
                    if let Some(s) = v.as_str() {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            out.push(trimmed.to_string());
                        }
                    }
                }
                collect_named_values_recursive(v, keys, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_named_values_recursive(item, keys, out);
            }
        }
        _ => {}
    }
}

fn command_not_found_in_logs(logs: &[String]) -> bool {
    logs.iter().any(|line| {
        let lower = line.to_lowercase();
        lower.contains("not recognized as an internal or external command")
            || lower.contains("command not found")
            || lower.contains("no such file or directory")
            || lower.contains("is not installed")
    })
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
    let alias = if old_tokens.len() >= 4 && old_tokens[2].eq_ignore_ascii_case("as") {
        Some(old_tokens[3].to_string())
    } else {
        None
    };
    let mut runtime_rewritten = false;
    if language == "nodejs" {
        let Some(changed) =
            ensure_distroless_compatible_node_runtime(&mut lines, from_idx, work_dir)
        else {
            return Ok(out);
        };
        runtime_rewritten = changed;
    }
    if old_base.contains("distroless") {
        if runtime_rewritten {
            fs::write(&dockerfile, lines.join("\n"))?;
        }
        return Ok(out);
    }
    lines[from_idx] = match alias {
        Some(a) => format!("FROM {desired} AS {a}"),
        None => format!("FROM {desired}"),
    };
    fs::write(&dockerfile, lines.join("\n"))?;
    out.switched = true;
    Ok(out)
}

fn ensure_distroless_compatible_node_runtime(
    lines: &mut [String],
    from_idx: usize,
    work_dir: &Path,
) -> Option<bool> {
    let Some((cmd_idx, directive, mut tokens)) = find_stage_runtime_command(lines, from_idx) else {
        return Some(false);
    };
    if !tokens_use_node_package_manager(&tokens) {
        return Some(false);
    }
    if !directive.eq_ignore_ascii_case("CMD") {
        return None;
    }
    let Some(rewritten) = rewrite_node_runtime_tokens_for_distroless(&tokens, work_dir) else {
        return None;
    };
    tokens = rewritten;
    let cmd_json = tokens
        .iter()
        .map(|v| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let rewritten_line = format!("CMD [{cmd_json}]");
    if lines[cmd_idx] != rewritten_line {
        lines[cmd_idx] = rewritten_line;
        Some(true)
    } else {
        Some(false)
    }
}

fn find_stage_runtime_command(
    lines: &[String],
    from_idx: usize,
) -> Option<(usize, String, Vec<String>)> {
    let mut out: Option<(usize, String, Vec<String>)> = None;
    for (idx, raw) in lines.iter().enumerate().skip(from_idx + 1) {
        let line = raw.trim();
        if line.to_uppercase().starts_with("FROM ") {
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_uppercase().starts_with("CMD ") {
            if let Some(tokens) = parse_container_command_tokens(line, "CMD") {
                out = Some((idx, "CMD".to_string(), tokens));
            }
        } else if line.to_uppercase().starts_with("ENTRYPOINT ") {
            if let Some(tokens) = parse_container_command_tokens(line, "ENTRYPOINT") {
                out = Some((idx, "ENTRYPOINT".to_string(), tokens));
            }
        }
    }
    out
}

fn parse_container_command_tokens(line: &str, directive: &str) -> Option<Vec<String>> {
    let rest = line.trim().strip_prefix(directive)?.trim();
    if rest.starts_with('[') {
        serde_json::from_str::<Vec<String>>(rest).ok()
    } else {
        let out = rest
            .split_whitespace()
            .map(|v| v.trim_matches('"').trim_matches('\'').to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

fn tokens_use_node_package_manager(tokens: &[String]) -> bool {
    let first = tokens.first().map(|v| v.to_lowercase()).unwrap_or_default();
    matches!(first.as_str(), "pnpm" | "npm" | "yarn" | "npx" | "corepack")
}

fn rewrite_node_runtime_tokens_for_distroless(
    tokens: &[String],
    work_dir: &Path,
) -> Option<Vec<String>> {
    if tokens.is_empty() {
        return None;
    }
    let first = tokens[0].to_lowercase();
    if first == "npx" && tokens.len() >= 3 && tokens[1].eq_ignore_ascii_case("next") {
        return rewrite_next_start_tokens(&tokens[1..]);
    }
    if (first == "pnpm" || first == "npm" || first == "yarn") && tokens.len() >= 2 {
        if first == "pnpm" && tokens[1].eq_ignore_ascii_case("exec") && tokens.len() >= 4 {
            return rewrite_next_start_tokens(&tokens[2..]);
        }
        if first == "yarn" && tokens[1].eq_ignore_ascii_case("next") && tokens.len() >= 3 {
            return rewrite_next_start_tokens(&tokens[1..]);
        }

        let script_name = if tokens[1].eq_ignore_ascii_case("run") {
            tokens.get(2).map(String::as_str)
        } else {
            tokens.get(1).map(String::as_str)
        };
        if let Some(name) = script_name {
            return rewrite_script_name_for_distroless(work_dir, name);
        }
    }
    None
}

fn rewrite_script_name_for_distroless(work_dir: &Path, script_name: &str) -> Option<Vec<String>> {
    let raw = fs::read_to_string(work_dir.join("package.json")).ok()?;
    let parsed = serde_json::from_str::<Value>(&raw).ok()?;
    let script = parsed
        .get("scripts")
        .and_then(|s| s.get(script_name))
        .and_then(Value::as_str)?
        .trim()
        .to_string();
    rewrite_script_command_for_distroless(&script)
}

fn rewrite_script_command_for_distroless(script: &str) -> Option<Vec<String>> {
    let trimmed = script.trim();
    if let Some(rest) = trimmed.strip_prefix("node ") {
        let out = rest
            .split_whitespace()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if out.is_empty() {
            return None;
        }
        return Some(out);
    }
    if let Some(idx) = trimmed.to_lowercase().find("next start") {
        let tail = trimmed[idx..].split_whitespace().collect::<Vec<_>>();
        if !tail.is_empty() {
            return rewrite_next_start_tokens(
                &tail.iter().map(|v| (*v).to_string()).collect::<Vec<_>>(),
            );
        }
    }
    None
}

fn rewrite_next_start_tokens(tokens: &[String]) -> Option<Vec<String>> {
    if tokens.len() < 2 {
        return None;
    }
    if !tokens[0].eq_ignore_ascii_case("next") || !tokens[1].eq_ignore_ascii_case("start") {
        return None;
    }
    let mut out = vec![
        "node_modules/next/dist/bin/next".to_string(),
        "start".to_string(),
    ];
    out.extend(tokens.iter().skip(2).cloned());
    Some(out)
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
        "specVersion": CYCLONEDX_SPEC_VERSION,
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

#[cfg(test)]
mod tests {
    use super::{
        collect_json, normalize_language, summary_has_findings, to_u32, VulnerabilitySummary,
    };
    use serde_json::json;

    #[test]
    fn collect_json_extracts_object_payload() {
        let logs = vec![
            "stdout: some prefix".to_string(),
            "stdout: {\"a\":1}".to_string(),
            "stderr: trailing".to_string(),
        ];
        assert_eq!(collect_json(&logs).as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn collect_json_extracts_array_payload() {
        let logs = vec![
            "stdout: noise".to_string(),
            "stdout: [{\"id\":1}]".to_string(),
            "stdout: more".to_string(),
        ];
        assert_eq!(collect_json(&logs).as_deref(), Some("[{\"id\":1}]"));
    }

    #[test]
    fn to_u32_handles_string_values() {
        let v = json!("42");
        assert_eq!(to_u32(Some(&v)), 42);
    }

    #[test]
    fn normalize_language_maps_alias() {
        assert_eq!(normalize_language("golang"), "go");
    }

    #[test]
    fn summary_has_findings_detects_empty_summary() {
        let summary = VulnerabilitySummary::default();
        assert!(!summary_has_findings(&summary));
    }

    #[test]
    fn summary_has_findings_detects_nonempty_summary() {
        let summary = VulnerabilitySummary {
            high: 1,
            ..Default::default()
        };
        assert!(summary_has_findings(&summary));
    }
}
