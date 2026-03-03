use anyhow::Result;
use chrono::Local;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::core::IntelligenceConfig;
use crate::runtime::shell;

#[derive(Debug, Clone, Serialize, Default)]
pub struct DependencyIntelligenceReport {
    pub generated_at: String,
    pub language: String,
    pub summary: IntelligenceSummary,
    pub outdated_packages: Vec<OutdatedPackage>,
    pub lighter_alternatives: Vec<AlternativeSuggestion>,
    pub optimization_hints: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IntelligenceSummary {
    pub total_dependencies: usize,
    pub unique_dependencies: usize,
    pub duplicate_packages: usize,
    pub max_tree_depth: usize,
    pub outdated_count: usize,
    pub health_score: u32,
    pub health_grade: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutdatedPackage {
    pub name: String,
    pub current: String,
    pub wanted: String,
    pub latest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlternativeSuggestion {
    pub package: String,
    pub suggested_alternative: String,
    pub reason: String,
}

pub fn enabled(config: Option<&IntelligenceConfig>) -> bool {
    config.and_then(|c| c.enabled).unwrap_or(true)
}

pub fn run(
    language: &str,
    _config: Option<&IntelligenceConfig>,
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<DependencyIntelligenceReport> {
    let normalized = normalize_language(language);
    let mut report = DependencyIntelligenceReport {
        generated_at: Local::now().to_rfc3339(),
        language: normalized.clone(),
        ..Default::default()
    };

    match normalized.as_str() {
        "nodejs" => analyze_nodejs(&mut report, work_dir, env, sandbox)?,
        _ => {
            report.notes.push(format!(
                "dependency intelligence currently provides deep analysis for nodejs; language={} gets baseline hints only",
                normalized
            ));
            report.optimization_hints = vec![
                "Pin dependency versions and commit the lockfile for reproducible builds."
                    .to_string(),
                "Remove unused dependencies and keep runtime dependencies minimal.".to_string(),
                "Schedule dependency updates to reduce security and compatibility drift."
                    .to_string(),
            ];
            report.summary.health_score = 78;
            report.summary.health_grade = grade_for_score(report.summary.health_score);
        }
    }

    if report.summary.health_grade.is_empty() {
        report.summary.health_grade = grade_for_score(report.summary.health_score);
    }
    Ok(report)
}

pub fn to_build_logs(report: &DependencyIntelligenceReport) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "dependency intelligence summary total={} unique={} duplicates={} depth={} outdated={} health={}({})",
        report.summary.total_dependencies,
        report.summary.unique_dependencies,
        report.summary.duplicate_packages,
        report.summary.max_tree_depth,
        report.summary.outdated_count,
        report.summary.health_score,
        report.summary.health_grade
    ));

    for outdated in report.outdated_packages.iter().take(10) {
        lines.push(format!(
            "outdated {} current={} wanted={} latest={}",
            outdated.name, outdated.current, outdated.wanted, outdated.latest
        ));
    }
    if report.outdated_packages.len() > 10 {
        lines.push(format!(
            "outdated list truncated: {} additional package(s)",
            report.outdated_packages.len() - 10
        ));
    }

    for suggestion in &report.lighter_alternatives {
        lines.push(format!(
            "lighter alternative {} -> {} ({})",
            suggestion.package, suggestion.suggested_alternative, suggestion.reason
        ));
    }

    for hint in &report.optimization_hints {
        lines.push(format!("optimization hint {hint}"));
    }
    for note in &report.notes {
        lines.push(format!("note {note}"));
    }
    lines
}

fn analyze_nodejs(
    report: &mut DependencyIntelligenceReport,
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<()> {
    let mut name_counts: HashMap<String, usize> = HashMap::new();
    let mut unique = HashSet::new();
    let mut total = 0usize;
    let mut max_depth = 0usize;
    let mut direct_dependencies = HashSet::new();

    if let Some(pkg) = read_json(work_dir.join("package.json").as_path()) {
        collect_direct_dependencies(&pkg, "dependencies", &mut direct_dependencies);
        collect_direct_dependencies(&pkg, "devDependencies", &mut direct_dependencies);
    } else {
        report.notes.push(
            "package.json not found or invalid; direct dependency hints may be incomplete"
                .to_string(),
        );
    }

    if !collect_tree_from_lockfile(
        work_dir,
        &mut total,
        &mut unique,
        &mut name_counts,
        &mut max_depth,
    ) {
        // Fallback to shallow tree only; full depth is too slow on large repos.
        let tree_run = shell::run_allow_failure("npm ls --json --depth=1", work_dir, env, sandbox)?;
        if let Some(raw_json) = collect_json(&tree_run.logs) {
            if let Ok(tree) = serde_json::from_str::<Value>(&raw_json) {
                walk_dependency_tree(
                    &tree,
                    0,
                    &mut total,
                    &mut unique,
                    &mut name_counts,
                    &mut max_depth,
                );
            } else {
                report.notes.push(
                    "npm ls output was not valid json; dependency tree stats are partial"
                        .to_string(),
                );
            }
        } else {
            report.notes.push(
                "npm ls produced no json output; dependency tree stats are partial".to_string(),
            );
        }
        if !tree_run.success {
            report.notes.push(format!(
                "npm ls exited with {:?}; this often indicates peer/optional dependency issues",
                tree_run.exit_code
            ));
        }
    } else {
        report
            .notes
            .push("tree stats derived from lockfile for faster analysis".to_string());
    }

    let outdated = if direct_dependencies.len() <= 60 {
        let cmd = "npm outdated --json --depth=0 --omit=dev";
        let outdated_run = shell::run_allow_failure(cmd, work_dir, env, sandbox)?;
        let parsed = parse_npm_outdated(&outdated_run.logs);
        if !outdated_run.success && parsed.is_empty() {
            report.notes.push(format!(
                "npm outdated exited with {:?}; continuing with available data",
                outdated_run.exit_code
            ));
        }
        parsed
    } else {
        report.notes.push(format!(
            "skipped npm outdated in fast mode (direct dependencies={})",
            direct_dependencies.len()
        ));
        Vec::new()
    };

    let duplicate_packages = name_counts.values().filter(|v| **v > 1).count();
    report.summary.total_dependencies = total;
    report.summary.unique_dependencies = unique.len();
    report.summary.max_tree_depth = max_depth;
    report.summary.duplicate_packages = duplicate_packages;
    report.summary.outdated_count = outdated.len();
    report.outdated_packages = outdated;
    report.lighter_alternatives = find_lighter_alternatives(&direct_dependencies);
    report.optimization_hints = generate_node_hints(report);
    report.summary.health_score = compute_health_score(report);
    report.summary.health_grade = grade_for_score(report.summary.health_score);

    Ok(())
}

fn collect_direct_dependencies(pkg: &Value, field: &str, deps: &mut HashSet<String>) {
    if let Some(map) = pkg.get(field).and_then(Value::as_object) {
        for key in map.keys() {
            deps.insert(key.to_string());
        }
    }
}

fn walk_dependency_tree(
    node: &Value,
    depth: usize,
    total: &mut usize,
    unique: &mut HashSet<String>,
    name_counts: &mut HashMap<String, usize>,
    max_depth: &mut usize,
) {
    if let Some(name) = node.get("name").and_then(Value::as_str) {
        *total += 1;
        unique.insert(name.to_string());
        *name_counts.entry(name.to_string()).or_insert(0) += 1;
        *max_depth = (*max_depth).max(depth);
    }

    if let Some(deps) = node.get("dependencies").and_then(Value::as_object) {
        for dep in deps.values() {
            walk_dependency_tree(dep, depth + 1, total, unique, name_counts, max_depth);
        }
    }
}

fn parse_npm_outdated(logs: &[String]) -> Vec<OutdatedPackage> {
    let mut items = Vec::new();
    let Some(raw_json) = collect_json(logs) else {
        return items;
    };
    let Ok(parsed) = serde_json::from_str::<Value>(&raw_json) else {
        return items;
    };
    let Some(map) = parsed.as_object() else {
        return items;
    };

    for (name, details) in map {
        let current = details
            .get("current")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let wanted = details
            .get("wanted")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let latest = details
            .get("latest")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        if is_probably_newer(&latest, &current) {
            items.push(OutdatedPackage {
                name: name.to_string(),
                current,
                wanted,
                latest,
            });
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    items
}

fn find_lighter_alternatives(direct_dependencies: &HashSet<String>) -> Vec<AlternativeSuggestion> {
    let rules = [
        (
            "moment",
            "dayjs or date-fns",
            "smaller modern date libraries with tree-shaking support",
        ),
        (
            "lodash",
            "lodash-es or native utilities",
            "reduce bundle size by importing only used helpers",
        ),
        (
            "axios",
            "fetch API or undici",
            "native/runtime HTTP clients can reduce dependency weight",
        ),
        (
            "request",
            "node-fetch or undici",
            "request is deprecated and heavier than modern alternatives",
        ),
        (
            "uuid",
            "crypto.randomUUID",
            "built-in uuid generation on modern Node runtimes",
        ),
        (
            "chalk",
            "picocolors",
            "smaller CLI color library with minimal overhead",
        ),
    ];

    let mut out = Vec::new();
    for (pkg, alternative, reason) in rules {
        if direct_dependencies.contains(pkg) {
            out.push(AlternativeSuggestion {
                package: pkg.to_string(),
                suggested_alternative: alternative.to_string(),
                reason: reason.to_string(),
            });
        }
    }
    out
}

fn generate_node_hints(report: &DependencyIntelligenceReport) -> Vec<String> {
    let mut hints = Vec::new();
    if report.summary.outdated_count > 0 {
        hints.push(
            "Run `npm update` (or targeted upgrades) and validate lockfile changes in CI."
                .to_string(),
        );
    }
    if report.summary.duplicate_packages > 0 {
        hints.push(
            "Run `npm dedupe` to flatten repeated packages and reduce install size.".to_string(),
        );
    }
    if report.summary.max_tree_depth >= 7 {
        hints.push(
            "Dependency tree is deep; prefer flatter libraries to reduce transitive risk."
                .to_string(),
        );
    }
    if report.summary.total_dependencies >= 250 {
        hints.push("Large dependency footprint detected; remove unused packages and avoid meta-framework plugin sprawl.".to_string());
    }
    if report.lighter_alternatives.is_empty() && report.summary.outdated_count == 0 {
        hints.push(
            "Dependency set looks stable; continue periodic upgrades to avoid version drift."
                .to_string(),
        );
    }
    hints
}

fn compute_health_score(report: &DependencyIntelligenceReport) -> u32 {
    let mut score = 100i32;
    score -= (report.summary.outdated_count as i32 * 3).min(30);
    score -= (report.summary.duplicate_packages as i32 * 2).min(20);
    if report.summary.max_tree_depth > 6 {
        score -= ((report.summary.max_tree_depth as i32 - 6) * 2).min(20);
    }
    if report.summary.total_dependencies > 200 {
        score -= (((report.summary.total_dependencies as i32 - 200) / 10) * 2).min(20);
    }
    score = score.clamp(0, 100);
    score as u32
}

fn grade_for_score(score: u32) -> String {
    match score {
        90..=100 => "A".to_string(),
        80..=89 => "B".to_string(),
        70..=79 => "C".to_string(),
        60..=69 => "D".to_string(),
        _ => "F".to_string(),
    }
}

fn read_json(path: &Path) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&raw).ok()
}

fn is_probably_newer(latest: &str, current: &str) -> bool {
    let clean = |v: &str| {
        v.trim()
            .trim_start_matches(['^', '~', 'v', '='])
            .split('-')
            .next()
            .unwrap_or("")
            .to_string()
    };
    let latest_parts = clean(latest)
        .split('.')
        .filter_map(|v| v.parse::<u32>().ok())
        .collect::<Vec<_>>();
    let current_parts = clean(current)
        .split('.')
        .filter_map(|v| v.parse::<u32>().ok())
        .collect::<Vec<_>>();

    if latest_parts.is_empty() || current_parts.is_empty() {
        return latest != current;
    }
    for i in 0..latest_parts.len().max(current_parts.len()) {
        let l = *latest_parts.get(i).unwrap_or(&0);
        let c = *current_parts.get(i).unwrap_or(&0);
        if l > c {
            return true;
        }
        if l < c {
            return false;
        }
    }
    false
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

    let start = body.find('{')?;
    let end = body.rfind('}')?;
    if end <= start {
        return None;
    }
    Some(body[start..=end].to_string())
}

fn collect_tree_from_lockfile(
    work_dir: &Path,
    total: &mut usize,
    unique: &mut HashSet<String>,
    name_counts: &mut HashMap<String, usize>,
    max_depth: &mut usize,
) -> bool {
    let lockfile = work_dir.join("package-lock.json");
    if !lockfile.exists() {
        return false;
    }
    let Some(lock) = read_json(&lockfile) else {
        return false;
    };
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        return false;
    };

    for (path, entry) in packages {
        if path.is_empty() {
            continue;
        }
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| path.rsplit('/').next())
            .unwrap_or("unknown");
        *total += 1;
        unique.insert(name.to_string());
        *name_counts.entry(name.to_string()).or_insert(0) += 1;
        let depth = path.matches("node_modules/").count();
        *max_depth = (*max_depth).max(depth);
    }
    true
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
        other => other.to_string(),
    }
}
