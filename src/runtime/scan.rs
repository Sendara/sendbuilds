use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::core::ScanConfig;
use crate::runtime::shell::{self, ShellRunOutput};

pub fn run(
    language: &str,
    config: Option<&ScanConfig>,
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<ShellRunOutput> {
    if let Some(custom) = config.and_then(|c| c.command.as_deref()) {
        return shell::run(custom, work_dir, env, sandbox);
    }

    match normalize_language(language).as_str() {
        "nodejs" => run_node_scan(work_dir, env, sandbox),
        "python" => shell::run("pip-audit -f json", work_dir, env, sandbox),
        "ruby" => shell::run("bundle audit check --update", work_dir, env, sandbox),
        "go" => shell::run("govulncheck ./...", work_dir, env, sandbox),
        "rust" => shell::run("cargo audit", work_dir, env, sandbox),
        "java" => shell::run(
            "echo security scan skipped: configure scanner for java",
            work_dir,
            env,
            sandbox,
        ),
        "php" => shell::run(
            "echo security scan skipped: configure scanner for php",
            work_dir,
            env,
            sandbox,
        ),
        _ => shell::run(
            "echo security scan skipped (no scanner configured)",
            work_dir,
            env,
            sandbox,
        ),
    }
}

pub fn enabled(config: Option<&ScanConfig>) -> bool {
    config.and_then(|c| c.enabled).unwrap_or(true)
}

fn run_node_scan(
    work_dir: &Path,
    env: &HashMap<String, String>,
    sandbox: bool,
) -> Result<ShellRunOutput> {
    let cmd = "npm audit --json --omit=dev --audit-level=high";
    let run = shell::run_allow_failure(cmd, work_dir, env, sandbox)?;
    if run.success {
        return Ok(run);
    }

    let summary = parse_npm_audit_summary(&run.logs);
    if summary.is_empty() {
        bail!(
            "security scan failed. command=`{}` exit={:?}. suggestion: run `npm audit fix` or review lockfile changes.",
            cmd,
            run.exit_code
        );
    }

    bail!(
        "security scan failed. command=`{}` exit={:?}. {}",
        cmd,
        run.exit_code,
        summary
    )
}

fn parse_npm_audit_summary(logs: &[String]) -> String {
    let json_raw = collect_json(logs);
    let Some(raw) = json_raw else {
        return String::new();
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

    let Some(vulns) = parsed.get("vulnerabilities").and_then(Value::as_object) else {
        return String::new();
    };
    if vulns.is_empty() {
        return String::new();
    }

    let mut packages = Vec::new();
    for (name, info) in vulns.iter().take(8) {
        let severity = info
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let fix = match info.get("fixAvailable") {
            Some(Value::Bool(true)) => "fix:available".to_string(),
            Some(Value::Bool(false)) => "fix:none".to_string(),
            Some(Value::Object(o)) => {
                let n = o.get("name").and_then(Value::as_str).unwrap_or("upgrade");
                format!("fix:{n}")
            }
            _ => "fix:unknown".to_string(),
        };
        packages.push(format!("{name}({severity},{fix})"));
    }

    let actions = "suggestions: 1) npm audit fix 2) update vulnerable packages/lockfile 3) if blocked, pin safe versions and rebuild cache";
    format!("vulnerable packages: {}. {}", packages.join(", "), actions)
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
