use chrono::Local;
use colored::Colorize;

use crate::core::Step;

const BANNER: &str = r#" _____  ______ _   _ _____  ____  _    _ _____ _      _____  
/ ____|/ ____| \ | |  __ \|  _ \| |  | |_   _| |    |  __ \ 
| (___ | |    |  \| | |  | | |_) | |  | | | | | |    | |  | |
 \___ \| |    | . ` | |  | |  _ <| |  | | | | | |    | |  | |
 ____) | |____| |\  | |__| | |_) | |__| |_| |_| |____| |__| |
|_____/ \_____|_| \_|_____/|____/ \____/|_____|______|_____/ "#;

fn ts() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

fn emit(level: &str, msg: &str) {
    let level_padded = format!("{level:<5}");
    let styled_level = match level {
        "INFO" => level_padded.blue().bold(),
        "WARN" => level_padded.yellow().bold(),
        "ERROR" => level_padded.red().bold(),
        _ => level_padded.normal(),
    };
    println!("[{}] {} | {}", ts().dimmed(), styled_level, msg);
}

fn classify_line(line: &str) -> &'static str {
    let lower = line.trim().to_lowercase();
    if lower.starts_with("warn") || lower.contains(" warning") || lower.contains("deprecated") {
        "WARN"
    } else if lower.starts_with("error")
        || lower.starts_with("fatal")
        || lower.contains(" failed")
        || lower.contains(" failure")
    {
        "ERROR"
    } else {
        "INFO"
    }
}

pub fn header(msg: &str) {
    println!("{}", BANNER.cyan().bold());
    emit("INFO", msg);
    emit("INFO", "Build started");
}

pub fn section(msg: &str) {
    emit("INFO", msg);
}

pub fn pipe(line: &str) {
    emit(classify_line(line), line.trim());
}

pub fn kv(key: &str, val: &str) {
    emit("INFO", &format!("{key}: {val}"));
}

pub fn ok(msg: &str) {
    emit("INFO", msg);
}

pub fn fail(msg: &str) {
    emit("ERROR", msg);
}

pub fn step_started(name: &str) {
    emit("INFO", &format!("{}...", friendly_step(name)));
}

pub fn step_completed(step: &Step) {
    let secs = step.duration_secs.unwrap_or_default();
    ok(&format!(
        "{} complete ({secs:.1}s)",
        friendly_step(&step.name)
    ));
}

pub fn step_failed(step: &Step) {
    let secs = step.duration_secs.unwrap_or_default();
    fail(&format!(
        "{} failed ({secs:.1}s)",
        friendly_step(&step.name)
    ));
}

pub fn steps_summary(steps: &[Step]) {
    section("Build summary");
    for step_data in steps {
        let duration = step_data.duration_secs.unwrap_or_default();
        let resources = step_data
            .resources
            .map(|r| {
                format!(
                    " cpu={:.1}% mem={}MB disk={}MB",
                    r.cpu_percent, r.memory_mb, r.disk_mb
                )
            })
            .unwrap_or_default();
        let msg = format!(
            "{}: status={} duration={:.1}s logs={}{}",
            friendly_step(&step_data.name),
            step_data.status.as_str(),
            duration,
            step_data.logs.len(),
            resources
        );
        match step_data.status.as_str() {
            "failed" => emit("ERROR", &msg),
            "running" => emit("WARN", &msg),
            _ => emit("INFO", &msg),
        }
    }
}

fn friendly_step(name: &str) -> String {
    match name {
        "source" => "Preparing source".to_string(),
        "detect-build-config" => "Detecting build configuration".to_string(),
        "compatibility-check" => "Running compatibility checks".to_string(),
        "incremental-prepare" => "Preparing incremental build data".to_string(),
        "install" => "Installing dependencies".to_string(),
        "dependency-intelligence" => "Analyzing dependencies".to_string(),
        "security-scan" => "Running security scan".to_string(),
        "deps-cache-save" => "Saving dependency cache".to_string(),
        "build" => "Building project".to_string(),
        "deploy" => "Generating artifacts".to_string(),
        "sign-artifacts" => "Signing artifacts".to_string(),
        "cache-state-save" => "Saving cache state".to_string(),
        "build-metrics" => "Writing build metrics".to_string(),
        _ => format!("Running {name}"),
    }
}
