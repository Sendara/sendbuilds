use chrono::Local;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::core::{Step, StepStatus};

static EVENTS_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_enabled(enabled: bool) {
    EVENTS_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn step_started(step: &Step) {
    emit("STEP_STARTED", step, StepStatus::Running.as_str(), None);
}

pub fn step_completed(step: &Step) {
    emit("STEP_COMPLETED", step, StepStatus::Completed.as_str(), None);
}

pub fn step_failed(step: &Step, error: &str) {
    emit(
        "STEP_FAILED",
        step,
        StepStatus::Failed.as_str(),
        Some(error),
    );
}

fn emit(event_type: &str, step: &Step, status: &str, error: Option<&str>) {
    if !EVENTS_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let ts = Local::now().to_rfc3339();
    let duration_ms = step
        .duration_secs
        .map(|secs| (secs * 1000.0).round() as u64);

    let mut fields = vec![
        format!("\"type\":\"{}\"", esc(event_type)),
        "\"channel\":\"build-step\"".to_string(),
        format!("\"step\":\"{}\"", esc(&step.name)),
        format!("\"status\":\"{}\"", esc(status)),
        format!("\"timestamp\":\"{}\"", esc(&ts)),
    ];

    if let Some(ms) = duration_ms {
        fields.push(format!("\"duration_ms\":{ms}"));
    }

    if let Some(resources) = step.resources {
        fields.push(format!("\"cpu_percent\":{:.2}", resources.cpu_percent));
        fields.push(format!("\"memory_mb\":{}", resources.memory_mb));
        fields.push(format!("\"disk_mb\":{}", resources.disk_mb));
    }

    if let Some(err) = error {
        fields.push(format!("\"error\":\"{}\"", esc(err)));
    }

    println!("EVENT {{{}}}", fields.join(","));
}

fn esc(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
