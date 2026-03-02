use chrono::Local;
use colored::Colorize;

use crate::core::Step;

fn ts() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

pub fn header(msg: &str) {
    println!("\n{}", format!("== {msg} ==").cyan().bold());
}

pub fn section(msg: &str) {
    println!("\n{} {}", ">".yellow().bold(), msg.bold());
}

pub fn step(msg: &str) {
    println!("  {} {}", "-".dimmed(), msg);
}

pub fn pipe(line: &str) {
    println!("    {}", line.dimmed());
}

pub fn kv(key: &str, val: &str) {
    println!("  {:12} {}", format!("{key}:").dimmed(), val);
}

pub fn ok(msg: &str) {
    println!("  {} {}", "+".green().bold(), msg.dimmed());
}

pub fn fail(msg: &str) {
    eprintln!("{} {} {}", ts().dimmed(), "x".red().bold(), msg.red().bold());
}

pub fn step_started(name: &str) {
    section(name);
    step("status: running");
}

pub fn step_completed(step: &Step) {
    let secs = step.duration_secs.unwrap_or_default();
    ok(&format!("status: completed ({secs:.1}s)"));
}

pub fn step_failed(step: &Step) {
    let secs = step.duration_secs.unwrap_or_default();
    fail(&format!("step '{}' failed ({secs:.1}s)", step.name));
}

pub fn steps_summary(steps: &[Step]) {
    section("step summary");
    for step_data in steps {
        let duration = step_data.duration_secs.unwrap_or_default();
        let resources = step_data.resources.map(|r| {
            format!(" cpu={:.1}% mem={}MB disk={}MB", r.cpu_percent, r.memory_mb, r.disk_mb)
        }).unwrap_or_default();
        println!(
            "  {:12} {:10} {:>6.1}s  logs={}{}",
            format!("{}:", step_data.name).dimmed(),
            step_data.status.as_str(),
            duration,
            step_data.logs.len(),
            resources
        );
    }
}
