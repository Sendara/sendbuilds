use anyhow::Result;
use std::fs;
use std::path::Path;
use sysinfo::System;

use crate::core::StepResources;

#[derive(Debug, Clone, Copy)]
pub struct ResourceSnapshot {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

pub fn sample(work_dir: &Path) -> Result<ResourceSnapshot> {
    let mut system = System::new_all();
    system.refresh_all();

    let cpu = system.global_cpu_info().cpu_usage();
    let memory_mb = system.used_memory() / 1024 / 1024;
    let disk_mb = dir_size_mb(work_dir)?;

    Ok(ResourceSnapshot {
        cpu_percent: cpu,
        memory_mb,
        disk_mb,
    })
}

pub fn to_step_resources(before: ResourceSnapshot, after: ResourceSnapshot) -> StepResources {
    StepResources {
        cpu_percent: ((before.cpu_percent + after.cpu_percent) / 2.0 * 10.0).round() / 10.0,
        memory_mb: after.memory_mb.saturating_sub(before.memory_mb),
        disk_mb: after.disk_mb.saturating_sub(before.disk_mb),
    }
}

fn dir_size_mb(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let bytes = dir_size_bytes(path)?;
    Ok(bytes / 1024 / 1024)
}

fn dir_size_bytes(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total = total.saturating_add(dir_size_bytes(&entry.path())?);
        } else if meta.is_file() {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
}
