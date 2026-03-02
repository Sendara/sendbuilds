use std::path::PathBuf;
use std::collections::HashMap;
use chrono::{DateTime, Local};

// everything a step might need to know about the current build
#[derive(Debug)]
pub struct BuildContext {
    pub project_name: String,
    pub work_dir:     PathBuf,
    pub artifact_dir: PathBuf,
    pub started_at:   DateTime<Local>,
    pub env:          HashMap<String, String>,
}

impl BuildContext {
    pub fn new(
        project_name: &str,
        work_dir: PathBuf,
        artifact_dir: PathBuf,
        env: HashMap<String, String>,
    ) -> Self {
        Self {
            project_name: project_name.to_string(),
            work_dir,
            artifact_dir,
            started_at: Local::now(),
            env,
        }
    }

    pub fn elapsed_secs(&self) -> f32 {
        (Local::now() - self.started_at).num_milliseconds() as f32 / 1000.0
    }
}
