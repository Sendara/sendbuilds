#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl StepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StepStatus::Pending => "pending",
            StepStatus::Running => "running",
            StepStatus::Completed => "completed",
            StepStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub status: StepStatus,
    pub logs: Vec<String>,
    pub duration_secs: Option<f32>,
    pub resources: Option<StepResources>,
}

#[derive(Debug, Clone, Copy)]
pub struct StepResources {
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

impl Step {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Pending,
            logs: Vec::new(),
            duration_secs: None,
            resources: None,
        }
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
    }
}
