use anyhow::{Context, Result, anyhow};
use std::thread;
use std::time::Instant;

use crate::core::{Step, StepStatus};
use crate::output::{events, logger as log};

pub struct ParallelStepTask {
    name: String,
    run: Box<dyn FnOnce(&mut Step) -> Result<()> + Send + 'static>,
}

impl ParallelStepTask {
    pub fn new<F>(name: impl Into<String>, run: F) -> Self
    where
        F: FnOnce(&mut Step) -> Result<()> + Send + 'static,
    {
        Self {
            name: name.into(),
            run: Box::new(run),
        }
    }
}

pub fn run(tasks: Vec<ParallelStepTask>) -> Result<Vec<Step>> {
    let mut handles = Vec::new();

    for task in tasks {
        handles.push(thread::spawn(move || run_single(task)));
    }

    let mut steps = Vec::new();
    let mut first_error = None;

    for handle in handles {
        match handle.join() {
            Ok(Ok(step)) => steps.push(step),
            Ok(Err(err)) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(_) => {
                if first_error.is_none() {
                    first_error = Some(anyhow!("parallel step panicked"));
                }
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(steps)
    }
}

fn run_single(task: ParallelStepTask) -> Result<Step> {
    let mut step = Step::new(task.name);
    step.status = StepStatus::Running;

    events::step_started(&step);
    log::step_started(&step.name);

    let start = Instant::now();
    let outcome = (task.run)(&mut step);
    step.duration_secs = Some(start.elapsed().as_secs_f32());

    match outcome {
        Ok(()) => {
            step.status = StepStatus::Completed;
            events::step_completed(&step);
            log::step_completed(&step);
            Ok(step)
        }
        Err(err) => {
            step.status = StepStatus::Failed;
            step.push_log(format!("error: {err:#}"));
            events::step_failed(&step, &err.to_string());
            log::step_failed(&step);
            Err(err).with_context(|| format!("parallel step '{}' failed", step.name))
        }
    }
}
