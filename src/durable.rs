//! Slice 07: durable state. A durable task is an ordered list of steps whose
//! progress is checkpointed to the ledger after each step. If the process
//! dies mid-task, a resume reads the last checkpoint off the ledger, restores
//! the accumulated state, and finishes; the ledger then shows the seam: an
//! unsealed run that stops at a checkpoint, and a second run that opens
//! declaring the checkpoint it restored. Nothing produced before the kill is
//! lost, because it was on the append-only record before the kill happened.

use crate::gateway::Pinning;
use crate::ledger::{Ledger, SignedHead};
use crate::policy::Policy;
use crate::runlog::RunCore;
use crate::Fault;
use serde_json::{json, Value};

/// One durable task run. Carries the accumulated per-step results so a
/// checkpoint is a complete restore point, not just a cursor.
pub struct DurableRun {
    core: RunCore,
    task_id: String,
    /// Results of every step completed so far, in order. A checkpoint writes
    /// this whole vector, so restoring one checkpoint restores everything up
    /// to it with nothing to replay.
    results: Vec<Value>,
    last_checkpoint: Option<String>,
}

/// What a resume recovered from the ledger before continuing.
#[derive(Debug, Clone)]
pub struct Restored {
    pub checkpoint_id: String,
    pub next_step: usize,
    pub results: Vec<Value>,
}

impl DurableRun {
    fn actor() -> Value {
        json!({
            "type": "system",
            "id": "system:durable-runner",
            "identity_source": "local",
            "rung": null,
        })
    }

    pub fn open(
        ledger: Ledger,
        policy: &Policy,
        task_id: &str,
        pin: &Pinning,
    ) -> Result<DurableRun, Fault> {
        Self::open_inner(ledger, policy, task_id, pin, None)
    }

    fn open_inner(
        ledger: Ledger,
        policy: &Policy,
        task_id: &str,
        pin: &Pinning,
        restored: Option<&Restored>,
    ) -> Result<DurableRun, Fault> {
        let policy_version = policy.policy_version.clone().unwrap_or_default();
        let authority = pin.authority(&policy.profile, &policy_version)?;
        let instruction_pack = authority["instruction_version"].clone();
        let settings_hash = authority["settings_hash"].clone();
        let profile = policy.profile.clone();
        let core = RunCore::open(ledger, Self::actor(), authority);
        let mut run = DurableRun {
            core,
            task_id: task_id.to_string(),
            results: restored.map(|r| r.results.clone()).unwrap_or_default(),
            last_checkpoint: restored.map(|r| r.checkpoint_id.clone()),
        };
        run.core.append(
            "run.open",
            json!({
                "profile": profile,
                "workload": task_id,
                "instruction_pack": instruction_pack,
                "settings_hash": settings_hash,
                "restored_checkpoint": restored.map(|r| r.checkpoint_id.clone()),
            }),
        )?;
        Ok(run)
    }

    /// Reopen a task from its last checkpoint on the ledger. The scan is over
    /// the ledger's own events, so what a resume restores is exactly what an
    /// auditor would read.
    pub fn resume(
        ledger: Ledger,
        policy: &Policy,
        task_id: &str,
        pin: &Pinning,
    ) -> Result<(DurableRun, Restored), Fault> {
        let restored = Self::last_checkpoint(&ledger, task_id)?.ok_or_else(|| {
            Fault::new(
                format!("no checkpoint for task {task_id} on this ledger"),
                "run the task first; resume only continues a task that checkpointed at least once",
            )
        })?;
        let run = Self::open_inner(ledger, policy, task_id, pin, Some(&restored))?;
        Ok((run, restored))
    }

    /// The last `state.checkpoint` for this task, decoded into a restore
    /// point. Public so a reader can ask "where would a resume pick up" without
    /// resuming.
    pub fn last_checkpoint(ledger: &Ledger, task_id: &str) -> Result<Option<Restored>, Fault> {
        let events = ledger.events_with_subjects()?;
        let mut found = None;
        for ev in &events {
            if ev["kind"] == json!("state.checkpoint") && ev["_subject"]["task"] == json!(task_id) {
                let subj = &ev["_subject"];
                let next_step = subj["next_step"].as_u64().unwrap_or(0) as usize;
                let results = subj["results"].as_array().cloned().unwrap_or_default();
                let checkpoint_id = subj["checkpoint_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                found = Some(Restored {
                    checkpoint_id,
                    next_step,
                    results,
                });
            }
        }
        Ok(found)
    }

    pub fn run_id(&self) -> &str {
        self.core.run_id()
    }

    pub fn results(&self) -> &[Value] {
        &self.results
    }

    /// Record one step's result and checkpoint it. The checkpoint carries the
    /// full accumulated results and the next step index, so it is a complete
    /// restore point.
    pub fn checkpoint_step(
        &mut self,
        step_index: usize,
        label: &str,
        result: Value,
    ) -> Result<(), Fault> {
        self.results
            .push(json!({ "step": step_index, "label": label, "result": result }));
        let checkpoint_id = format!("{}-ckpt-{}", self.core.run_id(), step_index);
        self.core.append(
            "state.checkpoint",
            json!({
                "checkpoint_id": checkpoint_id,
                "task": self.task_id,
                "covers": format!("steps 0..={step_index}"),
                "next_step": step_index + 1,
                "restores": format!("resume at step {}", step_index + 1),
                "results": self.results,
            }),
        )?;
        self.last_checkpoint = Some(checkpoint_id);
        Ok(())
    }

    pub fn last_checkpoint_id(&self) -> Option<&str> {
        self.last_checkpoint.as_deref()
    }

    pub fn seal(self, outcome: &str) -> Result<SignedHead, Fault> {
        let count = self.results.len();
        self.core.seal(
            json!({
                "task": self.task_id,
                "steps_completed": count,
                "restored_from": self.last_checkpoint,
            }),
            outcome,
        )
    }
}

/// Reads a ledger and describes the seam for one task: which run stopped
/// where, and which run restored it.
pub fn seam(events: &[Value], task_id: &str) -> Vec<String> {
    let mut lines = Vec::new();
    // Group open/seal/checkpoint by run_id in order of appearance.
    let mut order: Vec<String> = Vec::new();
    for ev in events {
        let run_id = ev["run_id"].as_str().unwrap_or("").to_string();
        let kind = ev["kind"].as_str().unwrap_or("");
        let subj = &ev["_subject"];
        let relevant = (kind == "run.open" && subj["workload"] == json!(task_id))
            || (kind == "state.checkpoint" && subj["task"] == json!(task_id))
            || (kind == "run.seal" && subj["task"] == json!(task_id));
        if !relevant {
            continue;
        }
        if !order.contains(&run_id) {
            order.push(run_id.clone());
        }
        match kind {
            "run.open" => {
                let restored = subj["restored_checkpoint"].as_str();
                match restored {
                    Some(c) => lines.push(format!("run {run_id} opened, restoring checkpoint {c}")),
                    None => lines.push(format!("run {run_id} opened fresh")),
                }
            }
            "state.checkpoint" => {
                let id = subj["checkpoint_id"].as_str().unwrap_or("?");
                lines.push(format!(
                    "  checkpoint {id}: {}",
                    subj["covers"].as_str().unwrap_or("")
                ));
            }
            "run.seal" => {
                lines.push(format!(
                    "run {run_id} sealed: {} ({} steps)",
                    subj["outcome"].as_str().unwrap_or("?"),
                    subj["steps_completed"].as_u64().unwrap_or(0)
                ));
            }
            _ => {}
        }
    }
    // Name the unsealed run: one that opened but never sealed.
    let sealed: Vec<&str> = events
        .iter()
        .filter(|e| e["kind"] == json!("run.seal") && e["_subject"]["task"] == json!(task_id))
        .filter_map(|e| e["run_id"].as_str())
        .collect();
    for run_id in &order {
        if !sealed.iter().any(|s| s == run_id) {
            lines.push(format!("run {run_id} never sealed: this is the kill point"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(run_id: &str, kind: &str, subject: Value) -> Value {
        json!({ "run_id": run_id, "kind": kind, "_subject": subject })
    }

    #[test]
    fn seam_names_the_kill_and_the_restore() {
        let events = vec![
            ev(
                "run-1",
                "run.open",
                json!({"workload": "audit", "restored_checkpoint": null}),
            ),
            ev(
                "run-1",
                "state.checkpoint",
                json!({"task": "audit", "checkpoint_id": "run-1-ckpt-0", "covers": "steps 0..=0"}),
            ),
            ev(
                "run-1",
                "state.checkpoint",
                json!({"task": "audit", "checkpoint_id": "run-1-ckpt-1", "covers": "steps 0..=1"}),
            ),
            // run-1 dies here, no seal.
            ev(
                "run-2",
                "run.open",
                json!({"workload": "audit", "restored_checkpoint": "run-1-ckpt-1"}),
            ),
            ev(
                "run-2",
                "state.checkpoint",
                json!({"task": "audit", "checkpoint_id": "run-2-ckpt-2", "covers": "steps 0..=2"}),
            ),
            ev(
                "run-2",
                "run.seal",
                json!({"task": "audit", "outcome": "complete", "steps_completed": 3}),
            ),
        ];
        let lines = seam(&events, "audit");
        assert!(lines
            .iter()
            .any(|l| l.contains("restoring checkpoint run-1-ckpt-1")));
        assert!(lines
            .iter()
            .any(|l| l.contains("run-1 never sealed: this is the kill point")));
        assert!(lines
            .iter()
            .any(|l| l.contains("run-2 sealed: complete (3 steps)")));
    }
}
