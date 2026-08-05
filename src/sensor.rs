//! Slice 05: the sensor bus. A sensor is a check with a lifecycle placement
//! whose verdict names the fix, because the reader is an agent. The bus
//! enforces one rule the other layers cannot: a sensor that cannot fail is
//! reported as broken, not as clean. Every sensor declares a negative
//! control (an input it must reject); a sensor that passes its own negative
//! control is a broken sensor, and a green board full of broken sensors is
//! the failure this bus exists to prevent.

use crate::gateway::Pinning;
use crate::ledger::{Ledger, SignedHead};
use crate::runlog::RunCore;
use crate::sandbox::Sandbox;
use crate::Fault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorKind {
    /// A deterministic check: a command that exits zero to pass.
    Computational,
    /// A model-judged check. Recorded as inferential so a reader knows the
    /// verdict is a judgement, not a proof.
    Inferential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    PreIntegration,
    PostIntegration,
    Continuous,
}

/// A registered sensor. `check` is a shell command with `{target}`
/// substituted by the artifact path; exit zero passes. `fix` is the message
/// a failing verdict carries, and it must name an action. `negative_control`
/// is the content the check must reject, which is what makes the sensor's
/// own liveness checkable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sensor {
    pub id: String,
    pub kind: SensorKind,
    pub placement: Placement,
    #[serde(default = "default_true")]
    pub blocking: bool,
    pub check: String,
    pub fix: String,
    pub negative_control: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
    Broken,
}

/// The outcome of running one sensor against one target, one-to-one with a
/// `sensor.verdict` event subject.
#[derive(Debug, Clone, Serialize)]
pub struct SensorVerdict {
    pub sensor: String,
    pub kind: SensorKind,
    pub placement: Placement,
    pub verdict: Verdict,
    pub blocked: bool,
    pub message: Option<String>,
    pub target: String,
}

impl Sensor {
    pub fn load(path: &Path) -> Result<Sensor, Fault> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Fault::new(
                format!("cannot read sensor {}: {e}", path.display()),
                "check the path; a sensor is a JSON object with id, kind, placement, check, fix, negative_control",
            )
        })?;
        let sensor: Sensor = serde_json::from_str(&text).map_err(|e| {
            Fault::new(
                format!("{} does not parse as a sensor: {e}", path.display()),
                "a sensor needs id, kind (computational|inferential), placement, check, fix, negative_control",
            )
        })?;
        sensor.validate()?;
        Ok(sensor)
    }

    /// A sensor whose fix does not name an action is a sensor whose failure
    /// an agent cannot act on. The same rule as `ci/message-lint`, applied to
    /// the sensor's own definition at load.
    pub fn validate(&self) -> Result<(), Fault> {
        if self.fix.trim().is_empty() {
            return Err(Fault::new(
                format!("sensor {} has an empty fix message", self.id),
                "write a fix that names the action to take; a sensor verdict is read by an agent",
            ));
        }
        if !self.check.contains("{target}") {
            return Err(Fault::new(
                format!("sensor {} check never references {{target}}", self.id),
                "put {target} in the check command so the sensor actually inspects the artifact",
            ));
        }
        Ok(())
    }

    /// Runs the check against a file whose contents are `content`, inside the
    /// sandbox, and returns whether it passed (exit zero). The sandbox is the
    /// same per-run isolation the broker uses, so a sensor cannot reach the
    /// network or write outside the run either.
    fn run_check(&self, sandbox: &Sandbox, content: &str) -> Result<bool, Fault> {
        let target = sandbox.workdir().join(format!("sensor-{}-target", self.id));
        std::fs::write(&target, content).map_err(|e| {
            Fault::new(
                format!("cannot stage the sensor target {}: {e}", target.display()),
                "check the run workdir is writable",
            )
        })?;
        let command = self
            .check
            .replace("{target}", &target.display().to_string());
        let out = sandbox.command(&command, &[]).output().map_err(|e| {
            Fault::new(
                format!("cannot run sensor {} check: {e}", self.id),
                "check the sensor command is a valid shell predicate",
            )
        })?;
        Ok(out.status.success())
    }

    /// The liveness check. A sensor must reject its own negative control; a
    /// sensor that passes it cannot fail and is therefore broken. This runs
    /// before any real verdict is trusted.
    pub fn is_live(&self, sandbox: &Sandbox) -> Result<bool, Fault> {
        // Live means: the negative control does NOT pass the check.
        Ok(!self.run_check(sandbox, &self.negative_control)?)
    }

    /// Evaluate the sensor against a target file's contents. Runs the
    /// liveness check first: a broken sensor never returns a clean pass, it
    /// returns `Broken`, which is the whole point of the bus.
    pub fn evaluate(
        &self,
        sandbox: &Sandbox,
        target: &str,
        content: &str,
    ) -> Result<SensorVerdict, Fault> {
        if !self.is_live(sandbox)? {
            return Ok(SensorVerdict {
                sensor: self.id.clone(),
                kind: self.kind,
                placement: self.placement,
                verdict: Verdict::Broken,
                blocked: self.blocking,
                message: Some(format!(
                    "Sensor {} passed its own negative control, so it cannot fail and its verdicts are worthless. Fix the check so the negative control fails, then re-register.",
                    self.id
                )),
                target: target.to_string(),
            });
        }
        let passed = self.run_check(sandbox, content)?;
        Ok(SensorVerdict {
            sensor: self.id.clone(),
            kind: self.kind,
            placement: self.placement,
            verdict: if passed { Verdict::Pass } else { Verdict::Fail },
            blocked: !passed && self.blocking,
            message: if passed { None } else { Some(self.fix.clone()) },
            target: target.to_string(),
        })
    }
}

impl SensorVerdict {
    /// The subject payload of the `sensor.verdict` event.
    pub fn subject(&self) -> Value {
        json!(self)
    }
}

/// A run whose job is to evaluate sensors and record their verdicts. Shares
/// the run plumbing (one run id, one seq, authority per event) and the
/// per-run sandbox with the broker, so a sensor verdict sits on the same
/// ledger, under the same authority, as the tool calls it gates.
pub struct SensorRun {
    core: RunCore,
    sandbox: Sandbox,
    blocked_any: bool,
    broken_any: bool,
}

impl SensorRun {
    pub fn open(
        ledger: Ledger,
        profile: &str,
        policy_version: &str,
        workload: &str,
        pin: &Pinning,
    ) -> Result<SensorRun, Fault> {
        let authority = pin.authority(profile, policy_version)?;
        let actor = json!({
            "type": "system",
            "id": "system:sensor-bus",
            "identity_source": "local",
            "rung": null,
        });
        let instruction_pack = authority["instruction_version"].clone();
        let settings_hash = authority["settings_hash"].clone();
        let core = RunCore::open(ledger, actor, authority);
        let sandbox = Sandbox::per_run(
            &std::env::temp_dir().join(format!("gantry-sensor-run-{}", core.run_id())),
            &[],
        )?;
        let mut run = SensorRun {
            core,
            sandbox,
            blocked_any: false,
            broken_any: false,
        };
        run.core.append(
            "run.open",
            json!({
                "profile": profile,
                "workload": workload,
                "instruction_pack": instruction_pack,
                "settings_hash": settings_hash,
                "restored_checkpoint": null,
            }),
        )?;
        Ok(run)
    }

    pub fn run_id(&self) -> &str {
        self.core.run_id()
    }

    /// Evaluate one sensor against an artifact file, record the verdict, and
    /// return it. A blocking failure or a broken sensor is remembered so the
    /// seal cannot claim clean.
    pub fn gate(&mut self, sensor: &Sensor, artifact: &Path) -> Result<SensorVerdict, Fault> {
        let content = std::fs::read_to_string(artifact).map_err(|e| {
            Fault::new(
                format!("cannot read the artifact under sensor {}: {e}", sensor.id),
                "check the artifact path exists and is a readable text file",
            )
        })?;
        let verdict = sensor.evaluate(&self.sandbox, &artifact.display().to_string(), &content)?;
        if verdict.blocked {
            self.blocked_any = true;
        }
        if verdict.verdict == Verdict::Broken {
            self.broken_any = true;
        }
        self.core.append("sensor.verdict", verdict.subject())?;
        Ok(verdict)
    }

    pub fn seal(self) -> Result<SignedHead, Fault> {
        let outcome = if self.broken_any {
            "sealed-with-broken-sensor"
        } else if self.blocked_any {
            "sealed-with-blocking-failure"
        } else {
            "clean"
        };
        self.core.seal(
            json!({
                "blocked_any": self.blocked_any,
                "broken_any": self.broken_any,
            }),
            outcome,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(name: &str) -> Sandbox {
        let dir = std::env::temp_dir().join(format!("gantry-sensor-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Sandbox::per_run(&dir, &[]).unwrap()
    }

    fn no_key_sensor() -> Sensor {
        Sensor {
            id: "no-private-key".into(),
            kind: SensorKind::Computational,
            placement: Placement::PreIntegration,
            blocking: true,
            check: "! grep -q 'BEGIN PRIVATE KEY' {target}".into(),
            fix: "Remove the embedded private key from the findings and reference it by a broker handle instead.".into(),
            negative_control: "-----BEGIN PRIVATE KEY-----\nMII...\n".into(),
        }
    }

    #[test]
    fn passing_and_failing_verdicts() {
        let s = no_key_sensor();
        let sb = sandbox("verdicts");
        let clean = s.evaluate(&sb, "findings.md", "no secrets here").unwrap();
        assert_eq!(clean.verdict, Verdict::Pass);
        assert!(!clean.blocked);
        assert!(clean.message.is_none());

        let dirty = s
            .evaluate(&sb, "findings.md", "look: -----BEGIN PRIVATE KEY-----")
            .unwrap();
        assert_eq!(dirty.verdict, Verdict::Fail);
        assert!(dirty.blocked, "a failing blocking sensor blocks");
        assert!(dirty
            .message
            .unwrap()
            .contains("Remove the embedded private key"));
    }

    #[test]
    fn a_sensor_that_cannot_fail_is_broken_not_clean() {
        let broken = Sensor {
            id: "always-green".into(),
            kind: SensorKind::Computational,
            placement: Placement::PostIntegration,
            blocking: true,
            // Ignores the target entirely and always passes.
            check: "true # {target}".into(),
            fix: "This should never be reachable.".into(),
            negative_control: "-----BEGIN PRIVATE KEY-----".into(),
        };
        let sb = sandbox("broken");
        let v = broken.evaluate(&sb, "anything", "anything").unwrap();
        assert_eq!(
            v.verdict,
            Verdict::Broken,
            "a sensor that passes its negative control is broken"
        );
        assert!(v.message.unwrap().contains("cannot fail"));
    }

    #[test]
    fn live_sensor_reports_live() {
        let sb = sandbox("live");
        assert!(no_key_sensor().is_live(&sb).unwrap());
    }

    #[test]
    fn fix_must_name_an_action_at_load() {
        let mut s = no_key_sensor();
        s.fix = "  ".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn check_must_reference_target() {
        let mut s = no_key_sensor();
        s.check = "true".into();
        assert!(s.validate().is_err());
    }
}
