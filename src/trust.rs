//! Slice 06: the orchestrator's trust budget. A capability earns its way up
//! the rung ladder on clean sensor history and is demoted automatically by
//! the next failure. The current rung is never stored as a fact; it is
//! replayed from the ledger's `rung.change` and `capability.run` events, so
//! the rung a capability holds is always derivable by a third party from the
//! signed record alone, which is the property that makes the ladder auditable
//! rather than asserted.

use crate::gateway::Pinning;
use crate::ledger::{Ledger, SignedHead};
use crate::policy::{Policy, Rung};
use crate::runlog::RunCore;
use crate::sensor::{Sensor, Verdict};
use crate::Fault;
use serde_json::{json, Value};
use std::path::Path;

/// The promotion rule, read from `policy.trust_budget.promotion`.
#[derive(Debug, Clone)]
pub struct TrustBudget {
    pub runs_at_rung: u64,
    pub approver: Approver,
    pub demotion_triggers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approver {
    Any,
    /// A closed set of identities permitted to promote.
    Named(Vec<String>),
}

impl TrustBudget {
    pub fn from_policy(policy: &Policy) -> TrustBudget {
        let tb = &policy.trust_budget;
        let runs_at_rung = tb["promotion"]["runs_at_rung"].as_u64().unwrap_or(20);
        let approver = match tb["promotion"]["approver"].as_str() {
            Some("named") => {
                let names = tb["promotion"]["named_approvers"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                Approver::Named(names)
            }
            _ => Approver::Any,
        };
        let demotion_triggers = tb["demotion"]["triggers"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    "sensor.fail".to_string(),
                    "human.override".to_string(),
                    "policy.deny".to_string(),
                ]
            });
        TrustBudget {
            runs_at_rung,
            approver,
            demotion_triggers,
        }
    }

    pub fn approver_ok(&self, identity: &str) -> bool {
        match &self.approver {
            Approver::Any => true,
            Approver::Named(names) => names.iter().any(|n| n == identity),
        }
    }
}

/// The rung a capability holds and how it got there, all derived from event
/// replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState {
    pub rung: Rung,
    /// Clean runs recorded since the capability last entered its current rung.
    pub clean_since_rung: u64,
}

impl TrustState {
    /// Replays the ledger for one capability. `start_rung` is the capability's
    /// declared rung in the policy; `rung.change` events move it, and
    /// `capability.run` events accumulate or reset the clean-run counter.
    pub fn replay(events: &[Value], capability: &str, start_rung: Rung) -> TrustState {
        let mut rung = start_rung;
        let mut clean = 0u64;
        for ev in events {
            let subj = &ev["_subject"];
            if subj["capability"] != json!(capability) {
                continue;
            }
            match ev["kind"].as_str() {
                Some("rung.change") => {
                    if let Some(to) = subj["to"].as_str().and_then(Rung::parse) {
                        rung = to;
                        clean = 0;
                    }
                }
                Some("capability.run") => match subj["outcome"].as_str() {
                    Some("clean") => clean += 1,
                    _ => clean = 0,
                },
                _ => {}
            }
        }
        TrustState {
            rung,
            clean_since_rung: clean,
        }
    }

    /// Promotion is earned when clean runs at the current rung reach the
    /// threshold and there is a higher rung to move to.
    pub fn promotion_earned(&self, budget: &TrustBudget) -> bool {
        self.clean_since_rung >= budget.runs_at_rung && self.rung.up().is_some()
    }
}

/// One orchestrated run of a capability: it runs the capability's sensor,
/// records the outcome as a `capability.run`, demotes automatically on
/// failure, and promotes on a clean run that reaches the threshold with an
/// approved promoter. The rung is recomputed from the ledger each time, never
/// held in a field.
pub struct Orchestrator {
    core: RunCore,
    policy: Policy,
    budget: TrustBudget,
}

/// What one orchestrated step did, for the caller to print.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub rung_before: Rung,
    pub rung_after: Rung,
    pub verdict: Verdict,
    pub change: Option<&'static str>,
}

impl Orchestrator {
    pub fn open(
        ledger: Ledger,
        policy: Policy,
        workload: &str,
        pin: &Pinning,
    ) -> Result<Orchestrator, Fault> {
        let policy_version = policy.policy_version.clone().unwrap_or_default();
        let authority = pin.authority(&policy.profile, &policy_version)?;
        let actor = json!({
            "type": "system",
            "id": "system:orchestrator",
            "identity_source": "local",
            "rung": null,
        });
        let instruction_pack = authority["instruction_version"].clone();
        let settings_hash = authority["settings_hash"].clone();
        let profile = policy.profile.clone();
        let budget = TrustBudget::from_policy(&policy);
        let core = RunCore::open(ledger, actor, authority);
        let mut orch = Orchestrator {
            core,
            policy,
            budget,
        };
        orch.core.append(
            "run.open",
            json!({
                "profile": profile,
                "workload": workload,
                "instruction_pack": instruction_pack,
                "settings_hash": settings_hash,
                "restored_checkpoint": null,
            }),
        )?;
        Ok(orch)
    }

    pub fn run_id(&self) -> &str {
        self.core.run_id()
    }

    fn start_rung(&self, capability: &str) -> Result<Rung, Fault> {
        self.policy
            .capabilities
            .iter()
            .find(|c| c.id == capability)
            .map(|c| c.rung)
            .ok_or_else(|| {
                Fault::new(
                    format!("capability {capability} is not declared in the policy"),
                    "name a capability present in config/policy.json",
                )
            })
    }

    /// The event history this run has written so far, each with its subject
    /// payload inlined under `_subject` for replay. Reads the ledger's own
    /// event log, so replay sees exactly what an auditor would.
    fn history(&self) -> Result<Vec<Value>, Fault> {
        self.core.replayable_events()
    }

    /// One step: evaluate the sensor, record a capability.run, then demote or
    /// promote as the outcome and history dictate.
    pub fn step(
        &mut self,
        capability: &str,
        sensor: &Sensor,
        artifact: &Path,
        approver: Option<&str>,
    ) -> Result<StepOutcome, Fault> {
        let start = self.start_rung(capability)?;
        let before = TrustState::replay(&self.history()?, capability, start).rung;

        // Run the sensor in its own sub-run so the verdict is on the ledger
        // with the sensor bus as actor, then read its outcome back.
        let verdict = self.run_sensor(sensor, artifact)?;
        let clean = matches!(verdict, Verdict::Pass);
        self.core.append(
            "capability.run",
            json!({
                "capability": capability,
                "rung": before.schema_name(),
                "outcome": if clean { "clean" } else { "sensor.fail" },
                "sensor": sensor.id,
            }),
        )?;

        let mut change = None;
        let mut after = before;

        if !clean
            && self
                .budget
                .demotion_triggers
                .iter()
                .any(|t| t == "sensor.fail")
        {
            if let Some(down) = before.down() {
                self.emit_rung_change(capability, before, down, "demotion", None)?;
                after = down;
                change = Some("demotion");
            }
        } else if clean {
            let state = TrustState::replay(&self.history()?, capability, start);
            if state.promotion_earned(&self.budget) {
                let promoter = approver.ok_or_else(|| {
                    Fault::new(
                        format!(
                            "capability {capability} has earned promotion but no approver was named"
                        ),
                        "re-run the step with --approver <identity>; a promotion is an act under someone's authority",
                    )
                })?;
                if !self.budget.approver_ok(promoter) {
                    return Err(Fault::new(
                        format!("{promoter} is not a permitted approver for promotion under this policy"),
                        "use an identity listed in trust_budget.promotion.named_approvers, or widen the policy",
                    ));
                }
                let up = before.up().expect("promotion_earned implies a higher rung");
                self.emit_rung_change(capability, before, up, "earned", Some(promoter))?;
                after = up;
                change = Some("promotion");
            }
        }

        Ok(StepOutcome {
            rung_before: before,
            rung_after: after,
            verdict,
            change,
        })
    }

    fn run_sensor(&mut self, sensor: &Sensor, artifact: &Path) -> Result<Verdict, Fault> {
        // The sandbox lives on the sensor's own run; evaluate through a
        // throwaway SensorRun is heavy, so evaluate directly against a
        // per-step sandbox and record the verdict on this run.
        let sandbox =
            crate::sandbox::Sandbox::per_run(&crate::sandbox::unique_run_dir("gantry-orch"), &[])?;
        let content = std::fs::read_to_string(artifact).map_err(|e| {
            Fault::new(
                format!("cannot read artifact {}: {e}", artifact.display()),
                "check the artifact path exists and is readable",
            )
        })?;
        let v = sensor.evaluate(&sandbox, &artifact.display().to_string(), &content)?;
        self.core.append("sensor.verdict", v.subject())?;
        Ok(v.verdict)
    }

    fn emit_rung_change(
        &mut self,
        capability: &str,
        from: Rung,
        to: Rung,
        trigger: &str,
        approver: Option<&str>,
    ) -> Result<(), Fault> {
        if trigger == "earned" {
            // A promotion is preceded by its approval event, so the record
            // shows who authorised it before it takes effect.
            self.core.append(
                "approval",
                json!({
                    "approver": { "id": approver, "source": "local" },
                    "verdict": "approve",
                    "decided": format!("promote {capability} from {} to {}", from.schema_name(), to.schema_name()),
                    "required_by": "trust_budget.promotion",
                }),
            )?;
        }
        self.core.append(
            "rung.change",
            json!({
                "capability": capability,
                "from": from.schema_name(),
                "to": to.schema_name(),
                "trigger": trigger,
                "approver": approver,
            }),
        )
    }

    pub fn seal(self, outcome: &str) -> Result<SignedHead, Fault> {
        self.core.seal(json!({}), outcome)
    }
}

/// Replays a sealed ledger directory and narrates one capability's rung arc.
pub fn narrate(events: &[Value], capability: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for ev in events {
        let subj = &ev["_subject"];
        if ev["kind"] == json!("rung.change") && subj["capability"] == json!(capability) {
            let from = subj["from"].as_str().unwrap_or("?");
            let to = subj["to"].as_str().unwrap_or("?");
            let trigger = subj["trigger"].as_str().unwrap_or("?");
            let approver = subj["approver"].as_str();
            let who = approver.map(|a| format!(" by {a}")).unwrap_or_default();
            lines.push(format!("{from} -> {to} ({trigger}{who})"));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(kind: &str, subject: Value) -> Value {
        json!({ "kind": kind, "_subject": subject })
    }

    fn budget(runs: u64) -> TrustBudget {
        TrustBudget {
            runs_at_rung: runs,
            approver: Approver::Any,
            demotion_triggers: vec!["sensor.fail".into()],
        }
    }

    #[test]
    fn clean_runs_accumulate_and_earn_promotion() {
        let mut events = vec![];
        for _ in 0..3 {
            events.push(ev(
                "capability.run",
                json!({"capability": "repo.write", "outcome": "clean"}),
            ));
        }
        let state = TrustState::replay(&events, "repo.write", Rung::Assisted);
        assert_eq!(state.clean_since_rung, 3);
        assert!(state.promotion_earned(&budget(3)));
        assert!(!state.promotion_earned(&budget(4)));
    }

    #[test]
    fn a_rung_change_resets_the_counter() {
        let events = vec![
            ev(
                "capability.run",
                json!({"capability": "c", "outcome": "clean"}),
            ),
            ev(
                "capability.run",
                json!({"capability": "c", "outcome": "clean"}),
            ),
            ev(
                "rung.change",
                json!({"capability": "c", "to": "autonomous"}),
            ),
            ev(
                "capability.run",
                json!({"capability": "c", "outcome": "clean"}),
            ),
        ];
        let state = TrustState::replay(&events, "c", Rung::Assisted);
        assert_eq!(state.rung, Rung::Autonomous);
        assert_eq!(
            state.clean_since_rung, 1,
            "counter resets on entering a new rung"
        );
    }

    #[test]
    fn a_failure_resets_the_counter() {
        let events = vec![
            ev(
                "capability.run",
                json!({"capability": "c", "outcome": "clean"}),
            ),
            ev(
                "capability.run",
                json!({"capability": "c", "outcome": "sensor.fail"}),
            ),
            ev(
                "capability.run",
                json!({"capability": "c", "outcome": "clean"}),
            ),
        ];
        let state = TrustState::replay(&events, "c", Rung::Assisted);
        assert_eq!(state.clean_since_rung, 1);
    }

    #[test]
    fn named_approver_gate() {
        let b = TrustBudget {
            runs_at_rung: 1,
            approver: Approver::Named(vec!["user:boss@corp".into()]),
            demotion_triggers: vec![],
        };
        assert!(b.approver_ok("user:boss@corp"));
        assert!(!b.approver_ok("user:intern@corp"));
    }

    #[test]
    fn autonomous_cannot_promote_further() {
        let events = vec![ev(
            "capability.run",
            json!({"capability": "c", "outcome": "clean"}),
        )];
        let state = TrustState::replay(&events, "c", Rung::Autonomous);
        assert!(
            !state.promotion_earned(&budget(1)),
            "no rung above autonomous"
        );
    }

    #[test]
    fn narrate_reads_the_arc() {
        let events = vec![
            ev(
                "rung.change",
                json!({"capability": "c", "from": "assisted", "to": "autonomous", "trigger": "earned", "approver": "user:boss"}),
            ),
            ev(
                "rung.change",
                json!({"capability": "c", "from": "autonomous", "to": "assisted", "trigger": "demotion", "approver": null}),
            ),
        ];
        let lines = narrate(&events, "c");
        assert_eq!(lines[0], "assisted -> autonomous (earned by user:boss)");
        assert_eq!(lines[1], "autonomous -> assisted (demotion)");
    }
}
