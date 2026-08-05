//! Slice 08: the conformance scorer. It reads a ledger's telemetry and scores
//! each of the twelve primitives from the events that are actually there,
//! never from a profile name or a config value. The scoring rules are data
//! (`config/scoring.json`), so a score is re-derivable by anyone holding the
//! ledger and the rules. A primitive whose base evidence never appears scores
//! N/A rather than 0, and the overall level is the minimum across the
//! primitives that did appear, never the average: one weak layer caps the
//! whole, which is the rubric's rule and the thing a mean would hide.

use crate::Fault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

/// One telemetry predicate. Everything is a statement about events on the
/// ledger, so nothing here can read a config file or a profile name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pred {
    /// The event kind this predicate is about.
    pub kind: String,
    /// Minimum number of matching events (default 1).
    #[serde(default)]
    pub min: Option<u64>,
    /// Optional subject constraint: the JSON pointer must equal `equals`, or
    /// (when `present` is set) merely exist and be non-null.
    #[serde(default)]
    pub pointer: Option<String>,
    #[serde(default)]
    pub equals: Option<Value>,
    #[serde(default)]
    pub present: Option<bool>,
    /// When true, the event must belong to a run that never sealed (the
    /// durable-resume seam is the only place this is true).
    #[serde(default)]
    pub in_unsealed_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level {
    pub level: u8,
    pub requires: Vec<Pred>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveRule {
    pub primitive: u8,
    pub name: String,
    /// If this predicate is unsatisfied the primitive is N/A: the workload
    /// never exercised it, which is an honest gap, not a zero.
    pub base: Pred,
    pub levels: Vec<Level>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scoring {
    pub rules_version: String,
    pub rules: Vec<PrimitiveRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrimitiveScore {
    pub primitive: u8,
    pub name: String,
    /// None means N/A: the base evidence never appeared.
    pub score: Option<u8>,
    pub evidence: String,
    /// A sample event id supporting the score, so the number points at a row.
    pub sample_event: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreSnapshot {
    pub scores: Vec<PrimitiveScore>,
    /// The minimum across primitives that are not N/A. None if all are N/A.
    pub overall: Option<u8>,
    pub rules_version: String,
    pub events_scored: usize,
}

impl Scoring {
    pub fn load(path: &Path) -> Result<Scoring, Fault> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Fault::new(
                format!("cannot read scoring rules {}: {e}", path.display()),
                "check the path; the tracked rules are config/scoring.json",
            )
        })?;
        serde_json::from_str(&text).map_err(|e| {
            Fault::new(
                format!("{} does not parse as scoring rules: {e}", path.display()),
                "each rule needs primitive, name, base, and ordered levels with requires and evidence",
            )
        })
    }

    /// Score every primitive against the events. `events` are envelopes with
    /// their subjects inlined under `_subject` (from `Ledger::events_with_subjects`).
    pub fn score(&self, events: &[Value]) -> ScoreSnapshot {
        // Which run ids never sealed, for the seam predicate.
        let sealed: std::collections::BTreeSet<&str> = events
            .iter()
            .filter(|e| e["kind"] == json!("run.seal"))
            .filter_map(|e| e["run_id"].as_str())
            .collect();

        let mut scores = Vec::new();
        for rule in &self.rules {
            let base_ok = pred_matches(&rule.base, events, &sealed).is_some();
            if !base_ok {
                scores.push(PrimitiveScore {
                    primitive: rule.primitive,
                    name: rule.name.clone(),
                    score: None,
                    evidence: "N/A: no telemetry for this primitive in this ledger".to_string(),
                    sample_event: None,
                });
                continue;
            }
            // The score is the highest level for which that level and every
            // lower level are fully satisfied. A gap stops the climb.
            let mut best = 0u8;
            let mut evidence = String::from("base evidence present");
            let mut sample = None;
            let mut sorted: Vec<&Level> = rule.levels.iter().collect();
            sorted.sort_by_key(|l| l.level);
            for level in sorted {
                let all: Option<Vec<String>> = level
                    .requires
                    .iter()
                    .map(|p| pred_matches(p, events, &sealed))
                    .collect();
                match all {
                    Some(ids) => {
                        best = level.level;
                        evidence = level.evidence.clone();
                        sample = ids.into_iter().find(|s| !s.is_empty());
                    }
                    None => break,
                }
            }
            scores.push(PrimitiveScore {
                primitive: rule.primitive,
                name: rule.name.clone(),
                score: Some(best),
                evidence,
                sample_event: sample,
            });
        }
        let overall = scores.iter().filter_map(|s| s.score).min();
        ScoreSnapshot {
            scores,
            overall,
            rules_version: self.rules_version.clone(),
            events_scored: events.len(),
        }
    }
}

/// Returns Some(sample_event_id) if the predicate holds, None otherwise. The
/// sample id lets a score point at a supporting row.
fn pred_matches(
    pred: &Pred,
    events: &[Value],
    sealed: &std::collections::BTreeSet<&str>,
) -> Option<String> {
    let min = pred.min.unwrap_or(1);
    let mut count = 0u64;
    let mut sample = None;
    for ev in events {
        if ev["kind"] != json!(pred.kind) {
            continue;
        }
        if pred.in_unsealed_run {
            let run_id = ev["run_id"].as_str().unwrap_or("");
            if sealed.contains(run_id) {
                continue;
            }
        }
        if let Some(pointer) = &pred.pointer {
            let at = ev["_subject"]
                .pointer(pointer)
                .cloned()
                .unwrap_or(Value::Null);
            if let Some(expected) = &pred.equals {
                if at != *expected {
                    continue;
                }
            } else if pred.present == Some(true) && at.is_null() {
                continue;
            }
        }
        count += 1;
        if sample.is_none() {
            sample = Some(ev["id"].as_str().unwrap_or("").to_string());
        }
    }
    if count >= min {
        Some(sample.unwrap_or_default())
    } else {
        None
    }
}

impl ScoreSnapshot {
    pub fn subject(&self) -> Value {
        json!(self)
    }

    /// A markdown scorecard, the console in text form.
    pub fn markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("| Primitive | Score | Evidence |\n|---|---|---|\n");
        for p in &self.scores {
            let score = p
                .score
                .map(|n| n.to_string())
                .unwrap_or_else(|| "N/A".into());
            s.push_str(&format!(
                "| {:02} {} | {} | {} |\n",
                p.primitive, p.name, score, p.evidence
            ));
        }
        let overall = self
            .overall
            .map(|n| n.to_string())
            .unwrap_or_else(|| "N/A".into());
        s.push_str(&format!(
            "\n**Overall level: {overall}** (the minimum across {} scored primitives, not the average). Rules {}, {} events scored.\n",
            self.scores.iter().filter(|p| p.score.is_some()).count(),
            self.rules_version,
            self.events_scored
        ));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, run_id: &str, kind: &str, subject: Value) -> Value {
        json!({ "id": id, "run_id": run_id, "kind": kind, "_subject": subject })
    }

    fn rules() -> Scoring {
        serde_json::from_value(json!({
            "rules_version": "test-1",
            "rules": [
                {
                    "primitive": 11, "name": "Observability",
                    "base": { "kind": "model.call" },
                    "levels": [
                        { "level": 3, "requires": [{ "kind": "model.call" }], "evidence": "calls on the ledger" },
                        { "level": 4, "requires": [{ "kind": "run.open", "pointer": "/restored_checkpoint", "present": true }], "evidence": "resume seam recorded" }
                    ]
                },
                {
                    "primitive": 5, "name": "Execution",
                    "base": { "kind": "tool.request" },
                    "levels": [
                        { "level": 4, "requires": [{ "kind": "tool.request", "pointer": "/sandbox", "equals": "seatbelt" }], "evidence": "sandboxed" }
                    ]
                },
                {
                    "primitive": 9, "name": "Skills",
                    "base": { "kind": "skill.resolve" },
                    "levels": [{ "level": 3, "requires": [{ "kind": "skill.resolve" }], "evidence": "x" }]
                }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn scores_from_telemetry_and_na_for_absent() {
        let events = vec![
            ev("e0", "r1", "model.call", json!({})),
            ev("e1", "r1", "tool.request", json!({ "sandbox": "seatbelt" })),
            // no restored_checkpoint anywhere, so primitive 11 caps at 3.
        ];
        let snap = rules().score(&events);
        let p11 = snap.scores.iter().find(|p| p.primitive == 11).unwrap();
        assert_eq!(p11.score, Some(3), "no seam, so observability caps at 3");
        let p5 = snap.scores.iter().find(|p| p.primitive == 5).unwrap();
        assert_eq!(p5.score, Some(4));
        let p9 = snap.scores.iter().find(|p| p.primitive == 9).unwrap();
        assert_eq!(p9.score, None, "no skill telemetry, so N/A not 0");
        // Overall is the minimum of the scored primitives (3), ignoring N/A.
        assert_eq!(snap.overall, Some(3));
    }

    #[test]
    fn a_seam_lifts_observability_to_4() {
        let events = vec![
            ev("e0", "r1", "model.call", json!({})),
            ev(
                "e1",
                "r2",
                "run.open",
                json!({ "restored_checkpoint": "r1-ckpt-1" }),
            ),
        ];
        let snap = rules().score(&events);
        let p11 = snap.scores.iter().find(|p| p.primitive == 11).unwrap();
        assert_eq!(p11.score, Some(4));
        assert_eq!(p11.sample_event.as_deref(), Some("e1"));
    }

    #[test]
    fn overall_is_the_minimum_not_the_average() {
        // One primitive at 4, one at 3; overall must be 3.
        let events = vec![
            ev("e0", "r1", "model.call", json!({})),
            ev(
                "e1",
                "r2",
                "run.open",
                json!({ "restored_checkpoint": "c" }),
            ),
            ev("e2", "r1", "tool.request", json!({ "sandbox": "none" })),
        ];
        let snap = rules().score(&events);
        // p11 -> 4, p5 -> base present but level-4 requires seatbelt (not met) -> 0.
        assert_eq!(snap.overall, Some(0), "a floor of 0 caps the whole");
    }
}
