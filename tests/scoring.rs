//! The mechanized half of ci/scoring-rules-reviewed: every predicate in the
//! tracked scoring rules references an event kind the schema documents. A
//! predicate on a kind nothing can emit is a dead rule that silently caps a
//! primitive forever; this test makes that a build failure. The other half,
//! whether a predicate actually requires what its evidence string claims,
//! remains human review.

use gantry::scorer::Scoring;
use serde_json::{json, Value};
use std::path::Path;

fn repo_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn every_scoring_predicate_kind_is_a_documented_event_kind() {
    let scoring = Scoring::load(&repo_path("config/scoring.json")).unwrap();
    let schema = std::fs::read_to_string(repo_path("docs/EVENT-SCHEMA.md")).unwrap();
    let mut kinds: Vec<String> = Vec::new();
    for rule in &scoring.rules {
        kinds.push(rule.base.kind.clone());
        for level in &rule.levels {
            for pred in &level.requires {
                kinds.push(pred.kind.clone());
            }
        }
    }
    kinds.sort();
    kinds.dedup();
    for kind in kinds {
        assert!(
            schema.contains(&format!("`{kind}`")),
            "scoring rule references event kind {kind}, which docs/EVENT-SCHEMA.md does not document; either document the kind or fix the rule"
        );
    }
}

#[test]
fn scoring_levels_are_unique_per_primitive_and_ascending() {
    let scoring = Scoring::load(&repo_path("config/scoring.json")).unwrap();
    for rule in &scoring.rules {
        let mut levels: Vec<u8> = rule.levels.iter().map(|l| l.level).collect();
        let sorted = {
            let mut s = levels.clone();
            s.sort();
            s.dedup();
            s
        };
        levels.sort();
        assert_eq!(
            levels, sorted,
            "primitive {} declares a duplicate level, which would make the climb ambiguous",
            rule.primitive
        );
        for level in &rule.levels {
            assert!(
                !level.evidence.trim().is_empty(),
                "primitive {} level {} has no evidence string; a score must say what it means",
                rule.primitive,
                level.level
            );
        }
    }
}

/// The template ships its own copy of the rules, and a harness scored under a
/// copy that has drifted from the tracked one is scored under rules nobody
/// reviewed.
#[test]
fn the_tracked_rules_and_the_template_copy_are_the_same_file() {
    let tracked = std::fs::read_to_string(repo_path("config/scoring.json")).unwrap();
    let template =
        std::fs::read_to_string(repo_path("templates/laptop/config/scoring.json")).unwrap();
    assert_eq!(
        tracked, template,
        "templates/laptop/config/scoring.json has drifted from config/scoring.json; copy the tracked rules over it, because a harness scoring itself under stale rules reports a number this repository never reviewed"
    );
}

fn ev(kind: &str, subject: Value) -> Value {
    json!({ "id": format!("ev-{kind}"), "run_id": "r1", "kind": kind, "_subject": subject })
}

fn score_of(events: &[Value], primitive: u8) -> Option<u8> {
    Scoring::load(&repo_path("config/scoring.json"))
        .unwrap()
        .score(events)
        .scores
        .iter()
        .find(|p| p.primitive == primitive)
        .unwrap()
        .score
}

/// Primitive 07 level 4 credits a human gate having run at an irreversible
/// step. What the human answered is not the level: a refusal is the gate
/// working. This is the property proof 13's first rule violated, asserted here
/// against the tracked rules so an inversion is a build failure rather than
/// something the next self-audit might notice.
#[test]
fn the_human_gate_scores_the_same_whether_the_human_said_yes_or_no() {
    // Levels 2 and 3: capability runs, then a promotion under a named
    // approver. The promotion writes its own `approval`, which is why level 4
    // matches on call_hash: a predicate on the kind alone is satisfied here,
    // and would hand level 4 to every ledger that reached level 3.
    let below = || {
        vec![
            ev("capability.run", json!({ "capability": "repo.write" })),
            ev("rung.change", json!({ "approver": "user:mariano@local" })),
            ev(
                "approval",
                json!({
                    "approver": { "id": "user:mariano@local", "source": "local" },
                    "verdict": "approve",
                    "decided": "promote repo.write from assisted to autonomous",
                }),
            ),
            ev(
                "policy.decision",
                json!({ "verdict": "hold", "rule": "r-publish" }),
            ),
        ]
    };
    let answered = |verdict: &str| {
        let mut evs = below();
        evs.push(ev(
            "approval",
            json!({
                "verdict": verdict,
                "approver": "user:mariano@local",
                "call_hash": "sha256:6aef52d1",
                "rule": "r-publish",
            }),
        ));
        evs
    };
    let approved = score_of(&answered("approve"), 7);
    let refused = score_of(&answered("deny"), 7);
    assert_eq!(
        approved, refused,
        "an approved call and a refused one scored differently, so primitive 07 level 4 pays for the answer instead of the gate"
    );
    assert_eq!(approved, Some(4));
    assert_eq!(
        score_of(&below(), 7),
        Some(3),
        "a held call nobody answered reached level 4; the promotion's own approval must not satisfy the predicate"
    );
}

/// Primitive 12 level 4 credits the drift walk having run. A ledger of matches
/// and a ledger of divergences are the same control working, and a ledger with
/// no walk is the state the level exists to distinguish.
#[test]
fn the_drift_walk_scores_the_same_whether_it_matched_or_diverged() {
    let below = || {
        vec![
            ev(
                "policy.decision",
                json!({ "verdict": "deny", "rule": "r-destructive-shell" }),
            ),
            ev(
                "run.open",
                json!({ "profile": "laptop", "unavailable": [] }),
            ),
        ]
    };
    let walked = |outcome: &str| {
        let mut evs = below();
        evs.push(ev(
            "drift.report",
            json!({ "field": "instruction_pack", "outcome": outcome }),
        ));
        evs
    };
    let matched = score_of(&walked("match"), 12);
    let diverged = score_of(&walked("divergence"), 12);
    assert_eq!(
        matched, diverged,
        "a clean walk and a divergent one scored differently, so primitive 12 level 4 pays for the verdict instead of the walk"
    );
    assert_eq!(matched, Some(4));
    assert_eq!(
        score_of(&below(), 12),
        Some(3),
        "a ledger with no drift walk reached level 4, so the level credits nothing"
    );
    // The other half of the level: a run that never recorded what this machine
    // could not provide has not checked its declaration at run open.
    let mut no_availability = walked("match");
    no_availability.retain(|e| e["kind"] != json!("run.open"));
    no_availability.push(ev("run.open", json!({ "profile": "laptop" })));
    assert_eq!(
        score_of(&no_availability, 12),
        Some(3),
        "a run.open with no availability list reached level 4; an absent list and a satisfied one must not read alike"
    );
}
