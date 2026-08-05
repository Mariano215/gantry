//! The mechanized half of ci/scoring-rules-reviewed: every predicate in the
//! tracked scoring rules references an event kind the schema documents. A
//! predicate on a kind nothing can emit is a dead rule that silently caps a
//! primitive forever; this test makes that a build failure. The other half,
//! whether a predicate actually requires what its evidence string claims,
//! remains human review.

use gantry::scorer::Scoring;
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
