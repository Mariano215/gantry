//! Slice 06 integration: a capability earns autonomy on clean sensor history
//! promoted by a named approver, is demoted automatically by the next
//! failure, and the whole arc reads back out of the ledger. Uses a small
//! demo policy so the threshold is reachable in a test.

use gantry::gateway::Pinning;
use gantry::ledger::{self, Ledger};
use gantry::policy::{Policy, Rung};
use gantry::sensor::Sensor;
use gantry::trust::{narrate, Orchestrator, TrustState};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-trust-it-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A minimal valid policy with a low promotion threshold, written to disk so
/// Policy::load computes its version. One capability, `demo.write`, starts
/// assisted with a rollback so its post gate is legal.
fn demo_policy(dir: &Path) -> PathBuf {
    let policy = json!({
        "v": 1,
        "profile": "laptop",
        "profile_requirements": { "egress": { "allow": [] } },
        "capabilities": [
            {"id": "demo.write", "tools": ["Write(**)"], "effect": "write.local", "rung": "assisted", "rollback": "git.worktree"}
        ],
        "rules": [
            {"id": "r-write", "match": {"capability": "demo.write"}, "action": "allow"},
            {"id": "r-default", "match": {}, "action": "deny", "message": "Declare the tool first in config/policy.json."}
        ],
        "trust_budget": {
            "promotion": { "runs_at_rung": 3, "approver": "named", "named_approvers": ["user:boss@corp"] },
            "demotion": { "triggers": ["sensor.fail"], "to": "one_rung_down", "automatic": true }
        }
    });
    let p = dir.join("policy.json");
    fs::write(&p, serde_json::to_string_pretty(&policy).unwrap()).unwrap();
    p
}

fn sensor() -> Sensor {
    serde_json::from_str(
        r#"{
        "id": "no-private-key",
        "kind": "computational",
        "placement": "post_integration",
        "blocking": true,
        "check": "! grep -q 'BEGIN PRIVATE KEY' {target}",
        "fix": "Remove the embedded private key and reference it by handle.",
        "negative_control": "-----BEGIN PRIVATE KEY-----\n"
    }"#,
    )
    .unwrap()
}

fn pin(dir: &Path, policy_path: &Path) -> Pinning {
    let pack = dir.join("pack.md");
    fs::write(&pack, "orchestrator").unwrap();
    Pinning {
        policy: policy_path.to_path_buf(),
        instructions: pack,
        settings: None,
        diverged: vec![],
        permission_mode: None,
    }
}

fn open(dir: &Path, led: &Path, policy_path: &Path) -> Orchestrator {
    let ledger = if led.join("events.jsonl").exists() {
        Ledger::open(led).unwrap()
    } else {
        Ledger::init(led).unwrap()
    };
    Orchestrator::open(
        ledger,
        Policy::load(policy_path).unwrap(),
        "trust-test",
        &pin(dir, policy_path),
    )
    .unwrap()
}

fn events(led: &Path) -> Vec<Value> {
    Ledger::open(led).unwrap().events_with_subjects().unwrap()
}

#[test]
fn earns_autonomy_then_is_demoted_by_the_next_failure() {
    let dir = workdir("arc");
    let policy_path = demo_policy(&dir);
    let led = dir.join("ledger");
    let clean = dir.join("clean.md");
    fs::write(&clean, "a clean finding").unwrap();

    // Three clean runs, promoted on the third by the named approver.
    for i in 0..3 {
        let mut orch = open(&dir, &led, &policy_path);
        let out = orch
            .step("demo.write", &sensor(), &clean, Some("user:boss@corp"))
            .unwrap();
        orch.seal("complete").unwrap();
        if i < 2 {
            assert_eq!(
                out.rung_after,
                Rung::Assisted,
                "no promotion before threshold"
            );
            assert_eq!(out.change, None);
        } else {
            assert_eq!(
                out.rung_after,
                Rung::Autonomous,
                "promoted on the third clean run"
            );
            assert_eq!(out.change, Some("promotion"));
        }
    }

    // The next run trips the sensor and demotes automatically.
    let bad = dir.join("bad.md");
    fs::write(&bad, "leak: -----BEGIN PRIVATE KEY-----").unwrap();
    let mut orch = open(&dir, &led, &policy_path);
    let out = orch
        .step("demo.write", &sensor(), &bad, Some("user:boss@corp"))
        .unwrap();
    orch.seal("complete").unwrap();
    assert_eq!(out.rung_before, Rung::Autonomous);
    assert_eq!(out.rung_after, Rung::Assisted);
    assert_eq!(out.change, Some("demotion"));

    // The whole arc reads back out of the ledger.
    let evs = events(&led);
    let story = narrate(&evs, "demo.write");
    assert_eq!(
        story[0],
        "assisted -> autonomous (earned by user:boss@corp)"
    );
    assert_eq!(story[1], "autonomous -> assisted (demotion)");
    let state = TrustState::replay(&evs, "demo.write", Rung::Assisted);
    assert_eq!(state.rung, Rung::Assisted);

    // The promotion carries an approval event before the rung.change.
    let kinds: Vec<&str> = evs.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    let approve_idx = kinds.iter().position(|k| *k == "approval").unwrap();
    let change_idx = kinds.iter().position(|k| *k == "rung.change").unwrap();
    assert!(
        approve_idx < change_idx,
        "approval precedes the rung change it authorises"
    );
    let approval = &evs[approve_idx]["_subject"];
    assert_eq!(approval["verdict"], "approve");
    assert_eq!(approval["approver"]["id"], "user:boss@corp");

    assert!(ledger::verify(&led).unwrap().ok());
}

#[test]
fn an_unpermitted_approver_cannot_promote() {
    let dir = workdir("badapprover");
    let policy_path = demo_policy(&dir);
    let led = dir.join("ledger");
    let clean = dir.join("clean.md");
    fs::write(&clean, "clean").unwrap();
    for _ in 0..2 {
        let mut orch = open(&dir, &led, &policy_path);
        orch.step("demo.write", &sensor(), &clean, Some("user:intern@corp"))
            .unwrap();
        orch.seal("complete").unwrap();
    }
    // Third clean run would earn promotion, but the approver is not permitted.
    let mut orch = open(&dir, &led, &policy_path);
    let err = orch
        .step("demo.write", &sensor(), &clean, Some("user:intern@corp"))
        .unwrap_err();
    assert!(err.cause.contains("not a permitted approver"), "{err}");
}

#[test]
fn earned_promotion_without_an_approver_is_refused() {
    let dir = workdir("noapprover");
    let policy_path = demo_policy(&dir);
    let led = dir.join("ledger");
    let clean = dir.join("clean.md");
    fs::write(&clean, "clean").unwrap();
    for _ in 0..2 {
        let mut orch = open(&dir, &led, &policy_path);
        orch.step("demo.write", &sensor(), &clean, None).unwrap();
        orch.seal("complete").unwrap();
    }
    let mut orch = open(&dir, &led, &policy_path);
    let err = orch
        .step("demo.write", &sensor(), &clean, None)
        .unwrap_err();
    assert!(err.cause.contains("no approver was named"), "{err}");
}
