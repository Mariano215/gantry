//! Slice 07 integration: a durable task killed mid-run resumes from its last
//! checkpoint with nothing lost, and the ledger shows the seam. The kill is a
//! real one: the run is dropped without sealing, exactly as a killed process
//! leaves it.

use gantry::durable::{seam, DurableRun};
use gantry::gateway::Pinning;
use gantry::ledger::{self, Ledger};
use gantry::policy::Policy;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-dur-it-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn pin(dir: &Path) -> Pinning {
    let pack = dir.join("pack.md");
    fs::write(&pack, "durable").unwrap();
    Pinning {
        policy: repo_path("config/policy.json"),
        instructions: pack,
        settings: None,
        diverged: vec![],
        permission_mode: None,
    }
}

fn policy() -> Policy {
    Policy::load(&repo_path("config/policy.json")).unwrap()
}

#[test]
fn kill_mid_run_then_resume_loses_nothing() {
    let dir = workdir("resume");
    let led = dir.join("ledger");

    // First run: two of four steps, then "killed" by dropping without seal.
    {
        let ledger = Ledger::init(&led).unwrap();
        let mut run = DurableRun::open(ledger, &policy(), "audit", &pin(&dir)).unwrap();
        run.checkpoint_step(0, "a", json!({"n": 0})).unwrap();
        run.checkpoint_step(1, "b", json!({"n": 1})).unwrap();
        // No seal: the run is dropped here, as a kill would leave it.
    }

    // Resume: restore and finish.
    let ledger = Ledger::open(&led).unwrap();
    let (mut run, restored) = DurableRun::resume(ledger, &policy(), "audit", &pin(&dir)).unwrap();
    assert_eq!(restored.next_step, 2);
    assert_eq!(
        restored.results.len(),
        2,
        "the two pre-kill results are restored"
    );
    run.checkpoint_step(2, "c", json!({"n": 2})).unwrap();
    run.checkpoint_step(3, "d", json!({"n": 3})).unwrap();
    assert_eq!(
        run.results().len(),
        4,
        "nothing lost: all four steps present"
    );
    run.seal("complete").unwrap();

    // The ledger shows the seam.
    let events = Ledger::open(&led).unwrap().events_with_subjects().unwrap();
    let lines = seam(&events, "audit");
    assert!(lines
        .iter()
        .any(|l| l.contains("never sealed: this is the kill point")));
    assert!(lines.iter().any(|l| l.contains("restoring checkpoint")));
    assert!(lines
        .iter()
        .any(|l| l.contains("sealed: complete (4 steps)")));

    // Two run.open events, exactly one run.seal: the first run is the seam.
    let opens = events
        .iter()
        .filter(|e| e["kind"] == json!("run.open"))
        .count();
    let seals = events
        .iter()
        .filter(|e| e["kind"] == json!("run.seal"))
        .count();
    assert_eq!((opens, seals), (2, 1));

    // The resume's run.open names the checkpoint it restored.
    let resume_open = events
        .iter()
        .find(|e| {
            e["kind"] == json!("run.open") && e["_subject"]["restored_checkpoint"] != json!(null)
        })
        .unwrap();
    assert!(resume_open["_subject"]["restored_checkpoint"]
        .as_str()
        .unwrap()
        .contains("ckpt-1"));

    assert!(ledger::verify(&led).unwrap().ok());
}

#[test]
fn resume_without_a_checkpoint_is_refused() {
    let dir = workdir("nockpt");
    let led = dir.join("ledger");
    let ledger = Ledger::init(&led).unwrap();
    // Open a run but never checkpoint, then drop it.
    let run = DurableRun::open(ledger, &policy(), "audit", &pin(&dir)).unwrap();
    drop(run);
    let ledger = Ledger::open(&led).unwrap();
    match DurableRun::resume(ledger, &policy(), "audit", &pin(&dir)) {
        Ok(_) => panic!("resume without a checkpoint should be refused"),
        Err(err) => assert!(err.cause.contains("no checkpoint"), "{err}"),
    }
}
