//! Slice 05 integration: a failing sensor blocks and its verdict names the
//! fix; the same sensor passes once the artifact is corrected; a sensor that
//! cannot fail is recorded as broken, not clean. Both attempts are on the
//! ledger under one run.

use gantry::gateway::Pinning;
use gantry::ledger::{self, Ledger};
use gantry::sensor::{Sensor, SensorRun};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-sensor-it-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn pin(dir: &Path) -> Pinning {
    let pack = dir.join("pack.md");
    fs::write(&pack, "sensor bus").unwrap();
    Pinning {
        policy: repo_path("config/policy.json"),
        instructions: pack,
        settings: None,
        diverged: vec![],
    }
}

fn no_key_sensor() -> Sensor {
    serde_json::from_str(
        r#"{
        "id": "no-private-key",
        "kind": "computational",
        "placement": "pre_integration",
        "blocking": true,
        "check": "! grep -q 'BEGIN PRIVATE KEY' {target}",
        "fix": "Remove the embedded private key from the findings and reference it by a broker handle instead.",
        "negative_control": "-----BEGIN PRIVATE KEY-----\nMII...\n"
    }"#,
    )
    .unwrap()
}

fn events(led: &Path) -> Vec<Value> {
    fs::read_to_string(led.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn subject(led: &Path, envelope: &Value) -> Value {
    let hex_part = envelope["subject_hash"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:");
    serde_json::from_str(
        &fs::read_to_string(led.join("payloads").join(format!("{hex_part}.json"))).unwrap(),
    )
    .unwrap()
}

/// The block-then-correct arc, both attempts on one ledger.
#[test]
fn failing_sensor_blocks_then_passes_after_correction() {
    let dir = workdir("correct");
    let led = dir.join("ledger");
    let artifact = dir.join("findings.md");
    fs::write(
        &artifact,
        "finding: key found\n-----BEGIN PRIVATE KEY-----\nMII\n",
    )
    .unwrap();

    let mut run = SensorRun::open(
        Ledger::init(&led).unwrap(),
        "laptop",
        "sha256:test",
        "sensor-test",
        &pin(&dir),
    )
    .unwrap();

    let first = run.gate(&no_key_sensor(), &artifact).unwrap();
    assert_eq!(format!("{:?}", first.verdict), "Fail");
    assert!(first.blocked);
    assert!(first
        .message
        .unwrap()
        .contains("Remove the embedded private key"));

    // The agent corrects the artifact and reruns.
    fs::write(
        &artifact,
        "finding: a key was present; it is now referenced by handle db-key\n",
    )
    .unwrap();
    let second = run.gate(&no_key_sensor(), &artifact).unwrap();
    assert_eq!(format!("{:?}", second.verdict), "Pass");
    assert!(!second.blocked);

    run.seal().unwrap();

    let evs = events(&led);
    let kinds: Vec<&str> = evs.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["run.open", "sensor.verdict", "sensor.verdict", "run.seal"]
    );
    let v1 = subject(&led, &evs[1]);
    let v2 = subject(&led, &evs[2]);
    assert_eq!(v1["verdict"], "fail");
    assert_eq!(v1["blocked"], true);
    assert_eq!(v2["verdict"], "pass");
    // The seal records that a blocking failure happened this run, so a reader
    // sees the correction arc rather than only its clean end.
    let seal = subject(&led, evs.last().unwrap());
    assert_eq!(seal["blocked_any"], true);
    assert_eq!(seal["outcome"], "sealed-with-blocking-failure");
    assert!(ledger::verify(&led).unwrap().ok());
}

/// A sensor that passes its own negative control is broken, and the run is
/// sealed as such, not as clean.
#[test]
fn broken_sensor_is_reported_broken() {
    let dir = workdir("broken");
    let led = dir.join("ledger");
    let artifact = dir.join("findings.md");
    fs::write(&artifact, "anything at all").unwrap();

    let mut broken: Sensor = no_key_sensor();
    broken.id = "always-green".into();
    broken.check = "true # {target}".into();

    let mut run = SensorRun::open(
        Ledger::init(&led).unwrap(),
        "laptop",
        "sha256:test",
        "sensor-test",
        &pin(&dir),
    )
    .unwrap();
    let v = run.gate(&broken, &artifact).unwrap();
    assert_eq!(format!("{:?}", v.verdict), "Broken");
    run.seal().unwrap();

    let evs = events(&led);
    let verdict = subject(&led, &evs[1]);
    assert_eq!(verdict["verdict"], "broken");
    let seal = subject(&led, evs.last().unwrap());
    assert_eq!(seal["broken_any"], true);
    assert_eq!(seal["outcome"], "sealed-with-broken-sensor");
}
