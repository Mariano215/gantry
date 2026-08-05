//! Slice 05 integration: a failing sensor blocks and its verdict names the
//! fix; the same sensor passes once the artifact is corrected; a sensor that
//! cannot fail is recorded as broken, not clean. Both attempts are on the
//! ledger under one run.

use gantry::gateway::Pinning;
use gantry::ledger::{self, Ledger};
use gantry::sandbox::Sandbox;
use gantry::sensor::{Sensor, SensorRun, Verdict};
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
        permission_mode: None,
    }
}

/// The tracked sensor, not a copy of it. Every test below therefore gates on
/// the check that actually ships.
fn no_key_sensor() -> Sensor {
    Sensor::load(&repo_path("docs/proof/fixtures/no-private-key.json")).unwrap()
}

fn sandbox(name: &str) -> Sandbox {
    let dir =
        std::env::temp_dir().join(format!("gantry-sensor-it-sb-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    Sandbox::per_run(&dir, &[]).unwrap()
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
    assert!(first.message.unwrap().contains("Remove the key material"));

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

/// The key material this project would actually leak, one case per branch of
/// the widened check. The hex here is hand-written, not the tracked fixture
/// seed, so the suite never carries a copy of a real key.
#[test]
fn key_material_beyond_one_pem_header_is_caught() {
    let s = no_key_sensor();
    let sb = sandbox("widened");
    let cases = [
        (
            "a raw ed25519 seed on a line of its own, the shape of config/actor-key-fixture.seed",
            "finding 3: the signing seed is committed\n7c93e0a5b16d482fa0c35e91d7b4602ff81a3c5d69e024b7a1f8c60d35e912ab\n",
        ),
        (
            "an openssh private key block",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----\n",
        ),
        (
            "an rsa pem header",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\n",
        ),
        (
            "an ec pem header",
            "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIOd\n",
        ),
        (
            "an encrypted pem header",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFHDBO\n",
        ),
        (
            "a seed labelled as one, inline in json",
            "{\"actor_seed\": \"e21a7f4c08b6d395e7c1042fa8b36d59071e4c8a2b6f30d95e1a7c4b08d6f321\"}\n",
        ),
    ];
    for (label, content) in cases {
        let v = s.evaluate(&sb, "findings.md", content).unwrap();
        assert_eq!(v.verdict, Verdict::Fail, "{label} must not pass the check");
        assert!(v.blocked, "{label} must block");
    }
}

/// The other direction, and the one that decides whether the sensor survives
/// contact with this project: the hashes it prints everywhere are not key
/// material. The inputs are the tracked files and a ledger written by this
/// test, not invented examples.
#[test]
fn the_hashes_this_project_emits_do_not_trip_the_check() {
    let dir = workdir("hashes");
    let led = dir.join("ledger");
    let artifact = dir.join("findings.md");
    fs::write(&artifact, "finding: nothing to report\n").unwrap();
    let mut run = SensorRun::open(
        Ledger::init(&led).unwrap(),
        "laptop",
        "sha256:test",
        "sensor-test",
        &pin(&dir),
    )
    .unwrap();
    run.gate(&no_key_sensor(), &artifact).unwrap();
    run.seal().unwrap();

    let s = no_key_sensor();
    let sb = sandbox("hashes");
    let mut documents = vec![
        (
            "config/policy.json".to_string(),
            fs::read_to_string(repo_path("config/policy.json")).unwrap(),
        ),
        (
            "config/instruction-reviews.jsonl".to_string(),
            fs::read_to_string(repo_path("config/instruction-reviews.jsonl")).unwrap(),
        ),
    ];
    documents.push((
        "a real ledger, envelopes and signed heads".to_string(),
        fs::read_to_string(led.join("events.jsonl")).unwrap()
            + &fs::read_to_string(led.join("heads.jsonl")).unwrap(),
    ));
    for (label, content) in documents {
        let v = s.evaluate(&sb, &label, &content).unwrap();
        assert_eq!(
            v.verdict,
            Verdict::Pass,
            "{label} is this system's own telemetry; a sensor that fires on it gets switched off"
        );
    }
}

/// The multi-control mechanism doing something. The check here is the one
/// this sensor shipped with before the widening: it rejects the plain PEM
/// control and passes the OpenSSH one, so declaring six controls and
/// rejecting only some of them is reported broken, never as a clean pass.
#[test]
fn a_check_that_misses_one_of_several_negative_controls_is_broken() {
    let mut narrow = no_key_sensor();
    narrow.id = "narrow-key-check".into();
    narrow.check = "! grep -q 'BEGIN PRIVATE KEY' {target}".into();
    let sb = sandbox("narrow");
    let v = narrow
        .evaluate(&sb, "findings.md", "nothing to see")
        .unwrap();
    assert_eq!(
        v.verdict,
        Verdict::Broken,
        "a check that only rejects some of its controls is broken, not clean"
    );
    let m = v.message.unwrap();
    // Control 2 is the OpenSSH block, which "BEGIN PRIVATE KEY" never matches.
    assert!(
        m.contains("negative control 2 of 6"),
        "the message names which control went unrejected: {m}"
    );
    assert!(m.contains("cannot fail"));
}

/// The positive controls doing something. This is the naive widening the
/// design notes warn about, "64 hex characters is a secret", which rejects
/// every negative control and then fires on the project's own telemetry.
#[test]
fn a_check_that_fires_on_its_positive_control_is_broken_too() {
    let mut jumpy = no_key_sensor();
    jumpy.id = "hex-is-a-secret".into();
    jumpy.check = "! grep -Eq '(-----BEGIN [A-Z0-9 ]*PRIVATE KEY|[0-9a-f]{64})' {target}".into();
    let sb = sandbox("jumpy");
    let v = jumpy
        .evaluate(&sb, "findings.md", "nothing to see")
        .unwrap();
    assert_eq!(
        v.verdict,
        Verdict::Broken,
        "a check that rejects content it must accept is broken, not clean"
    );
    let m = v.message.unwrap();
    assert!(
        m.contains("positive control 1 of 2"),
        "the message names which control was wrongly rejected: {m}"
    );
}

/// The single-string spelling still loads, so the sensors that declare one
/// control did not need editing.
#[test]
fn a_control_reads_as_a_string_or_as_a_list() {
    let one = Sensor::load(&repo_path(
        "templates/laptop/config/sensors/instruction-lifecycle.json",
    ))
    .unwrap();
    assert_eq!(one.negative_control.all().len(), 1);
    assert!(one.positive_control.all().is_empty());

    let many = Sensor::load(&repo_path(
        "templates/laptop/config/sensors/no-private-key.json",
    ))
    .unwrap();
    assert_eq!(many.negative_control.all().len(), 6);
    assert_eq!(many.positive_control.all().len(), 2);
}
