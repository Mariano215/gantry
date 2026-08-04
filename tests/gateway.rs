use gantry::gateway::{GatewayRun, Pinning};
use gantry::ledger::{self, Ledger};
use std::fs;
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-gw-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn pinning(dir: &Path) -> Pinning {
    let policy = dir.join("policy.md");
    let pack = dir.join("pack.md");
    fs::write(&policy, "policy v1").unwrap();
    fs::write(&pack, "you are an audit agent").unwrap();
    Pinning { policy, instructions: pack, settings: None }
}

#[test]
fn open_and_seal_bracket_the_run() {
    let dir = workdir("openseal");
    let pin = pinning(&dir);
    let led = dir.join("ledger");
    let run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    let head = run.seal("complete").unwrap();
    assert_eq!(head.size, 2, "run.open and run.seal");

    let report = ledger::verify(&led).unwrap();
    assert!(report.ok(), "sealed run verifies: {:?}", report.faults);

    let lines: Vec<String> = fs::read_to_string(led.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    let open: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    let seal: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    assert_eq!(open["kind"], "run.open");
    assert_eq!(open["seq"], 0);
    assert_eq!(seal["kind"], "run.seal");
    assert_eq!(seal["seq"], 1);
    assert_eq!(open["run_id"], seal["run_id"]);
    let auth = &open["authority"];
    assert_eq!(auth["profile"], "laptop");
    assert!(auth["policy_version"].as_str().unwrap().starts_with("sha256:"));
    assert!(auth["instruction_version"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(auth["diverged"], serde_json::json!([]));
}
