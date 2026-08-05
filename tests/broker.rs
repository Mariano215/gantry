//! Slice 03 integration: every tool call leaves a request, exactly one
//! policy decision, and a result on the ledger; denials name their rule; the
//! registry refuses loose definitions. These tests run the tracked
//! config/policy.json, not a fixture, so the policy the proof cites is the
//! policy under test.

use gantry::broker::{BrokerRun, ToolDef};
use gantry::gateway::Pinning;
use gantry::ledger::{self, Ledger};
use gantry::policy::Policy;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-br-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn tracked_policy() -> Policy {
    Policy::load(&repo_path("config/policy.json")).unwrap()
}

fn pinning(dir: &Path) -> Pinning {
    let pack = dir.join("pack.md");
    fs::write(&pack, "you are an audit agent").unwrap();
    Pinning {
        policy: repo_path("config/policy.json"),
        instructions: pack,
        settings: None,
        diverged: vec![],
    }
}

fn open_run(dir: &Path, name: &str) -> (BrokerRun, PathBuf) {
    let led = dir.join(format!("ledger-{name}"));
    let mut run = BrokerRun::open(
        Ledger::init(&led).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    (run, led)
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

/// The slice's headline attack: a genuinely destructive command is denied,
/// and the ledger names the rule, the policy version and the identity.
#[test]
fn destructive_command_denied_and_rule_named() {
    let dir = workdir("destructive");
    let (mut run, led) = open_run(&dir, "destructive");
    let fault = run.call("Bash", "rm -rf /").unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("r-destructive-shell"), "{fault}");
    assert!(
        fault.fix.contains("Scope the deletion"),
        "fix names the action: {fault}"
    );

    let evs = events(&led);
    // run.open, two registrations, request, decision, result, seal.
    let kinds: Vec<&str> = evs.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "run.open",
            "tool.register",
            "tool.register",
            "tool.request",
            "policy.decision",
            "tool.result",
            "run.seal"
        ]
    );

    let decision = subject(&led, &evs[4]);
    assert_eq!(decision["verdict"], "deny");
    assert_eq!(decision["rule"], "r-destructive-shell");
    assert_eq!(decision["capability"], "shell.exec");
    assert_eq!(decision["identity"]["id"], "user:mariano@local");
    assert!(!decision["message"].as_str().unwrap().is_empty());
    // The policy version in force is on the envelope of the decision itself.
    let policy_version = tracked_policy().policy_version.unwrap();
    assert_eq!(evs[4]["authority"]["policy_version"], json!(policy_version));

    let result = subject(&led, &evs[5]);
    assert_eq!(result["outcome"], "denied");
    assert_eq!(result["taint"], false);
    let request = subject(&led, &evs[3]);
    assert_eq!(result["request_id"], request["request_id"]);

    assert!(ledger::verify(&led).unwrap().ok());
}

#[test]
fn credential_file_read_denied() {
    let dir = workdir("credfile");
    let (mut run, led) = open_run(&dir, "credfile");
    let fault = run.call("Read", "./.env").unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("r-credential-file"), "{fault}");

    let evs = events(&led);
    let decision = subject(&led, &evs[4]);
    assert_eq!(decision["verdict"], "deny");
    assert_eq!(decision["rule"], "r-credential-file");
    assert_eq!(decision["capability"], "repo.read");
}

#[test]
fn egress_denied_on_laptop_profile() {
    let dir = workdir("egress");
    let (mut run, led) = open_run(&dir, "egress");
    let fault = run.call("Bash", "curl https://example.com").unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("r-egress-laptop"), "{fault}");
    let evs = events(&led);
    let decision = subject(&led, &evs[4]);
    assert_eq!(decision["capability"], "net.egress");
    assert_eq!(decision["effect"], "irreversible");
}

/// Allow on a pre gate is a hold: the call blocks, nothing executes, and the
/// obligation is an approval that no mechanism can yet grant.
#[test]
fn publish_holds_and_does_not_execute() {
    let dir = workdir("publish");
    let (mut run, led) = open_run(&dir, "publish");
    let marker = dir.join("pushed-marker");
    let cmd = format!("git push origin main && touch {}", marker.display());
    let fault = run.call("Bash", &cmd).unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("r-publish"), "{fault}");
    assert!(!marker.exists(), "a held call must not execute");

    let evs = events(&led);
    let decision = subject(&led, &evs[4]);
    assert_eq!(decision["verdict"], "hold");
    assert_eq!(decision["gate"], "pre");
    assert_eq!(decision["obligation"], "approval");
    let result = subject(&led, &evs[5]);
    assert_eq!(result["outcome"], "blocked");
}

/// The registry attack from the plan: a tool declared as "run any shell
/// command" with an open schema is refused, and the refusal is recorded.
#[test]
fn loose_tool_definition_is_rejected_and_recorded() {
    let dir = workdir("loose");
    let (mut run, led) = open_run(&dir, "loose");
    let def = ToolDef {
        name: "shell.any".into(),
        description: "Run any shell command.".into(),
        input_schema: json!({"type": "object"}),
    };
    let fault = run.register(&def).unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("rejected"), "{fault}");
    assert!(
        fault.cause.contains("no properties"),
        "names the looseness: {fault}"
    );

    let evs = events(&led);
    let reg = subject(&led, &evs[3]);
    assert_eq!(reg["verdict"], "rejected");
    assert!(reg["reason"]
        .as_str()
        .unwrap()
        .contains("any argument shape"));
    assert!(ledger::verify(&led).unwrap().ok());
}

/// Closed schema but a name no capability declares: still refused.
#[test]
fn undeclared_tool_is_refused_registration() {
    let dir = workdir("undeclared");
    let (mut run, _led) = open_run(&dir, "undeclared");
    let def = ToolDef {
        name: "Telemetry".into(),
        description: "Post run telemetry to a collector.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {"endpoint": {"type": "string"}},
            "additionalProperties": false,
        }),
    };
    let fault = run.register(&def).unwrap_err();
    assert!(fault.fix.contains("undeclared is denied"), "{fault}");
}

#[test]
fn allowed_read_executes_and_taints() {
    let dir = workdir("read-ok");
    let f = dir.join("note.txt");
    fs::write(&f, "hello from the working tree").unwrap();
    let (mut run, led) = open_run(&dir, "read-ok");
    let out = run.call("Read", &f.display().to_string()).unwrap();
    run.seal("complete").unwrap();
    assert_eq!(out.content, "hello from the working tree");
    assert!(out.taint, "file content is untrusted input");

    let evs = events(&led);
    let decision = subject(&led, &evs[4]);
    assert_eq!(decision["verdict"], "allow");
    assert_eq!(decision["rule"], "r-read-repo");
    assert_eq!(decision["obligation"], Value::Null);
    let result = subject(&led, &evs[5]);
    assert_eq!(result["outcome"], "ok");
    assert_eq!(result["taint"], true);
    assert!(result["result_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

/// An allowed post-gate call executes, but the seal cannot then claim clean:
/// the outstanding review count is written into the seal.
#[test]
fn post_gate_review_obligation_reaches_the_seal() {
    let dir = workdir("review");
    let (mut run, led) = open_run(&dir, "review");
    let out = run.call("Bash", "echo obligation").unwrap();
    assert_eq!(out.content.trim(), "obligation");
    run.seal("complete").unwrap();

    let evs = events(&led);
    let decision = subject(&led, &evs[4]);
    assert_eq!(decision["verdict"], "allow");
    assert_eq!(decision["gate"], "post");
    assert_eq!(decision["obligation"], "review");
    let seal = subject(&led, evs.last().unwrap());
    assert_eq!(seal["outcome"], "complete-with-outstanding-review");
    assert_eq!(seal["outstanding_reviews"], 1);
}

#[test]
fn unregistered_tool_never_reaches_the_policy() {
    let dir = workdir("unregistered");
    let (mut run, led) = open_run(&dir, "unregistered");
    let fault = run.call("Grep", "password").unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("not registered"), "{fault}");
    let evs = events(&led);
    let kinds: Vec<&str> = evs.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        ["run.open", "tool.register", "tool.register", "run.seal"]
    );
}

/// Resolve-to-execute wiring: a delegated run records subagent.spawn, an
/// in-grant call executes, and a call whose capability is outside the grant
/// is denied at the chokepoint with rule r-delegation, not by the runner's
/// diligence.
#[test]
fn a_delegated_grant_narrows_the_chokepoint() {
    let dir = workdir("delegated");
    let f = dir.join("step.md");
    fs::write(&f, "step body").unwrap();
    let (mut run, led) = open_run(&dir, "delegated");
    run.delegate_scope("repo-audit", "1.0", &["repo.read".into()])
        .unwrap();
    let ok = run.call("Read", &f.display().to_string()).unwrap();
    assert_eq!(ok.content, "step body");
    let fault = run.call("Bash", "echo outside the grant").unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("r-delegation"), "{fault}");
    assert!(fault.fix.contains("delegated grant"), "{fault}");

    let evs = events(&led);
    let spawn = evs
        .iter()
        .find(|e| e["kind"] == json!("subagent.spawn"))
        .expect("subagent.spawn on the ledger");
    let spawn_subject = subject(&led, spawn);
    assert_eq!(spawn_subject["granted"], json!(["repo.read"]));
    let denied = evs
        .iter()
        .filter(|e| e["kind"] == json!("policy.decision"))
        .map(|e| subject(&led, e))
        .find(|s| s["verdict"] == json!("deny"))
        .expect("the out-of-grant denial is on the ledger");
    assert_eq!(denied["rule"], "r-delegation");
    assert_eq!(denied["capability"], "shell.exec");
}

/// ci/gate-uses-earned-rung: a demotion on the ledger tightens the broker's
/// gate on the next call. shell.exec declares autonomous (gate post for
/// write.local); after a recorded demotion to led, the same call holds pre,
/// and the decision records the earned rung, not the declared one.
#[test]
fn broker_gates_on_the_earned_rung_not_the_declared_one() {
    let dir = workdir("earned-rung");
    let led = dir.join("ledger-earned-rung");
    let mut ledger = Ledger::init(&led).unwrap();
    ledger
        .append(gantry::event::NewEvent {
            id: "demote-0".into(),
            run_id: "run-orch".into(),
            parent_id: None,
            seq: 0,
            ts: gantry::gateway::rfc3339_now(),
            kind: "rung.change".into(),
            actor: json!({"type": "system", "id": "system:orchestrator", "identity_source": "local", "rung": null}),
            authority: json!({}),
            subject: json!({"capability": "shell.exec", "from": "autonomous", "to": "led", "trigger": "demotion", "approver": null}),
            redacted: vec![],
            attestation: None,
        })
        .unwrap();
    let mut run = BrokerRun::open(
        Ledger::open(&led).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    let fault = run.call("Bash", "echo demoted").unwrap_err();
    run.seal("complete").unwrap();
    assert!(fault.cause.contains("held"), "{fault}");
    let evs = events(&led);
    let decision_env = evs
        .iter()
        .find(|e| e["kind"] == json!("policy.decision"))
        .unwrap();
    let decision = subject(&led, decision_env);
    assert_eq!(decision["rung"], "led", "the earned rung gates, not the declared autonomous");
    assert_eq!(decision["gate"], "pre");
    assert_eq!(decision["verdict"], "hold");
}

/// ci/policy-host-parity, run against the tracked host settings: every deny
/// entry the host can short-circuit resolves to deny or hold here.
#[test]
fn tracked_policy_has_host_parity() {
    let settings = fs::read_to_string(repo_path(".claude/settings.json")).unwrap();
    let faults = tracked_policy().host_parity(&settings).unwrap();
    assert!(
        faults.is_empty(),
        "host deny entries without a policy rule: {faults:?}"
    );
}
