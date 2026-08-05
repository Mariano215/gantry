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
        permission_mode: None,
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
    // run.open, two registrations, request, decision, the demotion the denial
    // caused, result, seal. The rung.change sits between the decision and the
    // result because the decision is its cause and the result is what the
    // caller was told afterwards.
    let kinds: Vec<&str> = evs.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "run.open",
            "tool.register",
            "tool.register",
            "tool.request",
            "policy.decision",
            "rung.change",
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

    let result = subject(&led, &evs[6]);
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
    assert_eq!(
        decision["rung"], "led",
        "the earned rung gates, not the declared autonomous"
    );
    assert_eq!(decision["gate"], "pre");
    assert_eq!(decision["verdict"], "hold");
}

/// The tracked laptop profile declares an actor key, so a real broker run
/// signs every event it appends and the verifier reports them verified
/// against config/actor-keys.json rather than counting them unverified.
#[test]
fn a_real_run_is_signed_and_verifies_against_the_tracked_registry() {
    let dir = workdir("attested");
    let f = dir.join("note.txt");
    fs::write(&f, "content the run reads").unwrap();
    let (mut run, led) = open_run(&dir, "attested");
    run.call("Read", &f.display().to_string()).unwrap();
    run.seal("complete").unwrap();

    let registry = gantry::skills::KeyRegistry::load(&repo_path("config/actor-keys.json")).unwrap();
    let report = ledger::verify_with_actor_keys(&led, &registry.key_hexes()).unwrap();
    assert!(report.ok(), "faults: {:?}", report.faults);
    assert_eq!(
        report.attestations_verified,
        events(&led).len(),
        "every event of the run carries a verified attestation"
    );
    assert_eq!(report.attestations_unverified, 0);
    let key_id = &events(&led)[0]["attestation"]["key_id"];
    assert_eq!(
        key_id,
        &tracked_policy().profile_requirements["attestation"]["key_id"],
        "the key on the event is the key the profile declares"
    );
}

/// The laptop key's seed is tracked in this repository, so anyone holding the
/// checkout can produce a signature that verifies. That is acceptable for a
/// laptop profile and unacceptable to report as attribution, so the verifier
/// counts those separately. Without this the line a laptop run prints is
/// byte-identical to the line an HSM-backed deployment prints.
#[test]
fn a_verified_attestation_under_a_published_seed_is_counted_apart() {
    let dir = workdir("attested-published");
    let f = dir.join("note.txt");
    fs::write(&f, "content the run reads").unwrap();
    let (mut run, led) = open_run(&dir, "attested-published");
    run.call("Read", &f.display().to_string()).unwrap();
    run.seal("complete").unwrap();

    let registry = gantry::skills::KeyRegistry::load(&repo_path("config/actor-keys.json")).unwrap();
    let published = registry.published_seed_hexes();
    assert!(
        !published.is_empty(),
        "the tracked laptop key declares seed_published, or this test proves nothing"
    );

    let report =
        ledger::verify_with_actor_keys_and_published(&led, &registry.key_hexes(), &published)
            .unwrap();
    assert!(report.ok(), "faults: {:?}", report.faults);
    assert_eq!(
        report.attestations_under_published_seed, report.attestations_verified,
        "every laptop-profile attestation is signed under the published fixture seed"
    );

    // Told about no published seeds, the same ledger reports none: the count
    // follows the registry's declaration and is never inferred.
    let unqualified =
        ledger::verify_with_actor_keys_and_published(&led, &registry.key_hexes(), &[]).unwrap();
    assert_eq!(
        unqualified.attestations_verified,
        report.attestations_verified
    );
    assert_eq!(unqualified.attestations_under_published_seed, 0);
}

/// Altering a signed event after the fact is reported as alteration: the
/// attestation covers the fields the actor controls, so an edited envelope
/// no longer verifies under the key that signed it.
#[test]
fn altering_a_signed_event_is_reported_as_alteration() {
    let dir = workdir("attested-altered");
    let (run, led) = open_run(&dir, "attested-altered");
    run.seal("complete").unwrap();

    let path = led.join("events.jsonl");
    let mut lines: Vec<Value> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    lines[0]["ts"] = json!("2020-01-01T00:00:00.000Z");
    let rewritten: Vec<String> = lines
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect();
    fs::write(&path, rewritten.join("\n") + "\n").unwrap();

    let registry = gantry::skills::KeyRegistry::load(&repo_path("config/actor-keys.json")).unwrap();
    let report = ledger::verify_with_actor_keys(&led, &registry.key_hexes()).unwrap();
    assert!(!report.ok(), "an altered signed event must fault");
    assert!(
        report.faults.iter().any(|f| f
            .fault
            .cause
            .contains("carries an attestation under registered key")
            && f.fault.fix.contains("altered after signing")),
        "the fault names alteration: {:?}",
        report.faults
    );
}

/// The laptop fixture seed is tracked in this repository, so a signature under
/// it proves which run wrote an event and never who operated it. A `team` or
/// `regulated` attestation is read as attribution, so a non-laptop profile
/// declaring that key refuses to start rather than producing signatures that
/// read like attribution and are not.
#[test]
fn a_non_laptop_profile_declaring_a_published_seed_refuses_to_start() {
    let dir = workdir("attested-published-seed");
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(repo_path("config/policy.json")).unwrap())
            .unwrap();
    doc["profile"] = json!("regulated");
    let policy_path = dir.join("policy.json");
    fs::write(&policy_path, serde_json::to_string(&doc).unwrap()).unwrap();
    // The seed and the registry travel with the policy directory, so this run
    // can load the declared key and read what the registry says about it.
    for file in ["actor-key-fixture.seed", "actor-keys.json"] {
        fs::copy(repo_path(&format!("config/{file}")), dir.join(file)).unwrap();
    }

    let pin = Pinning {
        policy: policy_path.clone(),
        instructions: dir.join("pack.md"),
        settings: None,
        diverged: vec![],
        permission_mode: None,
    };
    fs::write(&pin.instructions, "you are an audit agent").unwrap();
    let led = dir.join("ledger-published-seed");
    let fault = BrokerRun::open(
        Ledger::init(&led).unwrap(),
        Policy::load(&policy_path).unwrap(),
        "broker-test",
        &pin,
    )
    .map(|_| ())
    .unwrap_err();
    assert!(
        fault.cause.contains("regulated") && fault.cause.contains("published"),
        "the refusal names the profile and the reason: {fault}"
    );
    assert!(
        fault.fix.contains("seed_published"),
        "the fix names the registry field to change: {fault}"
    );
    assert!(
        !led.join("events.jsonl").exists()
            || fs::read_to_string(led.join("events.jsonl"))
                .unwrap()
                .trim()
                .is_empty(),
        "a refused run appends nothing"
    );

    // The same declaration on the laptop profile is accepted, so the refusal
    // is about the profile and not about the key being unusable.
    doc["profile"] = json!("laptop");
    fs::write(&policy_path, serde_json::to_string(&doc).unwrap()).unwrap();
    BrokerRun::open(
        Ledger::init(&dir.join("ledger-laptop-seed")).unwrap(),
        Policy::load(&policy_path).unwrap(),
        "broker-test",
        &pin,
    )
    .map(|_| ())
    .expect("the laptop profile may sign under the published fixture seed");
}

/// A profile that declares an actor key it cannot load refuses to start.
/// Appending unsigned under a profile that says it signs is the silent
/// degradation this refusal exists to prevent.
#[test]
fn a_profile_declaring_an_unloadable_actor_key_refuses_to_start() {
    let dir = workdir("attested-unloadable");
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(repo_path("config/policy.json")).unwrap())
            .unwrap();
    doc["profile_requirements"]["attestation"]["seed_file"] = json!("no-such-key.seed");
    let policy_path = dir.join("policy.json");
    fs::write(&policy_path, serde_json::to_string(&doc).unwrap()).unwrap();

    let pin = Pinning {
        policy: policy_path.clone(),
        instructions: dir.join("pack.md"),
        settings: None,
        diverged: vec![],
        permission_mode: None,
    };
    fs::write(&pin.instructions, "you are an audit agent").unwrap();
    let led = dir.join("ledger-unloadable");
    let fault = BrokerRun::open(
        Ledger::init(&led).unwrap(),
        Policy::load(&policy_path).unwrap(),
        "broker-test",
        &pin,
    )
    .map(|_| ())
    .unwrap_err();
    assert!(fault.cause.contains("no-such-key.seed"), "{fault}");
    assert!(
        fault.fix.contains("appending unsigned"),
        "the fix names the refusal rule: {fault}"
    );
    assert!(
        !led.join("events.jsonl").exists()
            || fs::read_to_string(led.join("events.jsonl"))
                .unwrap()
                .trim()
                .is_empty(),
        "a refused run appends nothing"
    );
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

/// `gantry template init` on the tracked template, returning the harness's
/// declared actor key id. The bundle is validated as a harness in its own
/// right before the key id is read, so a destination that would refuse to run
/// fails here rather than downstream.
fn init_harness(dest: &Path) -> String {
    let template = repo_path("templates/laptop");
    assert!(
        template_cmd(&["init", template.to_str().unwrap(), dest.to_str().unwrap()])
            .status
            .success(),
        "template init failed"
    );
    // The produced directory is the same bundle shape, so the validator the
    // template passes is the one the harness must pass in its own right.
    assert!(
        template_cmd(&["validate", dest.to_str().unwrap()])
            .status
            .success(),
        "the generated harness does not validate"
    );
    Policy::load(&dest.join("config/policy.json"))
        .unwrap()
        .profile_requirements["attestation"]["key_id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `gantry template <args>`, run as the binary a user runs.
fn template_cmd(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_gantry"))
        .arg("template")
        .args(args)
        .output()
        .unwrap()
}

/// The template ships no key material, so init generates the key. Two inits
/// must produce two signing identities: a template that handed every install
/// the same key would produce signatures that verify and attribute nothing,
/// which is exactly what the published-seed refusal already rules out for
/// every profile but laptop. The generated harness must also actually sign,
/// and its attestations must not be counted under a published seed.
#[test]
fn template_init_generates_a_per_harness_key_and_the_harness_signs() {
    let dir = workdir("template-init");
    let first = dir.join("first");
    let second = dir.join("second");
    let first_key = init_harness(&first);
    let second_key = init_harness(&second);
    assert_ne!(
        first_key, second_key,
        "each init generates its own key; a shared one would hand every install the same signing identity"
    );

    let led = first.join("ledger");
    let pin = Pinning {
        policy: first.join("config/policy.json"),
        instructions: first.join("instructions/pack.md"),
        settings: None,
        diverged: vec![],
        permission_mode: None,
    };
    let mut run = BrokerRun::open(
        Ledger::init(&led).unwrap(),
        Policy::load(&pin.policy).unwrap(),
        "template-init",
        &pin,
    )
    .unwrap();
    run.register_builtins().unwrap();
    run.call(
        "Read",
        &first.join("instructions/pack.md").display().to_string(),
    )
    .unwrap();
    run.seal("complete").unwrap();

    let registry =
        gantry::skills::KeyRegistry::load(&first.join("config/actor-keys.json")).unwrap();
    let published = registry.published_seed_hexes();
    assert!(
        published.is_empty(),
        "a generated key is held by this install, so the registry never marks its seed published"
    );
    let report =
        ledger::verify_with_actor_keys_and_published(&led, &registry.key_hexes(), &published)
            .unwrap();
    assert!(report.ok(), "faults: {:?}", report.faults);
    assert_eq!(
        report.attestations_verified,
        events(&led).len(),
        "every event of the run verifies against the generated registry"
    );
    assert_eq!(report.attestations_unverified, 0);
    assert_eq!(
        report.attestations_under_published_seed, 0,
        "the generated attestation is attribution, not the laptop fixture's provenance"
    );
    assert_eq!(
        events(&led)[0]["attestation"]["key_id"],
        json!(first_key),
        "the key on the event is the key the generated policy declares"
    );
}

/// Init refuses rather than overwriting, and a refused init leaves no seed.
/// Key material for a harness nobody finished building is worse than no
/// harness: it looks like a held key and belongs to nothing.
#[test]
fn a_refused_init_leaves_no_seed_and_never_clobbers_one() {
    let dir = workdir("template-init-refused");
    let occupied = dir.join("occupied");
    fs::create_dir_all(occupied.join("config")).unwrap();
    fs::write(occupied.join("config/policy.json"), "{}").unwrap();
    let template = repo_path("templates/laptop");
    let out = template_cmd(&[
        "init",
        template.to_str().unwrap(),
        occupied.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        !occupied.join("config/actor-key.seed").exists(),
        "a refused init must not leave a seed for a harness that does not exist"
    );
    assert_eq!(
        fs::read_to_string(occupied.join("config/policy.json")).unwrap(),
        "{}",
        "init never overwrites what is already there"
    );

    // The same refusal covers key material: an init into a directory that
    // already holds a seed must not replace it.
    let done = dir.join("done");
    init_harness(&done);
    let seed = fs::read_to_string(done.join("config/actor-key.seed")).unwrap();
    let again = template_cmd(&["init", template.to_str().unwrap(), done.to_str().unwrap()]);
    assert!(!again.status.success());
    assert_eq!(
        fs::read_to_string(done.join("config/actor-key.seed")).unwrap(),
        seed,
        "a second init never rewrites the first harness's key"
    );
}

// ---------- approvals for held calls ----------

/// `gantry approve` against a ledger, run from the repository root so it reads
/// the tracked config/policy.json the same way the broker does.
fn approve_cmd(led: &Path, request_id: &str, approver: &str) -> std::process::Output {
    approve_with(led, request_id, approver, "approve")
}

fn approve_with(
    led: &Path,
    request_id: &str,
    approver: &str,
    verdict: &str,
) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_gantry"))
        .arg("approve")
        .arg(led)
        .arg(request_id)
        .arg(approver)
        .arg(verdict)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap()
}

/// The request id of the first request on the ledger whose decision held.
fn held_request_id(led: &Path) -> String {
    let evs = events(led);
    let mut pending = None;
    for ev in &evs {
        match ev["kind"].as_str() {
            Some("tool.request") => pending = Some(subject(led, ev)),
            Some("policy.decision") => {
                let d = subject(led, ev);
                if d["verdict"] == "hold" {
                    if let Some(req) = pending.take() {
                        return req["request_id"].as_str().unwrap().to_string();
                    }
                }
            }
            _ => {}
        }
    }
    panic!("no held request on this ledger");
}

/// The headline: a held call is a dead end until an approval exists, and the
/// approval releases exactly the call it names. The decision stays a hold,
/// because a hold is what the policy computed; the release is a separate
/// event, so the record never says the policy permitted a call it held.
#[test]
fn an_approval_releases_the_held_call_and_the_decision_still_says_hold() {
    let dir = workdir("approve-releases");
    let led = dir.join("ledger-approve");
    let cmd = "git push origin main";
    {
        let mut run = BrokerRun::open(
            Ledger::init(&led).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", cmd).unwrap_err();
        run.seal("complete").unwrap();
    }

    let request_id = held_request_id(&led);
    let out = approve_cmd(&led, &request_id, "user:mariano@local");
    assert!(
        out.status.success(),
        "approve failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The same call again. A new run, so a new request id: the grant has to be
    // found by the call's own identity, not by the id the approver saw.
    let before = events(&led).len();
    {
        let mut run = BrokerRun::open(
            Ledger::open(&led).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", cmd)
            .expect("the approval on the ledger releases this call");
        run.seal("complete").unwrap();
    }

    let evs = events(&led);
    let new: Vec<&Value> = evs[before..].iter().collect();
    let decision = new
        .iter()
        .find(|e| e["kind"] == "policy.decision")
        .map(|e| subject(&led, e))
        .expect("the released call still records its decision");
    assert_eq!(
        decision["verdict"], "hold",
        "the policy held this call and the decision must keep saying so"
    );
    let used = new
        .iter()
        .find(|e| e["kind"] == "approval.use")
        .map(|e| subject(&led, e))
        .expect("consuming an approval is itself an event");
    assert_eq!(used["rule"], "r-publish");
    assert_eq!(used["approver"], "user:mariano@local");
    assert_eq!(
        used["self_approved"], true,
        "the caller approved their own call, and the record says so rather than hiding it"
    );
    let result = new
        .iter()
        .find(|e| e["kind"] == "tool.result")
        .map(|e| subject(&led, e))
        .unwrap();
    assert_eq!(result["outcome"], "ok", "the approved call actually ran");
    assert!(ledger::verify(&led).unwrap().ok());
}

/// Single use. The second attempt at the same call finds the grant spent and
/// is held again, so an approval is permission for one call and not a
/// standing licence.
#[test]
fn an_approval_releases_one_call_and_not_the_next() {
    let dir = workdir("approve-single-use");
    let led = dir.join("ledger-single");
    let cmd = "git push origin main";
    let call_once = |expect_ok: bool| {
        let mut run = BrokerRun::open(
            if led.join("events.jsonl").exists() {
                Ledger::open(&led).unwrap()
            } else {
                Ledger::init(&led).unwrap()
            },
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        let outcome = run.call("Bash", cmd);
        run.seal("complete").unwrap();
        assert_eq!(outcome.is_ok(), expect_ok, "{outcome:?}");
    };

    call_once(false);
    let request_id = held_request_id(&led);
    assert!(approve_cmd(&led, &request_id, "user:mariano@local")
        .status
        .success());
    call_once(true);
    call_once(false);

    let spent = events(&led)
        .iter()
        .filter(|e| e["kind"] == "approval.use")
        .count();
    assert_eq!(spent, 1, "one grant, one use, however many attempts follow");
}

/// An approval names a call. A different call, held under the same rule by the
/// same policy, is not released by it.
#[test]
fn an_approval_does_not_release_a_different_call() {
    let dir = workdir("approve-other-call");
    let led = dir.join("ledger-other");
    {
        let mut run = BrokerRun::open(
            Ledger::init(&led).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", "git push origin main").unwrap_err();
        run.seal("complete").unwrap();
    }
    let request_id = held_request_id(&led);
    assert!(approve_cmd(&led, &request_id, "user:mariano@local")
        .status
        .success());

    // Same rule, same capability, different target, so a different call hash.
    let mut run = BrokerRun::open(
        Ledger::open(&led).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    let fault = run.call("Bash", "git push origin release").unwrap_err();
    run.seal("complete").unwrap();
    assert!(
        fault
            .cause
            .contains("no approval on this ledger releases it"),
        "an approval for one call must not release another: {fault}"
    );
}

/// An approval never reverses a denial. The CLI refuses to write one, which
/// matters because a denial is the policy's answer and an approval is only
/// ever the resolution of a hold.
#[test]
fn a_denied_call_cannot_be_approved() {
    let dir = workdir("approve-denied");
    let led = dir.join("ledger-denied");
    let mut run = BrokerRun::open(
        Ledger::init(&led).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    run.call("Bash", "rm -rf /").unwrap_err();
    run.seal("complete").unwrap();

    let evs = events(&led);
    let request = evs
        .iter()
        .find(|e| e["kind"] == "tool.request")
        .map(|e| subject(&led, e))
        .unwrap();
    let request_id = request["request_id"].as_str().unwrap();
    let out = approve_cmd(&led, request_id, "user:mariano@local");
    assert!(!out.status.success(), "a denial must not be approvable");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("only a held call can be approved"),
        "the refusal names the rule: {stderr}"
    );
    assert!(
        !events(&led).iter().any(|e| e["kind"] == "approval"),
        "a refused approval writes nothing"
    );
}

/// The consuming end re-derives permission rather than trusting that a grant
/// exists. A ledger is a file, so a grant can be put on it by something other
/// than `gantry approve`; here the grant is written while the profile permits
/// any approver, and consumed under a profile that names a closed set.
#[test]
fn a_grant_from_an_unpermitted_approver_does_not_release_the_call() {
    let dir = workdir("approve-unpermitted");
    let led = dir.join("ledger-unpermitted");
    let cmd = "git push origin main";
    {
        let mut run = BrokerRun::open(
            Ledger::init(&led).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", cmd).unwrap_err();
        run.seal("complete").unwrap();
    }
    let request_id = held_request_id(&led);
    assert!(approve_cmd(&led, &request_id, "user:mariano@local")
        .status
        .success());

    // The same ledger, now read under a policy whose approver set is closed
    // and does not contain the approver who signed that grant.
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(repo_path("config/policy.json")).unwrap())
            .unwrap();
    doc["trust_budget"]["promotion"]["approver"] = json!("named");
    doc["trust_budget"]["promotion"]["named_approvers"] = json!(["user:auditor@example.com"]);
    let strict_path = dir.join("strict-policy.json");
    fs::write(&strict_path, serde_json::to_string(&doc).unwrap()).unwrap();

    let mut run = BrokerRun::open(
        Ledger::open(&led).unwrap(),
        Policy::load(&strict_path).unwrap(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    let fault = run.call("Bash", cmd).unwrap_err();
    run.seal("complete").unwrap();
    assert!(
        fault.cause.contains("no approval on this ledger releases it"),
        "a grant from an approver the trust budget does not permit must not release a call: {fault}"
    );
    assert!(
        !events(&led).iter().any(|e| e["kind"] == "approval.use"),
        "an unusable grant is never consumed"
    );
}

/// A human who refuses is an approval with verdict deny, not an absent event.
/// The record has to distinguish "nobody looked at this" from "somebody looked
/// and said no", and the call stays held either way.
#[test]
fn a_refusal_is_recorded_and_releases_nothing() {
    let dir = workdir("approve-refused");
    let led = dir.join("ledger-refused");
    let cmd = "git push origin main";
    {
        let mut run = BrokerRun::open(
            Ledger::init(&led).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", cmd).unwrap_err();
        run.seal("complete").unwrap();
    }
    let request_id = held_request_id(&led);
    let out = approve_with(&led, &request_id, "user:mariano@local", "deny");
    assert!(
        out.status.success(),
        "recording a refusal is an ordinary write: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let refusal = events(&led)
        .iter()
        .find(|e| e["kind"] == "approval")
        .map(|e| subject(&led, e))
        .expect("the refusal is on the ledger, not merely absent");
    assert_eq!(refusal["verdict"], "deny");
    assert_eq!(refusal["approver"], "user:mariano@local");

    let mut run = BrokerRun::open(
        Ledger::open(&led).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    let fault = run.call("Bash", cmd).unwrap_err();
    run.seal("complete").unwrap();
    assert!(
        fault
            .cause
            .contains("no approval on this ledger releases it"),
        "a recorded refusal must not read as permission: {fault}"
    );
}

// ---------- a denial narrows autonomy ----------

/// The point of an earned rung. `config/policy.json` lists `policy.deny` as a
/// demotion trigger, and until this landed nothing read it: a capability could
/// be denied over and over and keep its rung as long as its sensors passed.
/// Autonomy that only ever goes up is not earned.
#[test]
fn a_denial_narrows_the_capabilitys_autonomy() {
    let dir = workdir("demote-on-deny");
    let (mut run, led) = open_run(&dir, "demote");
    run.call("Bash", "rm -rf /").unwrap_err();
    run.seal("complete").unwrap();

    let change = events(&led)
        .iter()
        .find(|e| e["kind"] == "rung.change")
        .map(|e| subject(&led, e))
        .expect("a denial demotes, and the demotion is an event");
    assert_eq!(change["capability"], "shell.exec");
    assert_eq!(
        change["from"], "autonomous",
        "shell.exec is declared autonomous in the tracked policy"
    );
    assert_eq!(change["to"], "assisted");
    assert_eq!(change["trigger"], "demotion");
    assert_eq!(
        change["cause"], "r-destructive-shell",
        "the demotion names the rule that caused it, so the arc stays explicable"
    );
}

/// Demotion stops at the floor. There is no rung below the one where a human
/// already drives, so further denials record no change rather than an
/// unbounded slide or a wrapped value.
#[test]
fn demotion_stops_at_the_floor() {
    let dir = workdir("demote-floor");
    let ledger_dir = dir.join("ledger-floor");
    for _ in 0..4 {
        let mut run = BrokerRun::open(
            if ledger_dir.join("events.jsonl").exists() {
                Ledger::open(&ledger_dir).unwrap()
            } else {
                Ledger::init(&ledger_dir).unwrap()
            },
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", "rm -rf /").unwrap_err();
        run.seal("complete").unwrap();
    }
    let changes: Vec<Value> = events(&ledger_dir)
        .iter()
        .filter(|e| e["kind"] == "rung.change")
        .map(|e| subject(&ledger_dir, e))
        .collect();
    assert_eq!(
        changes.len(),
        2,
        "autonomous to assisted to led, and then nothing: {changes:?}"
    );
    assert_eq!(changes[1]["to"], "led");
}

/// The demotion follows the capability the decision named, not the tool. A
/// denied `Read` costs `repo.read` its rung and leaves `shell.exec` alone.
///
/// The complementary case, a denial naming no capability at all, is not
/// reachable through the broker: `r-default` fires only for a tool no
/// capability declares, and such a tool is refused at registration before any
/// call reaches the policy (see `undeclared_tool_is_refused_registration`).
/// `demote_on_denial` still guards for it, because the policy can be
/// evaluated outside the broker.
#[test]
fn the_demotion_follows_the_capability_the_decision_named() {
    let dir = workdir("demote-no-cap");
    let ledger_dir = dir.join("ledger-nocap");
    let mut run = BrokerRun::open(
        Ledger::init(&ledger_dir).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    // Registered and declared, but the target matches the credential-file rule,
    // which denies under repo.read rather than falling through to r-default.
    run.call("Read", "./.env").unwrap_err();
    run.seal("complete").unwrap();

    let changes: Vec<Value> = events(&ledger_dir)
        .iter()
        .filter(|e| e["kind"] == "rung.change")
        .map(|e| subject(&ledger_dir, e))
        .collect();
    assert_eq!(changes.len(), 1, "one denial, one demotion");
    assert_eq!(changes[0]["capability"], "repo.read");
    assert_eq!(changes[0]["cause"], "r-credential-file");
}

/// The demotion is not decoration: the next call on that capability is gated
/// by the rung the denial cost it, because the broker replays trust history
/// before every decision.
#[test]
fn the_rung_a_denial_cost_gates_the_next_call() {
    let dir = workdir("demote-gates");
    let ledger_dir = dir.join("ledger-gates");
    {
        let mut run = BrokerRun::open(
            Ledger::init(&ledger_dir).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        run.call("Bash", "rm -rf /").unwrap_err();
        run.seal("complete").unwrap();
    }
    let mut run = BrokerRun::open(
        Ledger::open(&ledger_dir).unwrap(),
        tracked_policy(),
        "broker-test",
        &pinning(&dir),
    )
    .unwrap();
    run.register_builtins().unwrap();
    let _ = run.call("Bash", "echo hello");
    run.seal("complete").unwrap();

    let decision = events(&ledger_dir)
        .iter()
        .filter(|e| e["kind"] == "policy.decision")
        .map(|e| subject(&ledger_dir, e))
        .next_back()
        .unwrap();
    assert_eq!(
        decision["rung"], "assisted",
        "the earned rung after one denial gates this call, not the declared autonomous"
    );
}
