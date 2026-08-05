//! Slice 17: `on_unavailable` at run open. A profile declaring a requirement
//! nothing on this machine implements either refuses to start and says which
//! requirement, or starts and records the shortfall. These tests run the
//! tracked `config/policy.json` as the laptop case and derive the `regulated`
//! case from it, so the two differ only in what the profile declares.

use gantry::broker::BrokerRun;
use gantry::gateway::Pinning;
use gantry::ledger::Ledger;
use gantry::policy::{availability_check, unavailable_requirements, Policy, Providable};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-prof-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// The tracked laptop policy with the `regulated` profile's declarations, and
/// the stance under test. The attestation block is dropped: the tracked seed
/// is published, which a non-laptop profile refuses on its own, and this test
/// is about availability rather than about key custody of the fixture.
fn regulated_policy(dir: &Path, stance: &str) -> PathBuf {
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(repo_path("config/policy.json")).unwrap())
            .unwrap();
    let req = &mut doc["profile_requirements"];
    req["isolation"]["declared"] = json!("microvm");
    req["identity"]["declared"] = json!("oidc");
    req["ledger"]["anchoring"] = json!("rfc3161");
    req["ledger"]["key_custody"] = json!("hsm");
    req["on_unavailable"] = json!(stance);
    req.as_object_mut().unwrap().remove("attestation");
    doc["profile"] = json!("regulated");
    let path = dir.join(format!("policy-{stance}.json"));
    fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
    path
}

fn pinning(dir: &Path, policy: &Path) -> Pinning {
    let pack = dir.join("pack.md");
    fs::write(&pack, "you are an audit agent").unwrap();
    Pinning {
        policy: policy.to_path_buf(),
        instructions: pack,
        settings: None,
        diverged: vec![],
        permission_mode: None,
    }
}

fn subject(led: &Path, envelope: &Value) -> Value {
    let hex_part = envelope["subject_hash"]
        .as_str()
        .unwrap()
        .trim_start_matches("sha256:")
        .to_string();
    serde_json::from_str(
        &fs::read_to_string(led.join("payloads").join(format!("{hex_part}.json"))).unwrap(),
    )
    .unwrap()
}

/// The row the profile table says carries the weight. None of microvm, oidc,
/// rfc3161 or an hsm exists in this codebase, so a `regulated` policy that
/// sets `refuse` must not start here, and the fault must name each one.
#[test]
fn a_regulated_profile_refuses_to_start_and_names_the_unavailable_requirements() {
    let dir = workdir("regulated-refuse");
    let policy_path = regulated_policy(&dir, "refuse");
    let led = dir.join("ledger-refuse");
    let fault = BrokerRun::open(
        Ledger::init(&led).unwrap(),
        Policy::load(&policy_path).unwrap(),
        "broker-test",
        &pinning(&dir, &policy_path),
    )
    .map(|_| ())
    .unwrap_err();

    for named in [
        "isolation.declared",
        "microvm",
        "identity.declared",
        "oidc",
        "ledger.anchoring",
        "rfc3161",
        "ledger.key_custody",
        "hsm",
    ] {
        assert!(fault.cause.contains(named), "{named} unnamed: {fault}");
    }
    assert!(fault.cause.contains("regulated"), "{fault}");
    assert!(
        fault.fix.contains("degrade"),
        "the fix names the action to take: {fault}"
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

/// The same declarations under `degrade` start, and the weakening is on the
/// ledger. A shortfall the run swallowed would be worse than one it refused.
#[test]
fn the_same_profile_under_degrade_starts_and_records_the_shortfall() {
    let dir = workdir("regulated-degrade");
    let policy_path = regulated_policy(&dir, "degrade");
    let led = dir.join("ledger-degrade");
    BrokerRun::open(
        Ledger::init(&led).unwrap(),
        Policy::load(&policy_path).unwrap(),
        "broker-test",
        &pinning(&dir, &policy_path),
    )
    .map(|_| ())
    .expect("degrade starts the run");

    let events: Vec<Value> = fs::read_to_string(led.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let open = subject(&led, &events[0]);
    let short = open["unavailable"].as_array().unwrap();
    let fields: Vec<&str> = short.iter().filter_map(|s| s["field"].as_str()).collect();
    assert_eq!(
        fields,
        vec![
            "isolation.declared",
            "identity.declared",
            "ledger.anchoring",
            "ledger.key_custody"
        ],
        "run.open records every shortfall: {short:?}"
    );
    assert_eq!(short[0]["declared"], json!("microvm"));
    assert_eq!(short[3]["providable"], json!(["software"]));
}

/// The laptop profile declares what this build provides, so it starts with an
/// empty shortfall list. A check that refused the tracked policy would be
/// measuring the machine rather than the declaration.
#[test]
fn the_tracked_laptop_profile_is_unaffected() {
    let dir = workdir("laptop");
    let policy_path = repo_path("config/policy.json");
    let policy = Policy::load(&policy_path).unwrap();
    let providable = Providable::for_this_build(gantry::sandbox::active_backend());
    assert!(
        unavailable_requirements(&policy.profile_requirements, &providable).is_empty(),
        "the tracked laptop policy declares something this build cannot provide"
    );
    let led = dir.join("ledger-laptop");
    BrokerRun::open(
        Ledger::init(&led).unwrap(),
        policy,
        "broker-test",
        &pinning(&dir, &policy_path),
    )
    .map(|_| ())
    .expect("the tracked laptop profile starts");
}

/// The gateway is the other run open, and a model call under a profile this
/// machine cannot provide is the same silent degradation as a tool call under
/// one. Both refuse, so there is no second door into a degraded regulated run.
#[test]
fn the_gateway_refuses_the_same_profile() {
    let dir = workdir("regulated-gateway");
    let policy_path = regulated_policy(&dir, "refuse");
    let led = dir.join("ledger-gateway");
    let fault = gantry::gateway::GatewayRun::open(
        Ledger::init(&led).unwrap(),
        "gateway-test",
        &pinning(&dir, &policy_path),
    )
    .map(|_| ())
    .unwrap_err();
    assert!(fault.cause.contains("microvm"), "{fault}");
}

/// A stance the code does not recognise refuses on every run, shortfall or
/// not. Falling through to degrade would let one typo turn the row that
/// carries the weight back into prose.
#[test]
fn an_unrecognised_stance_refuses_rather_than_degrading() {
    let providable = Providable::for_this_build("seatbelt");
    let requirements = json!({
        "isolation": { "declared": "seatbelt" },
        "on_unavailable": "Refuse",
    });
    let fault = availability_check("regulated", &requirements, &providable)
        .map(|_| ())
        .unwrap_err();
    assert!(fault.cause.contains("Refuse"), "{fault}");
    assert!(fault.fix.contains("set it to refuse"), "{fault}");
}

/// Availability is not divergence, and the seam is visible in the arguments:
/// a host that can provide microvm answers yes for microvm even while this run
/// observed seatbelt. That case is a divergence for `gantry drift` to report,
/// and this check must stay silent on it.
#[test]
fn a_declaration_the_host_can_provide_is_available_even_when_this_run_diverges() {
    let requirements = json!({
        "isolation": { "declared": "microvm" },
        "on_unavailable": "refuse",
    });
    let hypervisor_host = Providable {
        isolation: vec!["microvm".to_string(), "seatbelt".to_string()],
        identity: vec!["local".to_string()],
        anchoring: vec!["none".to_string()],
        key_custody: vec!["software".to_string()],
    };
    assert!(
        availability_check("regulated", &requirements, &hypervisor_host)
            .unwrap()
            .is_empty()
    );
    assert!(
        availability_check(
            "regulated",
            &requirements,
            &Providable::for_this_build("seatbelt")
        )
        .is_err(),
        "this machine has no microvm backend and must refuse"
    );
}
