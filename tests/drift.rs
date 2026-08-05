//! Slice 15: the drift check reads what it can and admits what it cannot.
//!
//! The load-bearing test is the first one. Every other property here is
//! ordinary; the one that matters is that a source this build cannot read
//! reports `unobservable` even when the declared value and the value a naive
//! implementation would produce are the same string.

use gantry::drift::{self, Outcome, Running};
use gantry::policy::Policy;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gantry-drift-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// The tracked policy with `profile_requirements` replaced, written beside a
/// copy of the key material so a run against it can still sign.
fn policy_with(name: &str, requirements: Value) -> (PathBuf, PathBuf) {
    let dir = workdir(name);
    let text = std::fs::read_to_string(repo("config/policy.json")).unwrap();
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    doc["profile_requirements"] = requirements;
    let path = dir.join("policy.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    for f in ["actor-key-fixture.seed", "actor-keys.json"] {
        std::fs::copy(repo(&format!("config/{f}")), dir.join(f)).unwrap();
    }
    (dir, path)
}

fn nothing_observed() -> Running {
    Running {
        instructions: repo("instructions/pack.md"),
        settings: None,
        head_present: false,
        last_event: None,
    }
}

fn field<'a>(reports: &'a [drift::FieldReport], name: &str) -> &'a drift::FieldReport {
    reports
        .iter()
        .find(|r| r.field == name)
        .unwrap_or_else(|| panic!("no report for {name}"))
}

/// The adversarial core. `netns.route_table` is what the schema declares for
/// the egress allowlist and there is no network namespace on this host to
/// read. The declared value and the empty observation agree in the shape a
/// careless implementation would compare, and the outcome must still be a gap.
#[test]
fn a_source_this_build_cannot_read_is_unobservable_never_a_match() {
    let (_dir, path) = policy_with(
        "netns",
        json!({
            "egress": {"declared": "none", "allow": [], "observed_by": "netns.route_table"},
        }),
    );
    let policy = Policy::load(&path).unwrap();
    let reports = drift::walk(&policy, &nothing_observed());
    let egress = field(&reports, "egress");
    assert_eq!(egress.outcome, Outcome::Unobservable);
    assert_eq!(egress.observed, None);
    assert!(
        egress
            .fix
            .as_deref()
            .unwrap_or_default()
            .contains("namespace"),
        "the fix must name what would make it observable: {egress:?}"
    );
}

/// The same trap in the shape the tracked policy actually carries: the
/// sandbox allowlist is generated from `egress.allow`, so an implementation
/// that read it back would report a match for an unchecked control.
#[test]
fn the_generated_allowlist_is_not_an_observation_of_itself() {
    let policy = Policy::load(&repo("config/policy.json")).unwrap();
    let reports = drift::walk(&policy, &nothing_observed());
    let egress = field(&reports, "egress");
    assert_eq!(egress.outcome, Outcome::Unobservable);
    assert!(egress
        .cause
        .as_deref()
        .unwrap_or_default()
        .contains("declaration with itself"));
}

/// A typo in `observed_by` is a gap in one field, not an aborted walk. The
/// fields after it must still report, or a scan could be silenced by one
/// bad line.
#[test]
fn an_unreadable_source_does_not_stop_the_walk() {
    let (_dir, path) = policy_with(
        "unknown",
        json!({
            "a_isolation": {"declared": "seatbelt", "observed_by": "sandbox.active_backend"},
            "b_typo": {"declared": "whatever", "observed_by": "sandbox.actve_backend"},
            "c_instruction_pack": {"declared": "sha256:nope", "observed_by": "gateway.instruction_hash"},
        }),
    );
    let policy = Policy::load(&path).unwrap();
    let reports = drift::walk(&policy, &nothing_observed());
    assert_eq!(reports.len(), 3, "the walk stopped early: {reports:?}");
    assert_eq!(field(&reports, "a_isolation").outcome, Outcome::Match);
    assert_eq!(field(&reports, "b_typo").outcome, Outcome::Unobservable);
    assert_eq!(
        field(&reports, "c_instruction_pack").outcome,
        Outcome::Divergence
    );
    assert!(field(&reports, "b_typo")
        .cause
        .as_deref()
        .unwrap_or_default()
        .contains("sandbox.actve_backend"));
}

/// A requirement with no `observed_by` is the admission the schema says it
/// is: reported as a gap, never counted as a clean field.
#[test]
fn a_requirement_with_no_source_is_reported_as_a_gap() {
    let policy = Policy::load(&repo("config/policy.json")).unwrap();
    let reports = drift::walk(&policy, &nothing_observed());
    for name in ["rung_default", "on_unavailable"] {
        let r = field(&reports, name);
        assert_eq!(r.outcome, Outcome::Unobservable, "{name} was not a gap");
        assert_eq!(r.observed_by, "none");
    }
}

/// A divergence names both values, so the reader does not have to go and
/// compute the running one to know what changed.
#[test]
fn a_divergence_names_both_values_and_a_fix() {
    let dir = workdir("settings");
    let settings = dir.join("settings.json");
    std::fs::write(&settings, "{\"permissions\":{}}").unwrap();
    let (_pdir, path) = policy_with(
        "settings-policy",
        json!({
            "host_permissions": {"declared": "sha256:0000", "observed_by": "hook.settings_hash"},
        }),
    );
    let policy = Policy::load(&path).unwrap();
    let running = Running {
        settings: Some(settings),
        ..nothing_observed()
    };
    let reports = drift::walk(&policy, &running);
    let r = field(&reports, "host_permissions");
    assert_eq!(r.outcome, Outcome::Divergence);
    let cause = r.cause.clone().unwrap_or_default();
    assert!(
        cause.contains("sha256:0000"),
        "declared value missing: {cause}"
    );
    assert!(
        cause.contains(&r.observed.clone().unwrap_or_default()),
        "observed value missing: {cause}"
    );
    assert_eq!(
        drift::diverged_ids(&reports),
        vec!["host_permissions.declared".to_string()]
    );
}

fn gantry(args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_gantry"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap()
}

fn kinds(ledger: &Path) -> Vec<String> {
    std::fs::read_to_string(ledger.join("events.jsonl"))
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|e| e["kind"].as_str().map(str::to_string))
        .collect()
}

/// Every field reports every run, matches included. A scan that spoke only on
/// change would read the same on the ledger as a scan that stopped running,
/// which is the property `docs/POLICY-SCHEMA.md` asks for by name.
#[test]
fn every_field_reports_every_run_and_the_ledger_verifies() {
    let led = workdir("cmd").join("led");
    let policy = Policy::load(&repo("config/policy.json")).unwrap();
    let fields = policy
        .profile_requirements
        .as_object()
        .map(serde_json::Map::len)
        .unwrap_or_default();
    for _ in 0..2 {
        let out = gantry(&["drift", &led.display().to_string(), "config/policy.json"]);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&format!("{fields} field(s) walked")),
            "walk did not cover every field: {text}"
        );
    }
    let reports = kinds(&led).iter().filter(|k| *k == "drift.report").count();
    assert_eq!(
        reports,
        fields * 2,
        "a run reported fewer fields than it walked"
    );
    let verify = gantry(&["ledger", "verify", &led.display().to_string()]);
    assert!(
        verify.status.success(),
        "the drift ledger does not verify: {}",
        String::from_utf8_lossy(&verify.stdout)
    );
}

/// A run that found a divergence says so in its own events' authority block,
/// which is the mechanism `docs/EVENT-SCHEMA.md` already declares for a
/// declaration that does not match what is running.
#[test]
fn a_divergent_field_lands_in_authority_diverged_and_the_exit_status_is_one() {
    let led = workdir("diverged").join("led");
    let out = gantry(&["drift", &led.display().to_string(), "config/policy.json"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let divergent: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(": divergence ("))
        .collect();
    if divergent.is_empty() {
        // The tracked policy agrees with the running system today. Nothing to
        // assert about a divergence that is not there, and saying so beats a
        // test that passes by finding nothing.
        assert!(
            out.status.success(),
            "no divergence but a non-zero exit: {text}"
        );
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(1),
        "a divergence must fail the command: {text}"
    );
    let last = std::fs::read_to_string(led.join("events.jsonl")).unwrap();
    let last: Value = serde_json::from_str(last.lines().last().unwrap()).unwrap();
    let diverged = last["authority"]["diverged"].to_string();
    for line in divergent {
        let name = line.split(':').next().unwrap_or_default();
        assert!(
            diverged.contains(name),
            "{name} diverged and the run's own events do not say so: {diverged}"
        );
    }
}
