//! Slice 15: the drift check, the sensor half of primitive 12.
//!
//! `docs/POLICY-SCHEMA.md` makes `observed_by` a required field on every
//! profile requirement. This module is the thing that reads those sources.
//! It walks `profile_requirements`, reads each source from the running
//! system, and produces one outcome per field: `match`, `divergence`, or
//! `unobservable`.
//!
//! The rule the whole module is built around: a source this build cannot
//! actually read reports `unobservable`, never `match`. Two values that agree
//! because neither was read is the failure this project exists to prevent, and
//! it is easy to write by accident, because the naive implementation of the
//! egress check reads the sandbox allowlist that was generated from the very
//! policy field being checked and finds it equal every time.
//!
//! An `observed_by` naming a source no code reads is a gap in the report, not
//! an error that stops the walk. A walk that aborted on the first unknown
//! source would report nothing about the fields it had not reached yet, which
//! is the opposite of what a scheduled scan is for.

use crate::gateway::file_hash;
use crate::ledger::Ledger;
use crate::policy::Policy;
use crate::sandbox;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The three outcomes `docs/POLICY-SCHEMA.md` specifies for one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Match,
    Divergence,
    Unobservable,
}

impl Outcome {
    pub fn schema_name(self) -> &'static str {
        match self {
            Outcome::Match => "match",
            Outcome::Divergence => "divergence",
            Outcome::Unobservable => "unobservable",
        }
    }
}

/// One field of `profile_requirements` after its source was read.
#[derive(Debug, Clone)]
pub struct FieldReport {
    pub field: String,
    pub observed_by: String,
    pub declared: Option<String>,
    pub observed: Option<String>,
    pub outcome: Outcome,
    pub cause: Option<String>,
    pub fix: Option<String>,
}

impl FieldReport {
    /// The subject of one `drift.report` event: declared value, running
    /// value, and the named fix, which is what `docs/EVENT-SCHEMA.md` says
    /// the kind carries.
    pub fn subject(&self) -> Value {
        json!({
            "field": self.field,
            "observed_by": self.observed_by,
            "outcome": self.outcome.schema_name(),
            "declared": self.declared,
            "observed": self.observed,
            "cause": self.cause,
            "fix": self.fix,
        })
    }

    /// One line for a terminal and for a CI check to grep. The outcome comes
    /// second so `^field: outcome` is a stable prefix.
    pub fn line(&self) -> String {
        let declared = self.declared.clone().unwrap_or_else(|| "none".to_string());
        let observed = self.observed.clone().unwrap_or_else(|| "none".to_string());
        let mut line = format!(
            "{}: {} ({}) declared={declared} observed={observed}",
            self.field,
            self.outcome.schema_name(),
            self.observed_by,
        );
        if let Some(cause) = &self.cause {
            line.push_str(&format!(". {cause}"));
        }
        if let Some(fix) = &self.fix {
            line.push_str(&format!(". Fix: {fix}"));
        }
        line
    }
}

/// What the running system can be asked, captured before the drift run
/// appends anything of its own. A walk that read the ledger after its own
/// reports were written would be observing itself.
pub struct Running {
    pub instructions: PathBuf,
    pub settings: Option<PathBuf>,
    pub head_present: bool,
    pub last_event: Option<Value>,
}

impl Running {
    pub fn observe(ledger: &Ledger, instructions: &Path, settings: Option<&Path>) -> Running {
        Running {
            instructions: instructions.to_path_buf(),
            settings: settings.map(Path::to_path_buf),
            head_present: ledger.latest_head().is_ok(),
            last_event: ledger
                .envelopes()
                .last()
                .and_then(|e| serde_json::to_value(e).ok()),
        }
    }
}

/// One reading of one source: a value, or the reason there is no value and
/// what to do about it.
enum Reading {
    Value(String),
    Unreadable { cause: String, fix: String },
}

fn unreadable(cause: impl Into<String>, fix: impl Into<String>) -> Reading {
    Reading::Unreadable {
        cause: cause.into(),
        fix: fix.into(),
    }
}

/// The sources this build reads. Named here so the fix on an unknown source
/// can list them rather than telling the reader to go and grep.
pub const READABLE_SOURCES: [&str; 6] = [
    "sandbox.active_backend",
    "gateway.instruction_hash",
    "hook.settings_hash",
    "ledger.head",
    "gateway.identity_source",
    "event.attestation.key_id",
];

/// Which declared field a source is compared against. Every source compares
/// against `declared` except the attestation, whose declared value is the
/// algorithm and whose observable value is the key id beside it.
fn compared_field(source: &str) -> &'static str {
    match source {
        "event.attestation.key_id" => "key_id",
        _ => "declared",
    }
}

fn last_event_field(running: &Running, path: &[&str]) -> Option<String> {
    let mut node = running.last_event.as_ref()?;
    for key in path {
        node = node.get(key)?;
    }
    node.as_str().map(str::to_string)
}

fn no_event() -> Reading {
    unreadable(
        "the ledger carries no event to read this off",
        "run any gantry command that appends an event against this ledger, then re-run gantry drift",
    )
}

fn read(source: &str, running: &Running) -> Reading {
    match source {
        // A real observation: whether the sandbox binary this host would run a
        // command under exists. It is the same expression Sandbox::per_run
        // uses to stamp the backend on every tool.request.
        "sandbox.active_backend" => Reading::Value(sandbox::active_backend().to_string()),
        "gateway.instruction_hash" => match file_hash(&running.instructions) {
            Ok(hash) => Reading::Value(hash),
            Err(fault) => unreadable(
                format!("the instruction pack cannot be hashed: {}", fault.cause),
                "restore the instruction pack at the path the run pins, then re-run gantry drift",
            ),
        },
        "hook.settings_hash" => match &running.settings {
            Some(path) => match file_hash(path) {
                Ok(hash) => Reading::Value(hash),
                Err(fault) => unreadable(
                    format!("the host settings file cannot be hashed: {}", fault.cause),
                    "restore .claude/settings.json, then re-run gantry drift",
                ),
            },
            None => unreadable(
                "this harness has no host settings file to hash",
                "install the harness under a host that keeps a settings file, or set observed_by to none and record that the host permission list is unchecked",
            ),
        },
        // The ledger being a signed local file is observable by there being a
        // signed head to read. The anchoring and key_custody rows beside it
        // are not read by anything and are covered in docs/POLICY-SCHEMA.md.
        "ledger.head" => {
            if running.head_present {
                Reading::Value("local_file".to_string())
            } else {
                unreadable(
                    "the ledger at this path has no signed head yet",
                    "run any gantry command that appends an event against this ledger, then re-run gantry drift",
                )
            }
        }
        // Telemetry, not configuration: the identity source recorded on the
        // newest event already on the ledger. It observes what the producer
        // wrote, which is one step better than reading the policy back and is
        // still not a query put to an identity provider.
        "gateway.identity_source" => {
            match last_event_field(running, &["actor", "identity_source"]) {
                Some(source) => Reading::Value(source),
                None if running.last_event.is_some() => unreadable(
                    "the newest event on the ledger records no actor identity source",
                    "check that the producer stamps actor.identity_source on every event; docs/EVENT-SCHEMA.md requires it",
                ),
                None => no_event(),
            }
        }
        "event.attestation.key_id" => {
            match last_event_field(running, &["attestation", "key_id"]) {
                Some(key_id) => Reading::Value(key_id),
                // An event that carries no attestation is an observation, not
                // a gap: the profile declared a key and the producer appended
                // unsigned, which is a divergence worth naming.
                None if running.last_event.is_some() => Reading::Value("unsigned".to_string()),
                None => no_event(),
            }
        }
        // Not an observation. The seatbelt profile's allowlist is generated
        // from this same policy field, so reading it back compares the
        // declaration with itself and agrees every time, including when the
        // host route table permits everything.
        "sandbox.egress_allow" => unreadable(
            "the sandbox allowlist is generated from this policy's own egress.allow, so reading it back would compare the declaration with itself",
            "observe the host packet filter or the container's network namespace instead, or set observed_by to none; until one of those happens the egress claim is carried by this document alone",
        ),
        "netns.route_table" => unreadable(
            "this build reads no network namespace, and the host it runs on has none",
            "run under a Linux network namespace and read its route table, or set observed_by to none and record that the egress claim is unchecked",
        ),
        "none" | "" => unreadable(
            "the requirement names no observation source",
            format!(
                "point observed_by at a source this build reads ({}), or accept that the requirement is carried by the document alone, which this walk reports every run rather than scoring it",
                READABLE_SOURCES.join(", ")
            ),
        ),
        other => unreadable(
            format!("no code in this build reads the source {other}"),
            format!(
                "point observed_by at a source this build reads ({}), or set it to none so the gap is reported as an admission rather than as a typo",
                READABLE_SOURCES.join(", ")
            ),
        ),
    }
}

/// One field of `profile_requirements` walked. `spec` is whatever the policy
/// put under the key: an object with `observed_by`, or a bare scalar like
/// `rung_default`, which declares a value and names no source at all.
fn report(field: &str, spec: &Value, running: &Running) -> FieldReport {
    let source = spec["observed_by"].as_str().unwrap_or("none").to_string();
    let declared = spec[compared_field(&source)]
        .as_str()
        .map(str::to_string)
        .or_else(|| spec.as_str().map(str::to_string));
    let mut out = FieldReport {
        field: field.to_string(),
        observed_by: source.clone(),
        declared: declared.clone(),
        observed: None,
        outcome: Outcome::Unobservable,
        cause: None,
        fix: None,
    };
    let Some(declared) = declared else {
        out.cause = Some(format!(
            "the requirement names observation source {source} and declares no value under {}",
            compared_field(&source)
        ));
        out.fix = Some(format!(
            "add a {} value to profile_requirements.{field}, or drop the entry; a source with nothing to compare against reports nothing",
            compared_field(&source)
        ));
        return out;
    };
    match read(&source, running) {
        Reading::Unreadable { cause, fix } => {
            out.cause = Some(cause);
            out.fix = Some(fix);
        }
        Reading::Value(observed) if observed == declared => {
            out.observed = Some(observed);
            out.outcome = Outcome::Match;
        }
        Reading::Value(observed) => {
            out.cause = Some(format!(
                "profile_requirements.{field} declares {declared} and {source} reads {observed}"
            ));
            out.fix = Some(format!(
                "set profile_requirements.{field}.{} to {observed} if the running value is the intended one, or put the running system back to {declared}; a divergent field caps primitive 12 at 2 until the two agree",
                compared_field(&source)
            ));
            out.observed = Some(observed);
            out.outcome = Outcome::Divergence;
        }
    }
    out
}

/// Every field of `profile_requirements`, in the policy document's key order.
/// Every field reports every run, matches included, because a scan that only
/// speaks up on change cannot be told apart from a scan that stopped running.
pub fn walk(policy: &Policy, running: &Running) -> Vec<FieldReport> {
    match policy.profile_requirements.as_object() {
        Some(fields) => fields
            .iter()
            .map(|(field, spec)| report(field, spec, running))
            .collect(),
        None => Vec::new(),
    }
}

/// The field names that diverged, in the `authority.diverged` form the event
/// schema uses (`<field>.<compared>`), so the drift run's own events carry the
/// divergence they found rather than only describing it in a subject.
pub fn diverged_ids(reports: &[FieldReport]) -> Vec<String> {
    reports
        .iter()
        .filter(|r| r.outcome == Outcome::Divergence)
        .map(|r| format!("{}.{}", r.field, compared_field(&r.observed_by)))
        .collect()
}

/// Counts in the order the summary prints them.
pub fn tally(reports: &[FieldReport]) -> (usize, usize, usize) {
    let count = |o: Outcome| reports.iter().filter(|r| r.outcome == o).count();
    (
        count(Outcome::Match),
        count(Outcome::Divergence),
        count(Outcome::Unobservable),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> Running {
        Running {
            instructions: PathBuf::from("instructions/pack.md"),
            settings: None,
            head_present: false,
            last_event: None,
        }
    }

    /// The adversarial core in its smallest form. The declared value and the
    /// value a naive reader would produce are the same string; the source is
    /// one nothing reads, so the outcome is a gap.
    #[test]
    fn a_source_nothing_reads_is_unobservable_even_when_the_values_would_agree() {
        let spec = json!({"declared": "none", "observed_by": "netns.route_table"});
        let r = report("egress", &spec, &running());
        assert_eq!(r.outcome, Outcome::Unobservable);
        assert_eq!(r.observed, None);
        assert!(r.fix.unwrap_or_default().contains("network namespace"));
    }

    #[test]
    fn an_entry_with_no_observed_by_reports_the_admission() {
        let r = report("rung_default", &json!("autonomous"), &running());
        assert_eq!(r.outcome, Outcome::Unobservable);
        assert_eq!(r.declared.as_deref(), Some("autonomous"));
        assert_eq!(r.observed_by, "none");
    }

    #[test]
    fn a_readable_source_that_disagrees_names_both_values() {
        let spec = json!({"declared": "microvm", "observed_by": "sandbox.active_backend"});
        let r = report("isolation", &spec, &running());
        assert_eq!(r.outcome, Outcome::Divergence);
        assert_eq!(r.observed.as_deref(), Some(sandbox::active_backend()));
        let cause = r.cause.unwrap_or_default();
        assert!(cause.contains("microvm") && cause.contains(sandbox::active_backend()));
    }
}
