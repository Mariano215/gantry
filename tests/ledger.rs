use ed25519_dalek::{Signer, SigningKey};
use gantry::event::{Envelope, NewEvent};
use gantry::ledger::{self, Ledger};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static DIR_N: AtomicU64 = AtomicU64::new(0);

fn temp_dir(name: &str) -> PathBuf {
    let n = DIR_N.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("gantry-test-{}-{name}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    d
}

fn ev(seq: u64, kind: &str, subject: serde_json::Value) -> NewEvent {
    NewEvent {
        id: format!("ev-{seq}"),
        run_id: "run-01".into(),
        parent_id: None,
        seq,
        ts: format!("2026-08-04T18:00:{:02}.000Z", seq),
        kind: kind.into(),
        actor: json!({"type":"agent","id":"agent:test","identity_source":"none","rung":null}),
        authority: json!({
            "profile":"laptop",
            "policy_version":"sha256:aa","instruction_version":"sha256:bb",
            "settings_hash":"sha256:cc","diverged":[]
        }),
        subject,
        redacted: vec![],
        attestation: None,
    }
}

fn build(name: &str, n: u64) -> (PathBuf, Ledger) {
    let dir = temp_dir(name);
    let mut l = Ledger::init(&dir).unwrap();
    for s in 1..=n {
        l.append(ev(s, "tool.request", json!({"tool_id":"Read","n":s})))
            .unwrap();
    }
    (dir, l)
}

/// An event with a real actor attestation over the schema's signing bytes.
fn attested_ev(seq: u64, sk: &SigningKey) -> NewEvent {
    let mut e = ev(seq, "tool.request", json!({"tool_id":"Read","n":seq}));
    let stub = Envelope {
        v: 2,
        id: e.id.clone(),
        run_id: e.run_id.clone(),
        parent_id: None,
        seq: e.seq,
        ts: e.ts.clone(),
        kind: e.kind.clone(),
        actor: e.actor.clone(),
        authority: e.authority.clone(),
        subject_hash: gantry::event::subject_hash(&e.subject).unwrap(),
        redacted: vec![],
        prev_hash: None,
        attestation: None,
    };
    let sig = sk.sign(&stub.attestation_bytes().unwrap());
    e.attestation = Some(json!({
        "alg": "ed25519",
        "key_id": gantry::skills::key_id_for(&sk.verifying_key()),
        "value": hex::encode(sig.to_bytes()),
    }));
    e
}

/// ci/attestation-verify: a registered key checks the attestation; no
/// registry counts it unverified and says so; it never silently passes.
#[test]
fn attestations_verify_against_a_registered_key_or_are_counted() {
    let dir = temp_dir("attest");
    let mut l = Ledger::init(&dir).unwrap();
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    l.append(attested_ev(1, &sk)).unwrap();
    let pub_hex = hex::encode(sk.verifying_key().as_bytes());

    let report = ledger::verify_with_actor_keys(&dir, std::slice::from_ref(&pub_hex)).unwrap();
    assert!(report.ok(), "faults: {:?}", report.faults);
    assert_eq!(report.attestations_verified, 1);
    assert_eq!(report.attestations_unverified, 0);

    let report = ledger::verify(&dir).unwrap();
    assert!(report.ok());
    assert_eq!(report.attestations_verified, 0);
    assert_eq!(
        report.attestations_unverified, 1,
        "unchecked is counted, not clean"
    );
}

/// A forged attestation under a registered key id is a fault, not a count.
#[test]
fn a_forged_attestation_under_a_registered_key_is_a_fault() {
    let dir = temp_dir("attest-forged");
    let mut l = Ledger::init(&dir).unwrap();
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let mut e = ev(1, "tool.request", json!({"x": 1}));
    let sig = sk.sign(b"entirely different bytes");
    e.attestation = Some(json!({
        "alg": "ed25519",
        "key_id": gantry::skills::key_id_for(&sk.verifying_key()),
        "value": hex::encode(sig.to_bytes()),
    }));
    l.append(e).unwrap();
    let pub_hex = hex::encode(sk.verifying_key().as_bytes());
    let report = ledger::verify_with_actor_keys(&dir, &[pub_hex]).unwrap();
    assert!(!report.ok(), "a forged attestation must fault");
    assert!(
        report
            .faults
            .iter()
            .any(|f| f.fault.cause.contains("does not verify")),
        "faults: {:?}",
        report.faults
    );
}

#[test]
fn clean_ledger_verifies() {
    let (dir, l) = build("clean", 7);
    assert_eq!(l.size(), 7);
    let report = ledger::verify(&dir).unwrap();
    assert_eq!(report.entries, 7);
    assert!(report.ok(), "unexpected faults: {:?}", report.faults);
}

#[test]
fn tampering_one_byte_names_the_entry_and_divergence() {
    let (dir, _l) = build("tamper-mid", 7);
    let path = dir.join("events.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    // flip one byte inside entry index 3: change its run_id content
    lines[3] = lines[3].replacen("run-01", "run-02", 1);
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let report = ledger::verify(&dir).unwrap();
    assert!(!report.ok(), "tamper went undetected");
    let named: Vec<_> = report.faults.iter().filter_map(|f| f.index).collect();
    assert!(
        named.contains(&3),
        "faults do not name entry 3: {:?}",
        report.faults
    );
    let text = report
        .faults
        .iter()
        .map(|f| f.fault.to_string())
        .collect::<String>();
    assert!(text.contains("diverges"), "no divergence named: {text}");
}

#[test]
fn tampering_the_last_entry_is_caught_by_the_signed_heads() {
    let (dir, _l) = build("tamper-last", 5);
    let path = dir.join("events.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let last = lines.len() - 1;
    lines[last] = lines[last].replacen("tool.request", "tool.requesU", 1);
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let report = ledger::verify(&dir).unwrap();
    assert!(!report.ok(), "last-entry tamper went undetected");
    let named: Vec<_> = report.faults.iter().filter_map(|f| f.index).collect();
    assert!(
        named.contains(&last),
        "faults do not name entry {last}: {:?}",
        report.faults
    );
}

#[test]
fn truncation_is_caught_and_named() {
    let (dir, _l) = build("truncate", 6);
    let path = dir.join("events.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    fs::write(&path, lines[..4].join("\n") + "\n").unwrap();

    let report = ledger::verify(&dir).unwrap();
    assert!(!report.ok(), "truncation went undetected");
    let text = report
        .faults
        .iter()
        .map(|f| f.fault.to_string())
        .collect::<String>();
    assert!(text.contains("truncated"), "no truncation named: {text}");
}

#[test]
fn inclusion_bundle_verifies_offline_and_rejects_tampering() {
    let (dir, l) = build("bundle", 9);
    let pub_hex = fs::read_to_string(dir.join("keys/ledger.pub")).unwrap();

    let bundle = l.prove(4).unwrap();
    // round-trip through JSON: the bundle is a file handed to a stranger
    let json_text = serde_json::to_string(&bundle).unwrap();
    let parsed: ledger::InclusionBundle = serde_json::from_str(&json_text).unwrap();
    ledger::verify_bundle(&parsed, &pub_hex).unwrap();

    // altered envelope must fail
    let mut bad = parsed;
    bad.envelope.run_id = "run-99".into();
    let err = ledger::verify_bundle(&bad, &pub_hex).unwrap_err();
    assert!(err.to_string().contains("inclusion fails"), "{err}");

    // altered head signature must fail
    let mut bad_head = l.prove(4).unwrap();
    bad_head.head.sig = format!("00{}", &bad_head.head.sig[2..]);
    let err = ledger::verify_bundle(&bad_head, &pub_hex).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");
}

#[test]
fn consistency_between_heads_verifies_offline() {
    let dir = temp_dir("consistency");
    let mut l = Ledger::init(&dir).unwrap();
    for s in 1..=4 {
        l.append(ev(s, "tool.request", json!({"n":s}))).unwrap();
    }
    let old_head = l.latest_head().unwrap();
    for s in 5..=11 {
        l.append(ev(s, "tool.request", json!({"n":s}))).unwrap();
    }
    let new_head = l.latest_head().unwrap();
    let proof = l.consistency(old_head.size as usize).unwrap();
    let pub_hex = fs::read_to_string(dir.join("keys/ledger.pub")).unwrap();
    ledger::verify_consistency_hex(
        old_head.size,
        &old_head.root_hash,
        &new_head,
        &proof,
        &pub_hex,
    )
    .unwrap();
}

#[test]
fn expiry_keeps_the_log_verifiable() {
    let (dir, mut l) = build("expire", 4);
    let target = l.prove(1).unwrap().envelope.subject_hash;
    l.expire(
        &target,
        ev(
            5,
            "retention.expire",
            json!({"expired": target, "rule":"retention/laptop-30d","actor":"system:retention"}),
        ),
    )
    .unwrap();

    // payload gone, envelope intact, log verifies
    let hex_part = target.strip_prefix("sha256:").unwrap();
    assert!(!dir
        .join("payloads")
        .join(format!("{hex_part}.json"))
        .exists());
    let report = ledger::verify(&dir).unwrap();
    assert!(
        report.ok(),
        "expiry broke verification: {:?}",
        report.faults
    );
}

#[test]
fn silent_payload_deletion_is_a_named_fault() {
    let (dir, l) = build("silent-delete", 4);
    let target = l.prove(2).unwrap().envelope.subject_hash;
    let hex_part = target.strip_prefix("sha256:").unwrap();
    fs::remove_file(dir.join("payloads").join(format!("{hex_part}.json"))).unwrap();

    let report = ledger::verify(&dir).unwrap();
    assert!(!report.ok(), "silent deletion went undetected");
    let text = report
        .faults
        .iter()
        .map(|f| f.fault.to_string())
        .collect::<String>();
    assert!(
        text.contains("retention.expire"),
        "fault does not name the fix: {text}"
    );
}

#[test]
fn expire_refuses_unknown_hash_and_wrong_kind() {
    let (_dir, mut l) = build("expire-refuse", 2);
    let err = l
        .expire(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ev(3, "retention.expire", json!({"expired":"x"})),
        )
        .unwrap_err();
    assert!(err.to_string().contains("no envelope references"), "{err}");

    let target = l.prove(0).unwrap().envelope.subject_hash;
    let err = l
        .expire(&target, ev(3, "tool.request", json!({"n":3})))
        .unwrap_err();
    assert!(err.to_string().contains("retention.expire"), "{err}");
}

#[test]
fn init_refuses_an_existing_ledger() {
    let (dir, _l) = build("reinit", 1);
    let err = match Ledger::init(&dir) {
        Err(f) => f,
        Ok(_) => panic!("re-init succeeded on an existing ledger"),
    };
    assert!(err.to_string().contains("already exists"), "{err}");
}

#[test]
fn removing_the_last_head_leaves_the_tail_unattested() {
    let (dir, _l) = build("headless-tail", 7);
    // tamper the newest entry AND drop the head that covers it
    let events_path = dir.join("events.jsonl");
    let text = fs::read_to_string(&events_path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let last = lines.len() - 1;
    lines[last] = lines[last].replacen("tool.request", "tool.requesU", 1);
    fs::write(&events_path, lines.join("\n") + "\n").unwrap();

    let heads_path = dir.join("heads.jsonl");
    let heads = fs::read_to_string(&heads_path).unwrap();
    let kept: Vec<&str> = heads.lines().take(6).collect();
    fs::write(&heads_path, kept.join("\n") + "\n").unwrap();

    let report = ledger::verify(&dir).unwrap();
    assert!(!report.ok(), "unattested tail went undetected");
    let text = report
        .faults
        .iter()
        .map(|f| f.fault.to_string())
        .collect::<String>();
    assert!(
        text.contains("no signed head covering"),
        "fault does not name the uncovered tail: {text}"
    );
}

#[test]
fn empty_heads_file_is_a_fault() {
    let (dir, _l) = build("no-heads", 3);
    fs::write(dir.join("heads.jsonl"), "").unwrap();
    let report = ledger::verify(&dir).unwrap();
    assert!(!report.ok(), "headless log passed verification");
    let text = report
        .faults
        .iter()
        .map(|f| f.fault.to_string())
        .collect::<String>();
    assert!(
        text.contains("no signed head verifies at all"),
        "fault does not say no head verifies: {text}"
    );
}

#[test]
fn one_tamper_reports_one_root_divergence() {
    let (dir, _l) = build("one-fault", 8);
    let path = dir.join("events.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    lines[2] = lines[2].replacen("run-01", "run-0X", 1);
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let report = ledger::verify(&dir).unwrap();
    let root_faults = report
        .faults
        .iter()
        .filter(|f| f.fault.cause.contains("Merkle root diverges"))
        .count();
    assert_eq!(
        root_faults, 1,
        "expected exactly one root divergence fault: {:?}",
        report.faults
    );
}

#[test]
fn unverified_attestations_are_counted() {
    let dir = temp_dir("attest");
    let mut l = Ledger::init(&dir).unwrap();
    l.append(ev(1, "tool.request", json!({"n":1}))).unwrap();
    let mut with_attestation = ev(2, "tool.request", json!({"n":2}));
    with_attestation.attestation =
        Some(json!({"alg":"ed25519","key_id":"ed25519:beef","value":"00"}));
    l.append(with_attestation).unwrap();

    let report = ledger::verify(&dir).unwrap();
    assert!(report.ok(), "attestation broke verify: {:?}", report.faults);
    assert_eq!(report.attestations_unverified, 1);
}

#[test]
fn reopen_continues_the_chain() {
    let (dir, l) = build("reopen", 3);
    let head_before = l.latest_head().unwrap();
    drop(l);
    let mut l = Ledger::open(&dir).unwrap();
    assert_eq!(l.size(), 3);
    l.append(ev(4, "tool.request", json!({"n":4}))).unwrap();
    let report = ledger::verify(&dir).unwrap();
    assert!(
        report.ok(),
        "reopened append broke chain: {:?}",
        report.faults
    );
    assert_eq!(l.latest_head().unwrap().size, head_before.size + 1);
}

/// ci/secret-in-prompt: a secret value that reaches any stored byte is
/// found, and the fault names the handle and file, never the value.
#[test]
fn a_secret_value_on_the_ledger_is_found_and_never_echoed() {
    let (dir, _l) = build("scan-clean", 3);
    let secrets = vec![("GANTRY_HANDLE_API".to_string(), "hunter2-value".to_string())];
    assert!(ledger::scan_for_secrets(&dir, &secrets).unwrap().is_empty());

    let (dir, mut l) = build("scan-hit", 1);
    l.append(ev(
        2,
        "tool.request",
        json!({"args": {"command": "curl -H 'authorization: hunter2-value'"}}),
    ))
    .unwrap();
    let hits = ledger::scan_for_secrets(&dir, &secrets).unwrap();
    assert!(!hits.is_empty(), "the leaked value must be found");
    for hit in &hits {
        let text = hit.to_string();
        assert!(text.contains("GANTRY_HANDLE_API"), "{text}");
        assert!(
            !text.contains("hunter2-value"),
            "the scanner must never echo the secret: {text}"
        );
    }
}
