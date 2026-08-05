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

/// Rewrite history the way only the log's own writer can: drop the tail of
/// events.jsonl and heads.jsonl, then append different events under the same
/// ledger key. The result is internally consistent and verifies clean, which
/// is exactly the limit an anchored head exists to close.
fn rewrite_history(dir: &std::path::Path, keep: usize, replacement: u64) -> Ledger {
    for file in ["events.jsonl", "heads.jsonl"] {
        let path = dir.join(file);
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(keep).collect();
        fs::write(&path, kept.join("\n") + "\n").unwrap();
    }
    let mut l = Ledger::open(dir).unwrap();
    for s in 0..replacement {
        l.append(ev(
            keep as u64 + s,
            "tool.request",
            json!({"rewritten": s, "tool_id":"Read"}),
        ))
        .unwrap();
    }
    l
}

/// A gap in one run's seq is reported, named and counted, and it is a finding
/// rather than a fault: the log is intact, the record is partial.
#[test]
fn a_seq_gap_is_reported_per_run_and_is_not_a_fault() {
    let dir = temp_dir("seq-gap");
    let mut l = Ledger::init(&dir).unwrap();
    for s in [0, 1, 2, 5, 6] {
        l.append(ev(s, "tool.request", json!({"n": s}))).unwrap();
    }
    // a second run, contiguous, so a checker that fires on everything fails
    for s in 0..3 {
        let mut e = ev(s, "tool.request", json!({"other": s}));
        e.run_id = "run-02".into();
        e.id = format!("ev-other-{s}");
        l.append(e).unwrap();
    }

    let report = ledger::verify(&dir).unwrap();
    assert!(
        report.ok(),
        "a gap is a finding, not a fault: {:?}",
        report.faults
    );
    assert_eq!(report.seq_gaps.len(), 1, "gaps: {:?}", report.seq_gaps);
    let gap = &report.seq_gaps[0];
    assert_eq!(gap.run_id, "run-01");
    assert_eq!((gap.after, gap.before, gap.missing), (2, 5, 2));

    // and a log with no gap reports none
    let (clean_dir, _l) = build("seq-nogap", 4);
    assert!(ledger::verify(&clean_dir).unwrap().seq_gaps.is_empty());
}

/// The bundle a third party is handed checks out, and the rewrite it exists to
/// catch does not.
#[test]
fn a_consistency_bundle_verifies_offline_and_a_rewrite_is_rejected() {
    let dir = temp_dir("consistency-bundle");
    let mut l = Ledger::init(&dir).unwrap();
    for s in 0..11 {
        l.append(ev(s, "tool.request", json!({"n": s}))).unwrap();
    }
    let pub_hex = fs::read_to_string(dir.join("keys/ledger.pub")).unwrap();
    let bundle = l.consistency_bundle(4).unwrap();
    let text = serde_json::to_string(&bundle).unwrap();
    let parsed: ledger::ConsistencyBundle = serde_json::from_str(&text).unwrap();
    ledger::verify_consistency_bundle(&parsed, &pub_hex).unwrap();

    // a proof element the log did not produce must not check out
    let mut tampered = parsed.clone();
    tampered.proof[0] = format!("sha256:{}", "ab".repeat(32));
    let err = ledger::verify_consistency_bundle(&tampered, &pub_hex).unwrap_err();
    assert!(err.to_string().contains("consistency fails"), "{err}");

    // an old head nobody signed must not check out either
    let mut forged = parsed.clone();
    forged.old_head.root_hash = format!("sha256:{}", "cd".repeat(32));
    let err = ledger::verify_consistency_bundle(&forged, &pub_hex).unwrap_err();
    assert!(err.to_string().contains("signature"), "{err}");

    // the real attack: the writer rewrites its own history and re-signs
    let kept_old_head = parsed.old_head.clone();
    let rewritten = rewrite_history(&dir, 3, 8);
    assert!(
        ledger::verify(&dir).unwrap().ok(),
        "the rewritten log verifies clean on its own, which is the point"
    );
    let after = ledger::ConsistencyBundle {
        proof: rewritten.consistency(4).unwrap(),
        new_head: rewritten.latest_head().unwrap(),
        old_head: kept_old_head,
    };
    let err = ledger::verify_consistency_bundle(&after, &pub_hex).unwrap_err();
    assert!(err.to_string().contains("consistency fails"), "{err}");
}

/// An anchor is a copy of a signed head kept where the log's writer is not.
/// It detects the rewrite that verification alone cannot, and only for whoever
/// holds the copy.
#[test]
fn an_anchored_head_detects_a_rewrite_verification_alone_misses() {
    let dir = temp_dir("anchor");
    let anchor_dir = temp_dir("anchor-dest");
    fs::create_dir_all(&anchor_dir).unwrap();
    let mut l = Ledger::init(&dir).unwrap();
    for s in 0..4 {
        l.append(ev(s, "tool.request", json!({"n": s}))).unwrap();
    }
    let dest = anchor_dir.join("head-4.json");
    let (head, envelope) = l
        .anchor(&dest, ev(4, "ledger.anchor", json!(null)))
        .unwrap();
    assert_eq!(head.size, 4);
    assert_eq!(envelope.kind, "ledger.anchor");

    let anchored: ledger::SignedHead =
        serde_json::from_str(&fs::read_to_string(&dest).unwrap()).unwrap();
    assert_eq!(anchored, head);
    let subject: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.join("payloads").join(format!(
            "{}.json",
            envelope.subject_hash.strip_prefix("sha256:").unwrap()
        )))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(subject["tree_size"], 4);
    assert!(subject["does_not_prove"].as_str().unwrap().contains("copy"));

    // honest growth is consistent with the anchor
    let pub_hex = fs::read_to_string(dir.join("keys/ledger.pub")).unwrap();
    for s in 5..9 {
        l.append(ev(s, "tool.request", json!({"n": s}))).unwrap();
    }
    let bundle = ledger::ConsistencyBundle {
        proof: l.consistency(anchored.size as usize).unwrap(),
        new_head: l.latest_head().unwrap(),
        old_head: anchored.clone(),
    };
    ledger::verify_consistency_bundle(&bundle, &pub_hex).unwrap();

    // a rewrite that verifies clean does not survive the anchored head
    let rewritten = rewrite_history(&dir, 3, 8);
    assert!(ledger::verify(&dir).unwrap().ok());
    let bundle = ledger::ConsistencyBundle {
        proof: rewritten.consistency(anchored.size as usize).unwrap(),
        new_head: rewritten.latest_head().unwrap(),
        old_head: anchored,
    };
    let err = ledger::verify_consistency_bundle(&bundle, &pub_hex).unwrap_err();
    assert!(err.to_string().contains("consistency fails"), "{err}");
}

/// An anchor the log's writer can rewrite beside the log is not an anchor, and
/// overwriting the older copy destroys the only evidence it carries.
#[test]
fn anchoring_refuses_a_destination_inside_the_ledger_and_refuses_to_overwrite() {
    let (dir, mut l) = build("anchor-refuse", 3);
    let inside = dir.join("head.json");
    let err = l
        .anchor(&inside, ev(4, "ledger.anchor", json!(null)))
        .unwrap_err();
    assert!(err.to_string().contains("inside the ledger"), "{err}");
    assert!(!inside.exists(), "a refused anchor wrote a file anyway");

    let anchor_dir = temp_dir("anchor-refuse-dest");
    fs::create_dir_all(&anchor_dir).unwrap();
    let dest = anchor_dir.join("head.json");
    l.anchor(&dest, ev(4, "ledger.anchor", json!(null)))
        .unwrap();
    let err = l
        .anchor(&dest, ev(5, "ledger.anchor", json!(null)))
        .unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");

    let err = l
        .anchor(
            &anchor_dir.join("other.json"),
            ev(6, "tool.request", json!(null)),
        )
        .unwrap_err();
    assert!(err.to_string().contains("ledger.anchor"), "{err}");
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
