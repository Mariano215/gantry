//! Slice 10 integration: the read-only console API of `docs/CONSOLE-API.md`,
//! exercised over a real loopback socket against a fixture ledger. Binding
//! loopback is what `tests/sandbox.rs` already does and it is not a route out:
//! the listener is this process, so the suite stays offline.

use gantry::console;
use gantry::event::NewEvent;
use gantry::ledger::Ledger;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::{fs, thread};

// -- fixture ----------------------------------------------------------------

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-console-it-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn event(run_id: &str, seq: u64, ts: &str, kind: &str, subject: Value) -> NewEvent {
    NewEvent {
        id: format!("{run_id}-{seq}"),
        run_id: run_id.to_string(),
        parent_id: None,
        seq,
        ts: ts.to_string(),
        kind: kind.to_string(),
        actor: json!({"type": "system", "id": "system:broker", "identity_source": "local", "rung": null}),
        authority: json!({"policy_version": "sha256:fixture", "diverged": []}),
        subject,
        redacted: vec![],
        attestation: None,
    }
}

/// Two runs: one sealed with a denial, a clean capability run and a
/// promotion; one that never sealed. The unsealed run is deliberate, because
/// the API must show the seam rather than hide it.
fn fixture_ledger(name: &str) -> PathBuf {
    let dir = workdir(name).join("ledger");
    let mut ledger = Ledger::init(&dir).unwrap();
    for ev in [
        event(
            "run-1000",
            0,
            "2026-08-05T09:14:01.000Z",
            "run.open",
            json!({"workload": "repo-audit", "restored_checkpoint": null}),
        ),
        event(
            "run-1000",
            1,
            "2026-08-05T09:14:02.000Z",
            "model.call",
            json!({"provider": "fixture", "tokens": 12}),
        ),
        event(
            "run-1000",
            2,
            "2026-08-05T09:14:03.000Z",
            "policy.decision",
            json!({
                "verdict": "deny",
                "capability": "repo.write",
                "rule": "r-destructive-shell",
                "message": "This command is destructive. Run it by hand if you mean it.",
            }),
        ),
        event(
            "run-1000",
            3,
            "2026-08-05T09:14:04.000Z",
            "capability.run",
            json!({"capability": "repo.write", "outcome": "clean"}),
        ),
        event(
            "run-1000",
            4,
            "2026-08-05T09:14:05.000Z",
            "rung.change",
            json!({
                "capability": "repo.write",
                "from": "assisted",
                "to": "autonomous",
                "trigger": "earned",
                "approver": "user:mariano@local",
            }),
        ),
        event(
            "run-1000",
            5,
            "2026-08-05T09:14:06.000Z",
            "run.seal",
            json!({"outcome": "complete", "event_count": 6}),
        ),
        event(
            "run-2000",
            0,
            "2026-08-05T10:00:00.000Z",
            "run.open",
            json!({"workload": "unsealed-audit", "restored_checkpoint": null}),
        ),
        event(
            "run-2000",
            1,
            "2026-08-05T10:00:01.000Z",
            "tool.request",
            json!({"tool": "Read", "target": "README.md"}),
        ),
    ] {
        ledger.append(ev).unwrap();
    }
    dir
}

// -- a client, because the suite may not reach for an HTTP crate ------------

struct Reply {
    status: u16,
    content_type: String,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }
}

fn raw(addr: SocketAddr, request: &str) -> Reply {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("no header terminator");
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .expect("no status code");
    let content_type = head
        .lines()
        .find_map(|l| l.strip_prefix("content-type: "))
        .unwrap_or_default()
        .trim()
        .to_string();
    Reply {
        status,
        content_type,
        body: body.to_string(),
    }
}

fn get(addr: SocketAddr, target: &str) -> Reply {
    raw(
        addr,
        &format!("GET {target} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"),
    )
}

/// Starts the server on an ephemeral loopback port and returns its address.
/// The thread is left running: the test binary exits and takes it with it.
fn serve(ledger: &Path) -> SocketAddr {
    let listener = console::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = ledger.display().to_string();
    thread::spawn(move || console::serve_on(&listener, &dir));
    addr
}

// -- the routes -------------------------------------------------------------

#[test]
fn every_route_answers_from_the_ledger_in_the_contracted_shape() {
    let ledger = fixture_ledger("routes");
    let addr = serve(&ledger);

    // GET /api/score
    let score = get(addr, "/api/score");
    assert_eq!(score.status, 200);
    assert_eq!(score.content_type, "application/json; charset=utf-8");
    let v = score.json();
    assert!(v["scores"].is_array(), "score has no scores array: {v}");
    assert!(v.get("overall").is_some(), "score has no overall: {v}");
    assert!(v["rules_version"].is_string());
    assert_eq!(v["events_scored"], json!(8));

    // GET /api/head
    let head = get(addr, "/api/head").json();
    assert_eq!(head["size"], json!(8));
    for field in ["root_hash", "ts", "key_id", "sig"] {
        assert!(head[field].is_string(), "head lacks {field}: {head}");
    }

    // GET /api/events
    let events = get(addr, "/api/events").json();
    assert_eq!(events["total"], json!(8));
    assert_eq!(events["returned"], json!(8));
    assert_eq!(events["offset"], json!(0));
    let first = &events["events"][0];
    for field in [
        "v",
        "id",
        "run_id",
        "seq",
        "ts",
        "kind",
        "actor",
        "authority",
        "subject_hash",
        "redacted",
        "_subject",
        "_attestation_state",
    ] {
        assert!(
            first[field] != Value::Null || field == "parent_id",
            "event lacks {field}: {first}"
        );
    }
    assert_eq!(first["kind"], json!("run.open"));
    // Newest last, exactly as the ledger is appended.
    assert_eq!(events["events"][7]["kind"], json!("tool.request"));
    // No producer emits attestations yet, so every row is absent. The point
    // is that it says so per event rather than saying nothing.
    for ev in events["events"].as_array().unwrap() {
        assert!(
            matches!(
                ev["_attestation_state"].as_str(),
                Some("verified" | "unverified" | "forged" | "absent")
            ),
            "unexpected attestation state: {ev}"
        );
        assert_eq!(ev["_attestation_state"], json!("absent"));
    }

    // GET /api/events/:id
    let id = first["id"].as_str().unwrap().to_string();
    let one = get(addr, &format!("/api/events/{id}")).json();
    assert_eq!(one["event"]["id"], json!(id));
    assert_eq!(one["index"], json!(0));
    assert_eq!(one["tree_size"], json!(8));
    assert_eq!(one["event"]["_attestation_state"], json!("absent"));

    // GET /api/runs
    let runs = get(addr, "/api/runs").json();
    let runs = runs["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2);
    // Newest first: the unsealed run opened later.
    assert_eq!(runs[0]["run_id"], json!("run-2000"));
    assert_eq!(runs[0]["sealed"], json!(false));
    assert_eq!(runs[0]["sealed_at"], Value::Null);
    assert_eq!(runs[0]["workload"], json!("unsealed-audit"));
    let sealed = &runs[1];
    assert_eq!(sealed["run_id"], json!("run-1000"));
    assert_eq!(sealed["sealed"], json!(true));
    assert_eq!(sealed["sealed_at"], json!("2026-08-05T09:14:06.000Z"));
    assert_eq!(sealed["opened_at"], json!("2026-08-05T09:14:01.000Z"));
    assert_eq!(sealed["workload"], json!("repo-audit"));
    assert_eq!(sealed["events"], json!(6));
    assert_eq!(sealed["denials"], json!(1));
    assert_eq!(sealed["unattested"], json!(6));
    assert_eq!(sealed["kinds"]["policy.decision"], json!(1));
    assert_eq!(sealed["kinds"]["run.seal"], json!(1));

    // GET /api/policy
    let policy = get(addr, "/api/policy").json();
    assert_eq!(policy["profile"], json!("laptop"));
    assert!(policy["version"]
        .as_str()
        .unwrap_or_default()
        .starts_with("sha256:"));
    let caps = policy["capabilities"].as_array().unwrap();
    let repo_write = caps
        .iter()
        .find(|c| c["id"] == json!("repo.write"))
        .expect("repo.write is in the tracked policy");
    assert_eq!(repo_write["rung"], json!("assisted"));
    assert_eq!(repo_write["effect"], json!("write.local"));
    let rules = policy["rules"].as_array().unwrap();
    let fired = rules
        .iter()
        .find(|r| r["id"] == json!("r-destructive-shell"))
        .expect("r-destructive-shell is in the tracked policy");
    assert_eq!(fired["decision"], json!("deny"));
    assert_eq!(fired["fired"], json!(1));
    // A rule that never fired is listed, not hidden.
    assert!(
        rules.iter().any(|r| r["fired"] == json!(0)),
        "an unfired rule must still be shown: {rules:?}"
    );

    // GET /api/trust
    let trust = get(addr, "/api/trust").json();
    let cap = trust["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["capability"] == json!("repo.write"))
        .cloned()
        .expect("repo.write is in the tracked policy");
    assert_eq!(cap["declared_rung"], json!("assisted"));
    // Replayed from the ledger: the rung.change moved it, the config did not.
    assert_eq!(cap["earned_rung"], json!("autonomous"));
    assert_eq!(cap["clean_since_rung"], json!(0));
    let history = cap["history"].as_array().unwrap();
    assert_eq!(history.len(), 2);
    let change = history
        .iter()
        .find(|h| h["kind"] == json!("rung.change"))
        .unwrap();
    assert_eq!(change["from"], json!("assisted"));
    assert_eq!(change["to"], json!("autonomous"));
    assert_eq!(change["approver"], json!("user:mariano@local"));
    assert!(change["event_id"].is_string());

    // GET /api/verify
    let verify = get(addr, "/api/verify").json();
    assert_eq!(verify["ok"], json!(true));
    assert_eq!(verify["entries"], json!(8));
    assert_eq!(verify["attestations_verified"], json!(0));
    assert_eq!(verify["attestations_unverified"], json!(0));
    assert_eq!(verify["faults"], json!([]));
    assert_eq!(verify["head"]["size"], json!(8));
    let reproduce = verify["reproduce"].as_str().unwrap();
    assert!(
        reproduce.starts_with("gantry ledger verify /"),
        "reproduce must be the runnable offline command: {reproduce}"
    );

    // A non-API path serves the console shell, so the front end routes itself.
    let shell = get(addr, "/ledger/run-1000");
    assert_eq!(shell.status, 200);
    assert_eq!(shell.content_type, "text/html; charset=utf-8");
    assert!(shell.body.contains("<!doctype html>"));
}

#[test]
fn the_events_filters_narrow_the_set_and_page_it() {
    let ledger = fixture_ledger("filters");
    let addr = serve(&ledger);

    let one_kind = get(addr, "/api/events?kind=policy.decision").json();
    assert_eq!(one_kind["total"], json!(1));
    assert_eq!(one_kind["events"][0]["kind"], json!("policy.decision"));

    // kind repeats into a set.
    let two_kinds = get(addr, "/api/events?kind=run.open&kind=run.seal").json();
    assert_eq!(two_kinds["total"], json!(3));

    let by_run = get(addr, "/api/events?run=run-2000").json();
    assert_eq!(by_run["total"], json!(2));

    let by_actor = get(addr, "/api/events?actor=system%3Abroker").json();
    assert_eq!(by_actor["total"], json!(8));
    assert_eq!(
        get(addr, "/api/events?actor=system%3Ascorer").json()["total"],
        json!(0)
    );

    // since is inclusive at the bound, and a whole-second bound must not
    // exclude an event that carries a fraction inside that second.
    let since = get(addr, "/api/events?since=2026-08-05T09:14:04Z").json();
    assert_eq!(since["total"], json!(5));
    assert_eq!(
        get(addr, "/api/events?since=2026-08-06").json()["total"],
        json!(0)
    );

    let paged = get(addr, "/api/events?limit=2&offset=3").json();
    assert_eq!(paged["total"], json!(8), "total counts the filtered set");
    assert_eq!(paged["returned"], json!(2));
    assert_eq!(paged["offset"], json!(3));
    assert_eq!(paged["events"][0]["kind"], json!("capability.run"));

    // Combined filters intersect.
    let combined = get(addr, "/api/events?run=run-1000&kind=run.seal").json();
    assert_eq!(combined["total"], json!(1));
}

#[test]
fn a_long_query_is_answered_whole_or_refused_never_truncated() {
    let ledger = fixture_ledger("longquery");
    let addr = serve(&ledger);

    // Well past the 1024-byte buffer the first server read. The last kind is
    // the one that matches, so a truncated read answers the wrong question.
    let mut target = String::from("/api/events?");
    for i in 0..300 {
        target.push_str(&format!("kind=filler.kind.{i:04}&"));
    }
    target.push_str("kind=policy.decision");
    assert!(target.len() > 4000);
    let long = get(addr, &target);
    assert_eq!(long.status, 200, "body: {}", long.body);
    let long = long.json();
    assert_eq!(long["total"], json!(1));
    assert_eq!(long["events"][0]["kind"], json!("policy.decision"));

    // Past the cap, the request is refused with a Fault rather than cut down
    // to a query that means something else.
    let mut huge = String::from("/api/events?");
    for i in 0..8000 {
        huge.push_str(&format!("kind=filler.kind.{i:06}&"));
    }
    huge.push_str("kind=run.open");
    let refused = raw(
        addr,
        &format!("GET {huge} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n"),
    );
    assert_eq!(refused.status, 400, "body: {}", refused.body);
    let fault = refused.json();
    assert!(fault["cause"].is_string() && fault["fix"].is_string());
}

// -- refusals ---------------------------------------------------------------

#[test]
fn an_unknown_api_path_is_a_404_fault() {
    let ledger = fixture_ledger("unknown");
    let addr = serve(&ledger);

    let miss = get(addr, "/api/nonesuch");
    assert_eq!(miss.status, 404);
    assert_eq!(miss.content_type, "application/json; charset=utf-8");
    let fault = miss.json();
    assert!(
        fault["cause"].as_str().unwrap().contains("/api/nonesuch"),
        "the cause must name the path: {fault}"
    );
    assert!(
        fault["fix"].as_str().unwrap().contains("/api/score"),
        "the fix must name the routes that do exist: {fault}"
    );

    // An id that was never appended is a 404, not an empty 200.
    let no_event = get(addr, "/api/events/ev-never-appended");
    assert_eq!(no_event.status, 404);
    assert!(no_event.json()["fix"].is_string());
}

#[test]
fn a_write_method_is_refused_because_the_api_is_read_only() {
    let ledger = fixture_ledger("readonly");
    let addr = serve(&ledger);

    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let reply = raw(
            addr,
            &format!(
                "{method} /api/score HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            ),
        );
        assert_eq!(reply.status, 405, "{method} was not refused");
        let fault = reply.json();
        assert!(
            fault["cause"].as_str().unwrap().contains(method),
            "the cause must name the method: {fault}"
        );
        assert!(fault["fix"].as_str().unwrap().contains("GET"));
    }
}

#[test]
fn a_query_that_cannot_be_parsed_is_refused_rather_than_guessed() {
    let ledger = fixture_ledger("badquery");
    let addr = serve(&ledger);

    for target in [
        "/api/events?limit=lots",
        "/api/events?offset=-1",
        "/api/events?since=last%20tuesday",
        "/api/events?since=2026-08-05T09%3A14%3A02%2B02%3A00",
        "/api/events?kinds=run.open",
        "/api/events?kind",
        "/api/events?kind=%zz",
    ] {
        let reply = get(addr, target);
        assert_eq!(
            reply.status, 400,
            "{target} was not refused: {}",
            reply.body
        );
        let fault = reply.json();
        assert!(
            !fault["cause"].as_str().unwrap_or_default().is_empty()
                && !fault["fix"].as_str().unwrap_or_default().is_empty(),
            "{target} produced a Fault with no fix: {fault}"
        );
    }

    // A limit above the maximum returns the maximum rather than erroring.
    let clamped = get(addr, "/api/events?limit=99999").json();
    assert_eq!(clamped["returned"], json!(8));
}

// -- the adversarial case ---------------------------------------------------

#[test]
fn a_mutated_event_makes_verify_report_not_ok_and_name_the_entry() {
    let ledger = fixture_ledger("tampered");
    let addr = serve(&ledger);
    assert_eq!(get(addr, "/api/verify").json()["ok"], json!(true));

    // Rewrite one stored envelope in place, same length and still canonical
    // JSON, so only the hashes give it away. The ledger is append-only, so
    // this is exactly the edit no code path performs.
    let path = ledger.join("events.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let before = lines[2].clone();
    lines[2] = lines[2].replace("2026-08-05T09:14:03.000Z", "2026-08-05T09:14:09.000Z");
    assert_ne!(before, lines[2], "the fixture entry was not altered");
    fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    // Derived on the request, never cached: the same server now reports the
    // fault without a restart.
    let verify = get(addr, "/api/verify").json();
    assert_eq!(verify["ok"], json!(false), "verify: {verify}");
    let faults = verify["faults"].as_array().unwrap();
    assert!(!faults.is_empty());
    assert!(
        faults.iter().any(|f| f["index"] == json!(2)),
        "no fault names the altered entry: {faults:?}"
    );
    for fault in faults {
        let text = fault["fault"].as_str().unwrap();
        assert!(
            text.contains("Fix:"),
            "a fault must carry the action to take: {text}"
        );
    }
    assert!(
        verify["reproduce"]
            .as_str()
            .unwrap()
            .starts_with("gantry ledger verify "),
        "the reader gets the command that checks the server"
    );
}
