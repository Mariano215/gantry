use gantry::gateway::{msg, GatewayRun, Pinning, Provider};
use gantry::ledger::{self, Ledger};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
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

/// Minimal canned HTTP server: accepts one connection, returns `body` with
/// `status`, hands back the raw request bytes. Loopback only; the no-network
/// invariant holds.
fn stub(status: u16, body: &str) -> (String, std::thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = body.to_string();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut req = vec![0u8; 65536];
        let mut n = 0;
        loop {
            let r = sock.read(&mut req[n..]).unwrap();
            n += r;
            let head_end = req[..n].windows(4).position(|w| w == b"\r\n\r\n");
            if let Some(he) = head_end {
                let head = String::from_utf8_lossy(&req[..he]).to_lowercase();
                let clen: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                if n >= he + 4 + clen {
                    break;
                }
            }
            if r == 0 {
                break;
            }
        }
        req.truncate(n);
        let resp = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes()).unwrap();
        req
    });
    (format!("http://127.0.0.1:{port}/v1"), handle)
}

fn provider(base_url: &str, name: &str, key_env: Option<&str>) -> Provider {
    Provider {
        name: name.into(),
        base_url: base_url.into(),
        model: "stub-model".into(),
        key_env: key_env.map(String::from),
        window_budget: 8192,
        cost_in_per_mtok: 2.0,
        cost_out_per_mtok: 10.0,
    }
}

const OK_BODY: &str = r#"{"choices":[{"message":{"role":"assistant","content":"stub answer"}}],"usage":{"prompt_tokens":42,"completion_tokens":7}}"#;

fn read_subject(led: &Path, line: usize) -> serde_json::Value {
    let lines = fs::read_to_string(led.join("events.jsonl")).unwrap();
    let env: serde_json::Value = serde_json::from_str(lines.lines().nth(line).unwrap()).unwrap();
    let hex_part = env["subject_hash"].as_str().unwrap().trim_start_matches("sha256:");
    serde_json::from_str(&fs::read_to_string(led.join("payloads").join(format!("{hex_part}.json"))).unwrap()).unwrap()
}

#[test]
fn call_appends_model_call_event() {
    let dir = workdir("call-ok");
    let pin = pinning(&dir);
    let (base, srv) = stub(200, OK_BODY);
    let led = dir.join("ledger");
    let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    let out = run
        .call(&provider(&base, "stub", None), &[msg("user", "hello")])
        .unwrap();
    run.seal("complete").unwrap();

    assert_eq!(out.content, "stub answer");
    assert_eq!((out.prompt_tokens, out.completion_tokens), (42, 7));

    let req = String::from_utf8(srv.join().unwrap()).unwrap();
    assert!(req.starts_with("POST /v1/chat/completions"), "path: {req}");
    assert!(req.contains(r#""model":"stub-model""#));

    let lines = fs::read_to_string(led.join("events.jsonl")).unwrap();
    let call: serde_json::Value = serde_json::from_str(lines.lines().nth(1).unwrap()).unwrap();
    assert_eq!(call["kind"], "model.call");
    // Subject lives behind subject_hash; read it from payloads/.
    let subject = read_subject(&led, 1);
    assert_eq!(subject["provider"], "stub");
    assert_eq!(subject["outcome"], "ok");
    assert_eq!(subject["tokens"], serde_json::json!({"prompt": 42, "completion": 7}));
    assert_eq!(subject["window"], serde_json::json!({"budget": 8192, "actual": 49}));
    assert!(subject["prompt_hash"].as_str().unwrap().starts_with("sha256:"));
    assert!(subject["cost_usd"].as_f64().unwrap() > 0.0);
    assert!(subject.get("messages").is_none(), "raw prompt never in the subject");

    // seal carries the accumulated cost
    let seal_subject = read_subject(&led, 2);
    assert!(seal_subject["cost_total_usd"].as_f64().unwrap() > 0.0);
}

#[test]
fn missing_key_faults_before_any_request() {
    let dir = workdir("call-nokey");
    let pin = pinning(&dir);
    let mut run = GatewayRun::open(Ledger::init(&dir.join("ledger")).unwrap(), "smoke", &pin).unwrap();
    let p = provider("http://127.0.0.1:1/v1", "stub", Some("GANTRY_TEST_UNSET_KEY"));
    let fault = run.call(&p, &[msg("user", "hello")]).unwrap_err();
    assert!(fault.fix.contains("GANTRY_TEST_UNSET_KEY"), "fix names the var: {fault}");
}

/// A provider error body that echoes request headers (proxies and gateways
/// do this in debug 4xx/5xx pages) must never carry the key onto the
/// append-only ledger. Also the first test to exercise the Authorization
/// header path, since the other call tests use key_env: None.
#[test]
fn provider_error_never_leaks_the_key_onto_the_ledger() {
    let dir = workdir("call-key-leak");
    let pin = pinning(&dir);
    let sentinel = "sk-test-sentinel-9f3a1c";
    std::env::set_var("GANTRY_TEST_SENTINEL_KEY", sentinel);
    let body = format!(r#"{{"error":"rejected header Authorization: Bearer {sentinel}"}}"#);
    let (base, srv) = stub(500, &body);
    let led = dir.join("ledger");
    let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    let p = provider(&base, "stub", Some("GANTRY_TEST_SENTINEL_KEY"));
    let fault = run.call(&p, &[msg("user", "hello")]).unwrap_err();
    run.seal("complete").unwrap();
    srv.join().unwrap();
    std::env::remove_var("GANTRY_TEST_SENTINEL_KEY");

    assert!(!fault.cause.contains(sentinel), "fault cause carries the key: {fault}");

    let lines = fs::read_to_string(led.join("events.jsonl")).unwrap();
    let call: serde_json::Value = serde_json::from_str(lines.lines().nth(1).unwrap()).unwrap();
    assert_eq!(call["kind"], "model.call");
    let subject = read_subject(&led, 1);
    assert_eq!(subject["outcome"], "error");

    // Every file the run touched (events, heads, payloads) must be sentinel-free.
    fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    files_under(&led, &mut files);
    assert!(!files.is_empty());
    for f in files {
        let text = fs::read_to_string(&f).unwrap_or_default();
        assert!(!text.contains(sentinel), "sentinel leaked into {}", f.display());
    }
}

#[test]
fn http_500_is_a_ledger_event() {
    let dir = workdir("call-500");
    let pin = pinning(&dir);
    let (base, _srv) = stub(500, r#"{"error":"boom"}"#);
    let led = dir.join("ledger");
    let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    let fault = run.call(&provider(&base, "stub", None), &[msg("user", "hi")]).unwrap_err();
    run.seal("failed").unwrap();
    assert!(fault.cause.contains("on the ledger"), "{fault}");
    let subject = read_subject(&led, 1);
    assert_eq!(subject["outcome"], "error");
    assert!(subject["error"]["cause"].as_str().unwrap().contains("500"));
    assert!(!subject["error"]["fix"].as_str().unwrap().is_empty());
    assert!(gantry::ledger::verify(&led).unwrap().ok());
}

#[test]
fn connection_refused_is_a_ledger_event() {
    let dir = workdir("call-refused");
    let pin = pinning(&dir);
    // Bind then drop, so the port exists but nothing listens.
    let port = { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() };
    let led = dir.join("ledger");
    let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    let p = provider(&format!("http://127.0.0.1:{port}/v1"), "stub", None);
    run.call(&p, &[msg("user", "hi")]).unwrap_err();
    run.seal("failed").unwrap();
    let subject = read_subject(&led, 1);
    assert_eq!(subject["outcome"], "error");
    assert!(subject["error"]["fix"].as_str().unwrap().contains("base_url"));
}

fn sorted_keys(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    k.sort();
    k
}

/// The slice 02 claim in miniature: two providers, one envelope shape and one
/// model.call subject shape. The three-environment version is the proof run.
#[test]
fn envelope_shape_identical_across_providers() {
    let dir = workdir("shape");
    let pin = pinning(&dir);
    let mut shapes = Vec::new();
    for name in ["alpha", "beta"] {
        let (base, _srv) = stub(200, OK_BODY);
        let led = dir.join(format!("ledger-{name}"));
        let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
        run.call(&provider(&base, name, None), &[msg("user", "hello")]).unwrap();
        run.seal("complete").unwrap();
        let lines = fs::read_to_string(led.join("events.jsonl")).unwrap();
        let env: serde_json::Value = serde_json::from_str(lines.lines().nth(1).unwrap()).unwrap();
        shapes.push((sorted_keys(&env), sorted_keys(&read_subject(&led, 1))));
    }
    assert_eq!(shapes[0], shapes[1], "same envelope keys and same subject keys");
}

#[test]
fn key_bytes_never_reach_the_ledger() {
    let dir = workdir("keyleak");
    let pin = pinning(&dir);
    let canary = "sk-canary-8c2f1a9d7e";
    std::env::set_var("GANTRY_TEST_CANARY_KEY", canary);
    let (base, srv) = stub(200, OK_BODY);
    let led = dir.join("ledger");
    let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    run.call(&provider(&base, "stub", Some("GANTRY_TEST_CANARY_KEY")), &[msg("user", "hello")]).unwrap();
    run.seal("complete").unwrap();
    let req = String::from_utf8(srv.join().unwrap()).unwrap();
    assert!(req.contains(&format!("Bearer {canary}")), "wire contains Bearer token");

    fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    files_under(&led, &mut files);
    assert!(!files.is_empty());
    for f in files {
        let text = fs::read_to_string(&f).unwrap_or_default();
        assert!(!text.contains(canary), "key bytes found in {}", f.display());
    }
}
