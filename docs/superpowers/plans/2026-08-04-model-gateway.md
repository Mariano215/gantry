# Model Gateway Implementation Plan (slice 02)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every model call goes through `gateway::GatewayRun`, which appends schema v2 events (`run.open`, `model.call`, `run.seal`) to the slice 01 ledger; one OpenAI-compatible adapter proves three environments produce one envelope shape.

**Architecture:** A `gateway` module in the existing `gantry` crate. `GatewayRun` owns an open `Ledger` and is the only way to issue a model call, so the chokepoint is structural. One blocking HTTP adapter (`ureq`) speaks OpenAI-compatible `POST {base_url}/chat/completions` to all three environments. A `gantry run` subcommand executes a fixed two-turn workload.

**Tech Stack:** Rust 2021, existing crate (`serde`, `serde_json`, `serde_jcs`, `sha2`, `hex`), new dependency `ureq` 2 with rustls.

**Spec:** `docs/superpowers/specs/2026-08-04-model-gateway-design.md`.

## Global Constraints

- No `unwrap` or `expect` outside tests and `main` (clippy enforced). `unwrap_or`, `unwrap_or_default` are fine.
- Every `Fault` names the fix, because the reader is an agent.
- No network in tests. Loopback stubs only (`TcpListener` on `127.0.0.1:0`).
- Envelope field order and naming are schema-breaking; do not touch `src/event.rs` types.
- No em-dashes or en-dashes in any prose, doc, comment, or commit message.
- Docs and code comments in the repo voice: direct, sentence case, no emoji.
- Commits: conventional message, end body with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- After each task: `cargo test` and `cargo clippy --all-targets -- -D warnings` clean before commit.
- Environment gotcha from proof 01: if `cc` fails, a dashboard tool may shadow the system compiler in PATH; check `which cc`.

---

### Task 1: Timestamp and version-pinning helpers

**Files:**
- Create: `src/gateway.rs`
- Modify: `src/lib.rs` (add `pub mod gateway;`)
- Test: unit tests at the bottom of `src/gateway.rs`

**Interfaces:**
- Consumes: `crate::Fault` (`Fault::new(cause, fix)`), `sha2::{Digest, Sha256}`, `hex`.
- Produces: `pub fn rfc3339_now() -> String`, `pub fn rfc3339_from_unix(secs: u64, millis: u32) -> String`, `pub fn file_hash(path: &Path) -> Result<String, Fault>` (returns `sha256:<hex>` over raw file bytes).

- [ ] **Step 1: Write the failing tests**

Create `src/gateway.rs`:

```rust
//! Slice 02: the model gateway. Every model call in this crate goes through
//! GatewayRun, which appends the call to the evidence ledger. See
//! docs/superpowers/specs/2026-08-04-model-gateway-design.md.

use crate::Fault;
use sha2::{Digest, Sha256};
use std::path::Path;

/// RFC 3339 UTC with millisecond precision, the `ts` format the schema uses.
pub fn rfc3339_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_from_unix(d.as_secs(), d.subsec_millis())
}

pub fn rfc3339_from_unix(secs: u64, millis: u32) -> String {
    todo!()
}

/// `sha256:<hex>` over raw file bytes, for authority version pinning.
pub fn file_hash(path: &Path) -> Result<String, Fault> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339_from_unix(0, 0), "1970-01-01T00:00:00.000Z");
        // date -u -r 1785873600 => 2026-08-04T20:00:00Z
        assert_eq!(rfc3339_from_unix(1_785_873_600, 481), "2026-08-04T20:00:00.481Z");
        // leap-year boundary: 2024-02-29T00:00:00Z
        assert_eq!(rfc3339_from_unix(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn file_hash_pins_bytes() {
        let dir = std::env::temp_dir().join(format!("gantry-gw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pack.md");
        std::fs::write(&p, b"instruction pack v1").unwrap();
        let h1 = file_hash(&p).unwrap();
        assert!(h1.starts_with("sha256:"));
        std::fs::write(&p, b"instruction pack v2").unwrap();
        assert_ne!(file_hash(&p).unwrap(), h1);
        let fault = file_hash(&dir.join("missing.md")).unwrap_err();
        assert!(fault.fix.contains("pin"), "fix names pinning: {fault}");
    }
}
```

Add to `src/lib.rs` after `pub mod event;`:

```rust
pub mod gateway;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test gateway`
Expected: FAIL (todo! panics).

- [ ] **Step 3: Implement**

Replace the two `todo!()` bodies:

```rust
pub fn rfc3339_from_unix(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days, the standard days-to-date algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

pub fn file_hash(path: &Path) -> Result<String, Fault> {
    let bytes = std::fs::read(path).map_err(|e| {
        Fault::new(
            format!("cannot read {} for version pinning: {e}", path.display()),
            "check the path exists; every call must pin instruction and policy versions",
        )
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test gateway && cargo clippy --all-targets -- -D warnings`
Expected: PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/gateway.rs src/lib.rs
git commit -m "feat(slice-02): gateway timestamp and version-pinning helpers"
```

---

### Task 2: Provider config, GatewayRun open and seal

**Files:**
- Modify: `src/gateway.rs`
- Test: `tests/gateway.rs` (create)

**Interfaces:**
- Consumes: `gantry::ledger::Ledger` (`Ledger::init(&Path) -> Result<Ledger, Fault>`, `Ledger::open`, `append(NewEvent) -> Result<Envelope, Fault>`, `latest_head() -> Result<SignedHead, Fault>`, `size() -> usize`), `gantry::event::NewEvent`, Task 1 helpers.
- Produces:
  - `pub struct Provider { pub name: String, pub base_url: String, pub model: String, pub key_env: Option<String>, pub window_budget: u64, pub cost_in_per_mtok: f64, pub cost_out_per_mtok: f64 }` (Serialize, Deserialize, Clone, Debug; the three optional fields `#[serde(default)]`).
  - `pub struct Pinning { pub policy: PathBuf, pub instructions: PathBuf, pub settings: Option<PathBuf> }`
  - `pub struct GatewayRun` with `pub fn open(ledger: Ledger, workload: &str, pin: &Pinning) -> Result<GatewayRun, Fault>`, `pub fn seal(self, outcome: &str) -> Result<SignedHead, Fault>`, `pub fn run_id(&self) -> &str`.
  - `pub fn load_providers(path: &Path) -> Result<Vec<Provider>, Fault>`

- [ ] **Step 1: Write the failing test**

Create `tests/gateway.rs`:

```rust
use gantry::gateway::{GatewayRun, Pinning};
use gantry::ledger::{self, Ledger};
use std::fs;
use std::path::PathBuf;

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-gw-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn pinning(dir: &PathBuf) -> Pinning {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test gateway`
Expected: FAIL to compile (types missing).

- [ ] **Step 3: Implement in `src/gateway.rs`**

```rust
use crate::event::NewEvent;
use crate::ledger::{Ledger, SignedHead};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

/// One reachable model endpoint. All three proof environments are entries of
/// this one shape; the seam under test is the event, not the adapter count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub key_env: Option<String>,
    pub window_budget: u64,
    #[serde(default)]
    pub cost_in_per_mtok: f64,
    #[serde(default)]
    pub cost_out_per_mtok: f64,
}

/// The tracked files whose hashes pin authority per event (schema constraint 5).
pub struct Pinning {
    pub policy: PathBuf,
    pub instructions: PathBuf,
    pub settings: Option<PathBuf>,
}

/// An open run. Owning the only route to a model call is what makes the
/// gateway a chokepoint rather than a convention.
pub struct GatewayRun {
    ledger: Ledger,
    run_id: String,
    next_seq: u64,
    actor: Value,
    authority: Value,
    cost_total_usd: f64,
}

pub fn load_providers(path: &std::path::Path) -> Result<Vec<Provider>, Fault> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Fault::new(
            format!("cannot read providers file {}: {e}", path.display()),
            "check the path; the tracked file is config/providers.json",
        )
    })?;
    serde_json::from_str(&text).map_err(|e| {
        Fault::new(
            format!("{} does not parse as a provider list: {e}", path.display()),
            "each entry needs name, base_url, model, window_budget; key_env and cost rates are optional",
        )
    })
}

impl GatewayRun {
    pub fn open(ledger: Ledger, workload: &str, pin: &Pinning) -> Result<GatewayRun, Fault> {
        let instruction_version = file_hash(&pin.instructions)?;
        let settings_hash = match &pin.settings {
            Some(p) => Value::String(file_hash(p)?),
            None => Value::Null,
        };
        let authority = json!({
            "profile": "laptop",
            "policy_version": file_hash(&pin.policy)?,
            "instruction_version": instruction_version,
            "settings_hash": settings_hash,
            "diverged": [],
        });
        let actor = json!({
            "type": "agent",
            "id": "agent:gantry-run",
            "identity_source": "local",
            "rung": "assisted",
        });
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let run_id = format!("run-{}", d.as_millis());
        let mut run = GatewayRun {
            ledger,
            run_id,
            next_seq: 0,
            actor,
            authority,
            cost_total_usd: 0.0,
        };
        run.append_event(
            "run.open",
            json!({
                "profile": "laptop",
                "workload": workload,
                "instruction_pack": instruction_version,
                "settings_hash": run.authority["settings_hash"],
                "restored_checkpoint": null,
            }),
        )?;
        Ok(run)
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn seal(mut self, outcome: &str) -> Result<SignedHead, Fault> {
        let head_at_seal = self.ledger.latest_head()?;
        let event_count = self.next_seq;
        let cost = self.cost_total_usd;
        self.append_event(
            "run.seal",
            json!({
                "outcome": outcome,
                "event_count": event_count,
                "head_at_seal": head_at_seal,
                "cost_total_usd": cost,
            }),
        )?;
        self.ledger.latest_head()
    }

    fn append_event(&mut self, kind: &str, subject: Value) -> Result<(), Fault> {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.ledger.append(NewEvent {
            id: format!("{}-{seq}", self.run_id),
            run_id: self.run_id.clone(),
            parent_id: None,
            seq,
            ts: rfc3339_now(),
            kind: kind.to_string(),
            actor: self.actor.clone(),
            authority: self.authority.clone(),
            subject,
            redacted: Vec::new(),
            attestation: None,
        })?;
        Ok(())
    }
}
```

Note: `SignedHead` must be `Serialize` already (it is printed as JSON by the CLI). If `json!` cannot embed it directly, use `serde_json::to_value(&head_at_seal)` with a `Fault` mapping the error to "report this as a bug; SignedHead is serialisable by construction".

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add src/gateway.rs tests/gateway.rs
git commit -m "feat(slice-02): GatewayRun opens and seals runs as ledger events"
```

---

### Task 3: The model call, happy path, against a loopback stub

**Files:**
- Modify: `Cargo.toml`, `docs/DEPENDENCIES.md`, `src/gateway.rs`
- Test: `tests/gateway.rs`

**Interfaces:**
- Consumes: Task 2 `GatewayRun`, `Provider`; `gantry::event::subject_hash(&Value) -> Result<String, Fault>`.
- Produces:
  - `pub struct ChatMessage { pub role: String, pub content: String }` (Serialize, Clone, Debug), `pub fn msg(role: &str, content: &str) -> ChatMessage`.
  - `pub struct CallResult { pub content: String, pub prompt_tokens: u64, pub completion_tokens: u64, pub latency_ms: u64 }`
  - `GatewayRun::call(&mut self, provider: &Provider, messages: &[ChatMessage]) -> Result<CallResult, Fault>`
  - Test helper in `tests/gateway.rs`: `fn stub(status: u16, body: &str) -> (String, std::thread::JoinHandle<Vec<u8>>)` returning a base_url like `http://127.0.0.1:PORT/v1` and the raw request bytes it saw.

- [ ] **Step 1: Add the dependency**

In `Cargo.toml` under the existing dependency comments:

```toml
# ureq: blocking HTTP for the gateway adapter, rustls TLS. The gateway is the
# one component allowed to reach a provider; see docs/DEPENDENCIES.md.
ureq = { version = "2", features = ["json"] }
```

Append to `docs/DEPENDENCIES.md`:

```markdown
## ureq

Network capability: yes, and it is the point. The gateway adapter is the one
chokepoint allowed to reach a model provider (architecture invariant one).
Blocking client, rustls, no tokio tree. Tests never use it against a real
host; the suite talks to loopback stubs only.
```

Run: `cargo build`
Expected: compiles.

- [ ] **Step 2: Write the failing test**

Append to `tests/gateway.rs`:

```rust
use gantry::gateway::{msg, Provider};
use std::io::{Read, Write};
use std::net::TcpListener;

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
    let s_hex = call["subject_hash"].as_str().unwrap().trim_start_matches("sha256:");
    let subject: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(led.join("payloads").join(format!("{s_hex}.json"))).unwrap())
            .unwrap();
    assert_eq!(subject["provider"], "stub");
    assert_eq!(subject["outcome"], "ok");
    assert_eq!(subject["tokens"], serde_json::json!({"prompt": 42, "completion": 7}));
    assert_eq!(subject["window"], serde_json::json!({"budget": 8192, "actual": 49}));
    assert!(subject["prompt_hash"].as_str().unwrap().starts_with("sha256:"));
    assert!(subject["cost_usd"].as_f64().unwrap() > 0.0);
    assert!(subject.get("messages").is_none(), "raw prompt never in the subject");

    // seal carries the accumulated cost
    let seal: serde_json::Value = serde_json::from_str(lines.lines().nth(2).unwrap()).unwrap();
    let seal_hex = seal["subject_hash"].as_str().unwrap().trim_start_matches("sha256:");
    let seal_subject: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(led.join("payloads").join(format!("{seal_hex}.json"))).unwrap())
            .unwrap();
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --test gateway`
Expected: FAIL to compile (`msg`, `call` missing).

- [ ] **Step 4: Implement in `src/gateway.rs`**

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

pub fn msg(role: &str, content: &str) -> ChatMessage {
    ChatMessage { role: role.to_string(), content: content.to_string() }
}

#[derive(Debug, Clone)]
pub struct CallResult {
    pub content: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub latency_ms: u64,
}

impl GatewayRun {
    /// The chokepoint. Issues one chat completion and appends the call to the
    /// ledger whether it succeeded or not. The key never leaves this frame.
    pub fn call(&mut self, provider: &Provider, messages: &[ChatMessage]) -> Result<CallResult, Fault> {
        let key = match &provider.key_env {
            Some(var) => match std::env::var(var) {
                Ok(v) if !v.is_empty() => Some(v),
                _ => {
                    return Err(Fault::new(
                        format!("provider {} needs a key in ${var}, which is unset or empty", provider.name),
                        format!("export {var} before running, or drop key_env from the provider entry"),
                    ))
                }
            },
            None => None,
        };
        let prompt_hash = crate::event::subject_hash(&json!(messages))?;
        let url = format!("{}/chat/completions", provider.base_url);
        let body = json!({ "model": provider.model, "messages": messages });
        let started = std::time::Instant::now();
        let outcome = http_post_json(&url, key.as_deref(), &body);
        let latency_ms = started.elapsed().as_millis() as u64;

        match outcome {
            Ok(resp) => {
                let content = resp["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let prompt_tokens = resp["usage"]["prompt_tokens"].as_u64().unwrap_or(0);
                let completion_tokens = resp["usage"]["completion_tokens"].as_u64().unwrap_or(0);
                let cost_usd = (prompt_tokens as f64 * provider.cost_in_per_mtok
                    + completion_tokens as f64 * provider.cost_out_per_mtok)
                    / 1_000_000.0;
                self.cost_total_usd += cost_usd;
                self.append_event("model.call", json!({
                    "provider": provider.name,
                    "model": provider.model,
                    "base_url": provider.base_url,
                    "key_env": provider.key_env,
                    "declared_inputs": [{"name": "messages", "arrived": true}],
                    "prompt_hash": prompt_hash,
                    "window": {"budget": provider.window_budget, "actual": prompt_tokens + completion_tokens},
                    "tokens": {"prompt": prompt_tokens, "completion": completion_tokens},
                    "cost_usd": cost_usd,
                    "latency_ms": latency_ms,
                    "outcome": "ok",
                    "error": null,
                }))?;
                Ok(CallResult { content, prompt_tokens, completion_tokens, latency_ms })
            }
            Err(fault) => {
                self.append_event("model.call", json!({
                    "provider": provider.name,
                    "model": provider.model,
                    "base_url": provider.base_url,
                    "key_env": provider.key_env,
                    "declared_inputs": [{"name": "messages", "arrived": true}],
                    "prompt_hash": prompt_hash,
                    "window": {"budget": provider.window_budget, "actual": null},
                    "tokens": null,
                    "cost_usd": 0.0,
                    "latency_ms": latency_ms,
                    "outcome": "error",
                    "error": {"cause": fault.cause, "fix": fault.fix.clone()},
                }))?;
                Err(Fault::new(
                    format!("model call to {} failed and is on the ledger", provider.name),
                    fault.fix,
                ))
            }
        }
    }
}

fn http_post_json(url: &str, key: Option<&str>, body: &Value) -> Result<Value, Fault> {
    let mut req = ureq::post(url).timeout(std::time::Duration::from_secs(180));
    if let Some(k) = key {
        req = req.set("Authorization", &format!("Bearer {k}"));
    }
    match req.send_json(body.clone()) {
        Ok(resp) => resp.into_json::<Value>().map_err(|e| {
            Fault::new(
                format!("provider returned a non-JSON body: {e}"),
                "check base_url points at an OpenAI-compatible /v1 endpoint",
            )
        }),
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            let text = text.chars().take(300).collect::<String>();
            Err(Fault::new(
                format!("provider returned HTTP {code}: {text}"),
                "check the model name, the key, and the provider status page",
            ))
        }
        Err(ureq::Error::Transport(t)) => Err(Fault::new(
            format!("cannot reach {url}: {t}"),
            "check the base_url, the network route, and that the endpoint is up",
        )),
    }
}
```

Note for the implementer: the missing-key case appends no event because no call was issued; the test pins this. If clippy flags the `as f64` casts, allow them locally with a comment naming why the precision loss is acceptable (token counts are far below 2^52).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS, clippy clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock docs/DEPENDENCIES.md src/gateway.rs tests/gateway.rs
git commit -m "feat(slice-02): model calls flow through the gateway onto the ledger

Adds ureq (rustls) as the adapter's HTTP client; the gateway is the one
component allowed network reach, noted in docs/DEPENDENCIES.md."
```

---

### Task 4: Error paths are ledger events

**Files:**
- Modify: `tests/gateway.rs` (implementation should already satisfy; fix `src/gateway.rs` if not)

**Interfaces:**
- Consumes: Task 3 `stub`, `provider`, `GatewayRun::call`.
- Produces: regression tests `http_500_is_a_ledger_event`, `connection_refused_is_a_ledger_event`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/gateway.rs`:

```rust
fn read_subject(led: &PathBuf, line: usize) -> serde_json::Value {
    let lines = fs::read_to_string(led.join("events.jsonl")).unwrap();
    let env: serde_json::Value = serde_json::from_str(lines.lines().nth(line).unwrap()).unwrap();
    let hex_part = env["subject_hash"].as_str().unwrap().trim_start_matches("sha256:");
    serde_json::from_str(&fs::read_to_string(led.join("payloads").join(format!("{hex_part}.json"))).unwrap()).unwrap()
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
```

- [ ] **Step 2: Run tests**

Run: `cargo test --test gateway`
Expected: PASS if Task 3 was implemented as written; if either fails, fix `call()` until both pass without weakening the happy-path test.

- [ ] **Step 3: Commit**

```bash
git add tests/gateway.rs
git commit -m "test(slice-02): failed model calls land on the ledger with a named fix"
```

---

### Task 5: Shape stability and the no-key-bytes assertion

**Files:**
- Modify: `tests/gateway.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: `envelope_shape_identical_across_providers`, `key_bytes_never_reach_the_ledger`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/gateway.rs`:

```rust
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
    let (base, _srv) = stub(200, OK_BODY);
    let led = dir.join("ledger");
    let mut run = GatewayRun::open(Ledger::init(&led).unwrap(), "smoke", &pin).unwrap();
    run.call(&provider(&base, "stub", Some("GANTRY_TEST_CANARY_KEY")), &[msg("user", "hello")]).unwrap();
    run.seal("complete").unwrap();
    for entry in fs::read_dir(&led).unwrap().chain(fs::read_dir(led.join("payloads")).unwrap()) {
        let path = entry.unwrap().path();
        if path.is_file() {
            let text = fs::read_to_string(&path).unwrap();
            assert!(!text.contains(canary), "key bytes found in {}", path.display());
        }
    }
}
```

Note: `read_dir(...).chain(read_dir(...))` iterates the ledger root (`events.jsonl`, `heads.jsonl`, key files) and `payloads/`. If the ledger nests other directories, walk them too; the assertion must cover every file under the ledger dir.

- [ ] **Step 2: Run tests**

Run: `cargo test --test gateway`
Expected: PASS (both are properties the implementation should already hold; a failure is a real defect, fix `src/gateway.rs`).

- [ ] **Step 3: Commit**

```bash
git add tests/gateway.rs
git commit -m "test(slice-02): one shape across providers, no key bytes on the ledger"
```

---

### Task 6: Tracked config, instruction pack, and the run subcommand

**Files:**
- Create: `config/providers.json`, `instructions/pack.md`
- Modify: `src/main.rs`
- Test: manual smoke against a stub is impractical from the CLI; the subcommand is one library call per line, and the proof run in Task 7 is its test. Unit-test only `load_providers` wiring via `cargo test`.

**Interfaces:**
- Consumes: `load_providers`, `GatewayRun`, `msg`, `Ledger::init`, `Ledger::open`.
- Produces: `gantry run <providers.json> <provider-name> <ledger-dir>`.

- [ ] **Step 1: Create `instructions/pack.md`**

```markdown
# Instruction pack: gateway smoke workload, v1

You are a security audit agent. Answer in one sentence, no preamble. This
file is version-pinned: its sha256 is the instruction_version on every event
of a run that consumed it.
```

- [ ] **Step 2: Create `config/providers.json`**

```json
[
  {
    "name": "openai",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-5-mini",
    "key_env": "OPENAI_API_KEY",
    "window_budget": 128000,
    "cost_in_per_mtok": 0.25,
    "cost_out_per_mtok": 2.0
  },
  {
    "name": "gpu-box",
    "base_url": "http://100.120.203.53:11434/v1",
    "model": "gemma4-8b-32k",
    "window_budget": 32768
  },
  {
    "name": "local",
    "base_url": "http://127.0.0.1:11434/v1",
    "model": "qwen3:0.6b",
    "window_budget": 32768
  }
]
```

Cost rates are config data; correct them against the provider's price page at proof time if they have drifted, and note the check in the proof.

- [ ] **Step 3: Add the subcommand to `src/main.rs`**

Add to the `USAGE` string:

```
  gantry run <providers.json> <provider-name> <ledger-dir>
```

Add imports:

```rust
use gantry::gateway::{self, msg, GatewayRun, Pinning};
```

Add the match arm before the `[]` arm:

```rust
["run", providers_path, name, ledger_dir] => {
    let providers = gateway::load_providers(Path::new(providers_path))?;
    let provider = providers.iter().find(|p| p.name == *name).ok_or_else(|| {
        let names: Vec<&str> = providers.iter().map(|p| p.name.as_str()).collect();
        Fault::new(
            format!("no provider named {name} in {providers_path}"),
            format!("use one of: {}", names.join(", ")),
        )
    })?;
    let dir = Path::new(ledger_dir);
    let ledger = if dir.join("events.jsonl").exists() {
        Ledger::open(dir)?
    } else {
        Ledger::init(dir)?
    };
    let pack_path = Path::new("instructions/pack.md");
    let pin = Pinning {
        policy: "docs/POLICY-SCHEMA.md".into(),
        instructions: pack_path.into(),
        settings: Some(Path::new(".claude/settings.json"))
            .filter(|p| p.exists())
            .map(Into::into),
    };
    let system = read_file(&pack_path.display().to_string())?;
    let mut run = GatewayRun::open(ledger, "gateway-smoke", &pin)?;
    let q1 = "Name the single biggest risk of an unsigned tool registry.";
    let a1 = run.call(provider, &[msg("system", &system), msg("user", q1)])?;
    println!("[{}] {}", provider.name, a1.content.trim());
    let q2 = "Name one mitigation for that risk.";
    let a2 = run.call(
        provider,
        &[msg("system", &system), msg("user", q1), msg("assistant", &a1.content), msg("user", q2)],
    )?;
    println!("[{}] {}", provider.name, a2.content.trim());
    let head = run.seal("complete")?;
    println!("sealed: {} events, head size {}", head.size, head.size);
    Ok(0)
}
```

If a call fails, `?` propagates the Fault after the event is already on the ledger; the run is left unsealed, which is itself honest evidence. State this in a one-line comment.

- [ ] **Step 4: Build, lint, run against a dead port to see the error path once**

Run: `cargo build && cargo clippy --all-targets -- -D warnings`
Expected: clean.

Run: `printf '[{"name":"dead","base_url":"http://127.0.0.1:9/v1","model":"x","window_budget":1}]' > /tmp/dead.json && ./target/debug/gantry run /tmp/dead.json dead /tmp/gantry-dead-ledger; ./target/debug/gantry ledger verify /tmp/gantry-dead-ledger`
Expected: a Fault naming the fix, exit 1; verify shows 2 entries (run.open plus the error model.call) and passes.

- [ ] **Step 5: Commit**

```bash
git add config/providers.json instructions/pack.md src/main.rs
git commit -m "feat(slice-02): gantry run drives a pinned two-turn workload through the gateway"
```

---

### Task 7: Three-environment proof run and docs/proof/02.md

This task is run by the main session, not a subagent: it needs live keys, Tailscale, a brew install, and judgment.

**Files:**
- Create: `docs/proof/02-run.sh`, `docs/proof/02.md`
- Modify: `CLAUDE.md` only if a new invariant emerges from the proof.

**Interfaces:**
- Consumes: `gantry run`, `gantry ledger verify`, `gantry ledger prove`, `gantry ledger verify-inclusion`.
- Produces: the proof document that closes the slice, via the `/proof` command.

- [ ] **Step 1: Preflight the three environments**

```bash
tailscale status | grep windows-11        # GPU box awake?
curl -s --max-time 5 http://100.120.203.53:11434/v1/models | head -c 200
brew install ollama && brew services start ollama
ollama pull qwen3:0.6b
curl -s http://127.0.0.1:11434/v1/models | head -c 200
```

If the GPU box is asleep, ask Mariano to wake it rather than probing further (remote execution boundary: no SSH push).

- [ ] **Step 2: Write `docs/proof/02-run.sh`**

Shape, mirroring `docs/proof/01-run.sh` conventions:

```bash
#!/bin/zsh
# Proof 02: one run per environment, three ledgers, one shape.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof02.XXXXXX)
echo "workdir: $WORK"

for name in openai gpu-box local; do
  if [ "$name" = "local" ]; then
    # Loopback only. The deny comes first, the loopback carve-out second.
    sandbox-exec -p '(version 1)(allow default)(deny network*)(allow network* (remote ip "localhost:11434"))' \
      $BIN run config/providers.json local $WORK/ledger-local
  else
    $BIN run config/providers.json $name $WORK/ledger-$name
  fi
  $BIN ledger verify $WORK/ledger-$name
done

# Negative control: the same sandbox profile must refuse a non-loopback route.
sandbox-exec -p '(version 1)(allow default)(deny network*)(allow network* (remote ip "localhost:11434"))' \
  curl -s --max-time 5 https://api.openai.com/v1/models && echo "SANDBOX LEAK" || echo "external route denied, as required"

# The shape diff: field sets of every envelope and every model.call subject.
for name in openai gpu-box local; do
  jq -cS 'keys' $WORK/ledger-$name/events.jsonl | sort -u > $WORK/shape-envelope-$name.txt
done
diff $WORK/shape-envelope-openai.txt $WORK/shape-envelope-gpu-box.txt
diff $WORK/shape-envelope-openai.txt $WORK/shape-envelope-local.txt
echo "envelope shapes identical"
```

Iterate on the sandbox profile syntax until the negative control denies and the local run passes; record the final profile verbatim in the proof.

- [ ] **Step 3: Run it, then one offline inclusion check on the local ledger**

```bash
cargo build
zsh docs/proof/02-run.sh
./target/debug/gantry ledger prove <workdir>/ledger-local 1 > /tmp/bundle02.json
cp <workdir>/ledger-local/ledger.pub /tmp/
cd /tmp && sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  <repo>/target/debug/gantry ledger verify-inclusion bundle02.json ledger.pub
```

- [ ] **Step 4: Write the proof with the `/proof` command**

The document must contain: the claim, the three-environment run as the adversarial case (plus the sandbox negative control and the dead-port error-event run from Task 6), verbatim output, the shape diff, model.call subject values side by side (provider, model, tokens, cost, latency differ; keys identical), what surprised, and the conformance delta (primitive 02 and 11 move; 11 now has a chokepoint feeding it from a real run).

- [ ] **Step 5: Commit**

```bash
git add docs/proof/02-run.sh docs/proof/02.md
git commit -m "feat(slice-02): three-environment gateway proof, one ledger shape"
```

---

## Self-review notes

- Spec coverage: environments (Task 6 config, Task 7 run), adapter and chokepoint (Task 3), window accounting and cost (Task 3), pinning (Tasks 1, 2, 6), secrets (Tasks 3, 5), error events (Tasks 3, 4), shape claim (Tasks 5, 7), out-of-scope items untouched.
- ureq 2 API pinned (`version = "2"`); ureq 3 renamed these calls, do not upgrade mid-slice.
- `SignedHead` serialisation inside `json!` may need `serde_json::to_value`; noted in Task 2.
