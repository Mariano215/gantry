//! The console server and its read-only API, implementing
//! `docs/CONSOLE-API.md`. Standard library only: eight read-only routes do
//! not earn a web framework, and a framework would owe an entry in
//! `docs/DEPENDENCIES.md` that no reader would think was worth it.
//!
//! Three properties the routes hold:
//!
//! - Read-only. GET is the only method; anything else is 405. The console
//!   cannot approve, promote, demote or append, because a UI that can move a
//!   rung is an authority surface and the laptop profile has no identity
//!   story for one.
//! - Every response derives from the ledger on that request. Nothing is
//!   cached across requests, so a page is the current state of the log or it
//!   is a fault.
//! - An error is a `Fault`: `{"cause", "fix"}`, the same shape the CLI
//!   prints, and the fix names the action to take.

use crate::ledger::{self, ActorKeys, AttestationState, Ledger};
use crate::policy::Policy;
use crate::scorer::{ScoreSnapshot, Scoring};
use crate::trust::TrustState;
use crate::Fault;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

/// Tracked configuration the API reads per request, relative to the working
/// directory the server was started in.
const SCORING_PATH: &str = "config/scoring.json";
const POLICY_PATH: &str = "config/policy.json";
const ACTOR_KEYS_PATH: &str = "config/actor-keys.json";

/// A request head longer than this is refused rather than truncated. Reading
/// a fixed buffer and routing on whatever landed in it is how a long query
/// silently becomes a different query.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// What a refused request is allowed to still be sending, and how long to let
/// it. Closing a socket with unread bytes in it resets the connection, and the
/// response the client would lose is the one explaining the refusal.
const MAX_DRAIN_BYTES: usize = 4 * 1024 * 1024;
const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;

// -- server -----------------------------------------------------------------

/// Binds the console socket. Separate from `serve_on` so a caller that needs
/// the bound port (a test on an ephemeral port, say) can read it before the
/// accept loop starts.
pub fn bind(addr: &str) -> Result<TcpListener, Fault> {
    TcpListener::bind(addr).map_err(|e| {
        Fault::new(
            format!("cannot bind {addr}: {e}"),
            "use 127.0.0.1:0 for an ephemeral loopback port, or free the port",
        )
    })
}

/// Serve the console over loopback. One process, one thread, stdlib only;
/// every response is derived from the ledger on the request, so the page is
/// the log's current state. Loopback by default; an operator exposing it
/// further does so explicitly, and the read-only rule is what makes that
/// survivable.
pub fn serve(ledger_dir: &str, addr: &str) -> Result<i32, Fault> {
    let listener = bind(addr)?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| addr.to_string());
    println!("console at http://{bound}/ (ctrl-c to stop)");
    serve_on(&listener, ledger_dir);
    Ok(0)
}

/// The accept loop. One connection at a time: the API is read-only and
/// loopback, so a queue is cheaper than a thread pool nobody measured.
// ponytail: sequential accept. Spawn per connection if a slow /api/verify
// starts blocking the console in practice.
pub fn serve_on(listener: &TcpListener, ledger_dir: &str) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let response = match read_request(&mut stream) {
            Ok(request) => respond(ledger_dir, &request),
            Err(response) => response,
        };
        response.write_to(&mut stream);
    }
}

// -- responses --------------------------------------------------------------

struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    /// Extra header lines, each already `\r\n` terminated.
    extra: &'static str,
    body: String,
}

const JSON: &str = "application/json; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

impl Response {
    fn json(value: &Value) -> Response {
        Response {
            status: 200,
            reason: "OK",
            content_type: JSON,
            extra: "",
            body: value.to_string(),
        }
    }

    fn html(body: String) -> Response {
        Response {
            status: 200,
            reason: "OK",
            content_type: HTML,
            extra: "",
            body,
        }
    }

    fn fault(status: u16, reason: &'static str, extra: &'static str, fault: &Fault) -> Response {
        Response {
            status,
            reason,
            content_type: JSON,
            extra,
            body: json!({"cause": fault.cause, "fix": fault.fix}).to_string(),
        }
    }

    fn write_to(&self, stream: &mut TcpStream) {
        let head = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n{}connection: close\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len(),
            self.extra
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(self.body.as_bytes());
        let _ = stream.flush();
    }
}

/// An API failure: the status, its reason phrase, and the Fault to serialise.
type ApiError = (u16, &'static str, Fault);

fn bad_request(fault: Fault) -> ApiError {
    (400, "Bad Request", fault)
}

fn not_found(fault: Fault) -> ApiError {
    (404, "Not Found", fault)
}

fn read_failure(fault: Fault) -> ApiError {
    (500, "Internal Server Error", fault)
}

fn as_value<T: serde::Serialize>(value: &T, what: &str) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|e| {
        read_failure(Fault::new(
            format!("{what} does not serialise: {e}"),
            "report this as a bug; the type is serialisable by construction",
        ))
    })
}

// -- request parsing --------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
}

/// Reads and parses one request head. The whole head is read up to a cap and
/// the request line is taken from it complete, never from a fixed prefix: a
/// query longer than one buffer must be refused or honoured, not truncated
/// into a shorter query that means something else.
fn read_request(stream: &mut TcpStream) -> Result<Request, Response> {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > MAX_REQUEST_BYTES {
            drain(stream);
            return Err(Response::fault(
                400,
                "Bad Request",
                "",
                &Fault::new(
                    format!("the request head exceeds {MAX_REQUEST_BYTES} bytes"),
                    "shorten the query string; the API refuses a head it cannot read whole rather than truncating it into a different request",
                ),
            ));
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let Some(line) = text.split("\r\n").next().filter(|l| !l.is_empty()) else {
        return Err(Response::fault(
            400,
            "Bad Request",
            "",
            &Fault::new(
                "the connection carried no complete request line",
                "send a well-formed request line, for example: GET /api/score HTTP/1.1",
            ),
        ));
    };

    let parts: Vec<&str> = line.split(' ').collect();
    let [method, target, _version] = parts.as_slice() else {
        return Err(Response::fault(
            400,
            "Bad Request",
            "",
            &Fault::new(
                format!("request line {line:?} is not METHOD TARGET VERSION"),
                "send a well-formed request line, for example: GET /api/score HTTP/1.1",
            ),
        ));
    };

    if *method != "GET" {
        return Err(Response::fault(
            405,
            "Method Not Allowed",
            "allow: GET\r\n",
            &Fault::new(
                format!("{method} is not allowed: the console API is read-only"),
                "use GET; approving, promoting and appending are CLI operations because a write path here would be an unauthenticated authority surface",
            ),
        ));
    }

    parse_target(target).map(|(path, query)| Request {
        method: (*method).to_string(),
        path,
        query,
    })
}

/// Splits an origin-form target into a decoded path and its query pairs. A
/// target this cannot parse is refused; guessing what a malformed escape
/// meant would answer a question nobody asked.
fn parse_target(target: &str) -> Result<(String, Vec<(String, String)>), Response> {
    let malformed = |what: String| {
        Response::fault(
            400,
            "Bad Request",
            "",
            &Fault::new(
                what,
                "percent-encode the value with encodeURIComponent and retry; the API refuses a target it cannot decode rather than guessing",
            ),
        )
    };

    if !target.starts_with('/') {
        return Err(malformed(format!(
            "request target {target:?} is not origin form"
        )));
    }
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let path = percent_decode(raw_path).ok_or_else(|| {
        malformed(format!(
            "path {raw_path:?} is not valid percent-encoded UTF-8"
        ))
    })?;

    let mut query = Vec::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((k, v)) = pair.split_once('=') else {
            return Err(malformed(format!(
                "query parameter {pair:?} has no value; every parameter is key=value"
            )));
        };
        // Percent-decoding only: `+` is left alone, because encodeURIComponent
        // leaves it alone and an actor id or a hash may contain one.
        let (Some(k), Some(v)) = (percent_decode(k), percent_decode(v)) else {
            return Err(malformed(format!(
                "query parameter {pair:?} is not valid percent-encoded UTF-8"
            )));
        };
        query.push((k, v));
    }
    Ok((path, query))
}

/// Reads and discards what a refused request is still sending, so the refusal
/// itself reaches the client instead of being lost to a connection reset.
/// Bounded in bytes and in time: a client that will not stop is dropped.
fn drain(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(DRAIN_TIMEOUT));
    let mut sink = [0u8; 8192];
    let mut discarded = 0usize;
    while discarded < MAX_DRAIN_BYTES {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => discarded += n,
        }
    }
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Normalises an ISO 8601 instant to `YYYY-MM-DDTHH:MM:SS.mmm` so two
/// timestamps compare as plain strings whether or not either carries a
/// fraction. Accepts a bare date and a `Z` suffix; refuses a numeric zone
/// offset rather than assuming it is UTC.
fn normalise_ts(raw: &str) -> Option<String> {
    let s = raw.strip_suffix('Z').unwrap_or(raw);
    // The date's own separators sit at 4 and 7; a later `-` or any `+` is a
    // zone offset this does not convert.
    if s.contains('+') || s.rfind('-').is_some_and(|i| i > 7) {
        return None;
    }
    let (date, time) = match s.split_once('T') {
        Some((d, t)) => (d, t),
        None => (s, ""),
    };
    let mut date_parts = date.split('-');
    let (year, month, day) = (date_parts.next()?, date_parts.next()?, date_parts.next()?);
    if date_parts.next().is_some()
        || !digits(year, 4)
        || !digits(month, 2)
        || !digits(day, 2)
        || !time.is_empty() && time.len() < 5
    {
        return None;
    }
    if time.is_empty() {
        return Some(format!("{date}T00:00:00.000"));
    }
    let (clock, frac) = match time.split_once('.') {
        Some((c, f)) => (c, f),
        None => (time, ""),
    };
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut clock_parts = clock.split(':');
    let (hour, minute) = (clock_parts.next()?, clock_parts.next()?);
    let second = clock_parts.next().unwrap_or("00");
    if clock_parts.next().is_some() || !digits(hour, 2) || !digits(minute, 2) || !digits(second, 2)
    {
        return None;
    }
    let mut millis = frac.to_string();
    millis.truncate(3);
    while millis.len() < 3 {
        millis.push('0');
    }
    Some(format!("{date}T{hour}:{minute}:{second}.{millis}"))
}

fn digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}

// -- routing ----------------------------------------------------------------

fn respond(ledger_dir: &str, request: &Request) -> Response {
    debug_assert_eq!(request.method, "GET");
    if let Some(route) = request.path.strip_prefix("/api/") {
        return match api(ledger_dir, route, &request.query) {
            Ok(value) => Response::json(&value),
            Err((status, reason, fault)) => Response::fault(status, reason, "", &fault),
        };
    }
    // Unknown non-API paths serve the console shell, so the front end owns
    // its own routing.
    match scorecard(ledger_dir) {
        Ok(body) => Response::html(body),
        Err((status, reason, fault)) => Response {
            status,
            reason,
            content_type: HTML,
            extra: "",
            body: format!(
                "<!doctype html><meta charset=utf-8><title>Gantry console</title>\
<h1>The console cannot read the ledger</h1><p>{}</p><p><b>Fix:</b> {}</p>",
                escape(&fault.cause),
                escape(&fault.fix)
            ),
        },
    }
}

fn api(ledger_dir: &str, route: &str, query: &[(String, String)]) -> Result<Value, ApiError> {
    match route {
        "score" => score(ledger_dir),
        "head" => head(ledger_dir),
        "events" => events(ledger_dir, query),
        "runs" => runs(ledger_dir),
        "policy" => policy(ledger_dir),
        "trust" => trust(ledger_dir),
        "verify" => verify(ledger_dir),
        _ => match route.strip_prefix("events/") {
            Some(id) if !id.is_empty() && !id.contains('/') => one_event(ledger_dir, id),
            _ => Err(not_found(Fault::new(
                format!("/api/{route} is not a route"),
                "the routes are /api/score, /api/head, /api/events, /api/events/:id, /api/runs, /api/policy, /api/trust and /api/verify; see docs/CONSOLE-API.md",
            ))),
        },
    }
}

// -- handlers ---------------------------------------------------------------

fn open_ledger(ledger_dir: &str) -> Result<Ledger, ApiError> {
    Ledger::open(Path::new(ledger_dir)).map_err(read_failure)
}

/// The registered actor keys. A corrupt registry refuses whole, so a partial
/// trust root can never turn "unchecked" into "clean" on a rendered page.
/// Returns the registered keys and, separately, those whose seed is
/// published. The split is what lets a rendered page distinguish a signature
/// anyone could have produced from one only the key holder could.
fn actor_keys() -> Result<(Vec<String>, Vec<String>), ApiError> {
    let path = Path::new(ACTOR_KEYS_PATH);
    if !path.exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    crate::skills::KeyRegistry::load(path)
        .map(|registry| (registry.key_hexes(), registry.published_seed_hexes()))
        .map_err(read_failure)
}

/// Every event with its subject inlined and its attestation state derived.
/// The state comes from `ledger::ActorKeys`, the same code path the full
/// verifier uses, so the API and `gantry ledger verify` cannot disagree about
/// whether a signature is good.
fn annotated_events(ledger: &Ledger) -> Result<Vec<Value>, ApiError> {
    let (registered, published) = actor_keys()?;
    let keys = ActorKeys::parse_with_published(&registered, &published);
    let mut events = ledger.events_with_subjects().map_err(read_failure)?;
    // Both sequences come from the same envelope vector, so the zip is
    // positional and total.
    for (event, envelope) in events.iter_mut().zip(ledger.envelopes()) {
        event["_attestation_state"] = json!(keys.state_of(envelope).as_str());
        // What a verified signature is worth. `fixture` means the seed is
        // published, so the signature proves which run wrote the event and
        // not who operated it. A page that renders this the same as
        // `registered` is claiming attribution the record does not carry.
        event["_attestation_trust"] = json!(keys.trust_of(envelope));
    }
    Ok(events)
}

fn snapshot(ledger_dir: &str) -> Result<ScoreSnapshot, ApiError> {
    let scoring = Scoring::load(Path::new(SCORING_PATH)).map_err(read_failure)?;
    let ledger = open_ledger(ledger_dir)?;
    let events = ledger.events_with_subjects().map_err(read_failure)?;
    Ok(scoring.score(&events))
}

fn score(ledger_dir: &str) -> Result<Value, ApiError> {
    as_value(&snapshot(ledger_dir)?, "ScoreSnapshot")
}

fn head(ledger_dir: &str) -> Result<Value, ApiError> {
    let head = open_ledger(ledger_dir)?
        .latest_head()
        .map_err(read_failure)?;
    as_value(&head, "SignedHead")
}

/// The filters `/api/events` accepts. An unrecognised parameter is refused
/// rather than ignored: a filter that silently does nothing returns the wrong
/// rows under a name that says otherwise.
struct EventQuery {
    kinds: Vec<String>,
    run: Option<String>,
    actor: Option<String>,
    since: Option<String>,
    limit: usize,
    offset: usize,
}

impl EventQuery {
    fn parse(query: &[(String, String)]) -> Result<EventQuery, ApiError> {
        let mut q = EventQuery {
            kinds: Vec::new(),
            run: None,
            actor: None,
            since: None,
            limit: DEFAULT_LIMIT,
            offset: 0,
        };
        for (key, value) in query {
            match key.as_str() {
                "kind" => q.kinds.push(value.clone()),
                "run" => q.run = Some(value.clone()),
                "actor" => q.actor = Some(value.clone()),
                "since" => {
                    q.since = Some(normalise_ts(value).ok_or_else(|| {
                        bad_request(Fault::new(
                            format!("since={value} is not an ISO 8601 instant"),
                            "pass a date like 2026-08-05 or an instant like 2026-08-05T09:14:02Z; a numeric zone offset is not accepted",
                        ))
                    })?)
                }
                "limit" => {
                    q.limit = value
                        .parse::<usize>()
                        .map_err(|_| {
                            bad_request(Fault::new(
                                format!("limit={value} is not a non-negative integer"),
                                format!("pass an integer; the default is {DEFAULT_LIMIT} and anything above {MAX_LIMIT} returns {MAX_LIMIT}"),
                            ))
                        })?
                        .min(MAX_LIMIT)
                }
                "offset" => {
                    q.offset = value.parse::<usize>().map_err(|_| {
                        bad_request(Fault::new(
                            format!("offset={value} is not a non-negative integer"),
                            "pass an integer; offset skips that many events after filtering",
                        ))
                    })?
                }
                other => {
                    return Err(bad_request(Fault::new(
                        format!("{other} is not a query parameter of /api/events"),
                        "the parameters are kind, run, actor, since, limit and offset; correct the spelling rather than relying on an unknown one being ignored",
                    )))
                }
            }
        }
        Ok(q)
    }

    fn matches(&self, event: &Value) -> bool {
        if !self.kinds.is_empty() {
            let kind = event["kind"].as_str().unwrap_or_default();
            if !self.kinds.iter().any(|k| k == kind) {
                return false;
            }
        }
        if let Some(run) = &self.run {
            if event["run_id"].as_str() != Some(run.as_str()) {
                return false;
            }
        }
        if let Some(actor) = &self.actor {
            if !event["actor"].to_string().contains(actor.as_str()) {
                return false;
            }
        }
        if let Some(since) = &self.since {
            // An event whose ts does not parse cannot be placed in time, so a
            // since window excludes it rather than assuming it is recent.
            match event["ts"].as_str().and_then(normalise_ts) {
                Some(ts) if &ts >= since => {}
                _ => return false,
            }
        }
        true
    }
}

fn events(ledger_dir: &str, query: &[(String, String)]) -> Result<Value, ApiError> {
    let q = EventQuery::parse(query)?;
    let events = annotated_events(&open_ledger(ledger_dir)?)?;
    // `total` counts what the filter matched, before limit and offset, which
    // is the number a pager needs.
    let matched: Vec<&Value> = events.iter().filter(|e| q.matches(e)).collect();
    let total = matched.len();
    let page: Vec<Value> = matched
        .into_iter()
        .skip(q.offset)
        .take(q.limit)
        .cloned()
        .collect();
    Ok(json!({
        "events": page,
        "total": total,
        "returned": page.len(),
        "offset": q.offset,
    }))
}

fn one_event(ledger_dir: &str, id: &str) -> Result<Value, ApiError> {
    let ledger = open_ledger(ledger_dir)?;
    let tree_size = ledger.size();
    let events = annotated_events(&ledger)?;
    let index = events
        .iter()
        .position(|e| e["id"].as_str() == Some(id))
        .ok_or_else(|| {
            not_found(Fault::new(
                format!("no event with id {id} is on this ledger"),
                "take an id from /api/events; the ledger is append-only, so an id that was never appended will never appear",
            ))
        })?;
    Ok(json!({
        "event": events[index],
        "index": index,
        "tree_size": tree_size,
    }))
}

/// One run's shape, accumulated from its events in append order.
struct RunAgg {
    run_id: String,
    opened_at: String,
    sealed_at: Option<String>,
    workload: Option<String>,
    events: u64,
    kinds: BTreeMap<String, u64>,
    denials: u64,
    unattested: u64,
}

fn runs(ledger_dir: &str) -> Result<Value, ApiError> {
    let events = annotated_events(&open_ledger(ledger_dir)?)?;
    let mut by_run: BTreeMap<String, RunAgg> = BTreeMap::new();
    for event in &events {
        let run_id = event["run_id"].as_str().unwrap_or_default().to_string();
        let ts = event["ts"].as_str().unwrap_or_default().to_string();
        let kind = event["kind"].as_str().unwrap_or_default().to_string();
        let agg = by_run.entry(run_id.clone()).or_insert_with(|| RunAgg {
            run_id,
            // A run with no run.open is still a run: it is dated by its first
            // event rather than hidden.
            opened_at: ts.clone(),
            sealed_at: None,
            workload: None,
            events: 0,
            kinds: BTreeMap::new(),
            denials: 0,
            unattested: 0,
        });
        agg.events += 1;
        *agg.kinds.entry(kind.clone()).or_insert(0) += 1;
        // Anything short of a verified attestation is unattested. Absent,
        // unverified and forged are all "not signed by a key we trust".
        if event["_attestation_state"].as_str() != Some(AttestationState::Verified.as_str()) {
            agg.unattested += 1;
        }
        match kind.as_str() {
            "run.open" => {
                agg.opened_at = ts;
                agg.workload = event["_subject"]["workload"].as_str().map(String::from);
            }
            "run.seal" => agg.sealed_at = Some(ts),
            // The broker writes the verdict of a policy.decision under
            // `verdict`, the field name `policy::Decision` serialises.
            "policy.decision" if event["_subject"]["verdict"].as_str() == Some("deny") => {
                agg.denials += 1;
            }
            _ => {}
        }
    }
    let mut runs: Vec<RunAgg> = by_run.into_values().collect();
    // Newest first. The open time orders them; the run id breaks ties so the
    // order is stable across requests.
    runs.sort_by(|a, b| {
        b.opened_at
            .cmp(&a.opened_at)
            .then_with(|| b.run_id.cmp(&a.run_id))
    });
    let runs: Vec<Value> = runs
        .into_iter()
        .map(|r| {
            json!({
                "run_id": r.run_id,
                "opened_at": r.opened_at,
                "sealed_at": r.sealed_at,
                "sealed": r.sealed_at.is_some(),
                "workload": r.workload,
                "events": r.events,
                "kinds": r.kinds,
                "denials": r.denials,
                "unattested": r.unattested,
            })
        })
        .collect();
    Ok(json!({ "runs": runs }))
}

fn load_policy() -> Result<(Policy, String), ApiError> {
    let policy = Policy::load(Path::new(POLICY_PATH)).map_err(read_failure)?;
    let version = match &policy.policy_version {
        Some(v) => v.clone(),
        None => policy.version().map_err(read_failure)?,
    };
    Ok((policy, version))
}

fn policy(ledger_dir: &str) -> Result<Value, ApiError> {
    let (policy, version) = load_policy()?;
    let events = open_ledger(ledger_dir)?
        .events_with_subjects()
        .map_err(read_failure)?;

    let mut fired: BTreeMap<String, u64> = BTreeMap::new();
    for event in &events {
        if event["kind"].as_str() == Some("policy.decision") {
            if let Some(rule) = event["_subject"]["rule"].as_str() {
                *fired.entry(rule.to_string()).or_insert(0) += 1;
            }
        }
    }

    let capabilities: Vec<Value> = policy
        .capabilities
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "rung": c.rung.schema_name(),
                "effect": c.effect.schema_name(),
                "rollback": c.rollback,
            })
        })
        .collect();
    // A rule with fired 0 is listed, not hidden: an unfired deny rule is
    // either dead weight or a control nothing has ever tested.
    let rules: Vec<Value> = policy
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "decision": serde_json::to_value(r.action).unwrap_or(Value::Null),
                "message": r.message,
                "fired": fired.get(&r.id).copied().unwrap_or(0),
            })
        })
        .collect();

    Ok(json!({
        "profile": policy.profile,
        "version": version,
        "capabilities": capabilities,
        "rules": rules,
    }))
}

fn trust(ledger_dir: &str) -> Result<Value, ApiError> {
    let (policy, _) = load_policy()?;
    let events = open_ledger(ledger_dir)?
        .events_with_subjects()
        .map_err(read_failure)?;
    let capabilities: Vec<Value> = policy
        .capabilities
        .iter()
        .map(|cap| {
            let state = TrustState::replay(&events, &cap.id, cap.rung);
            let history: Vec<Value> = events
                .iter()
                .filter(|e| {
                    e["_subject"]["capability"].as_str() == Some(cap.id.as_str())
                        && matches!(e["kind"].as_str(), Some("rung.change" | "capability.run"))
                })
                .map(|e| {
                    json!({
                        "ts": e["ts"],
                        "event_id": e["id"],
                        "kind": e["kind"],
                        "from": e["_subject"]["from"],
                        "to": e["_subject"]["to"],
                        "approver": e["_subject"]["approver"],
                    })
                })
                .collect();
            json!({
                "capability": cap.id,
                "declared_rung": cap.rung.schema_name(),
                // Replayed from the ledger, never read from config. When it
                // differs from the declared rung, this is the one the broker
                // gates on.
                "earned_rung": state.rung.schema_name(),
                "clean_since_rung": state.clean_since_rung,
                "history": history,
            })
        })
        .collect();
    Ok(json!({ "capabilities": capabilities }))
}

fn verify(ledger_dir: &str) -> Result<Value, ApiError> {
    let dir = Path::new(ledger_dir);
    let (registered, published) = actor_keys()?;
    let report = ledger::verify_with_actor_keys_and_published(dir, &registered, &published)
        .map_err(read_failure)?;
    // A ledger broken enough that it will not open still gets a verdict: the
    // verifier reads the files, and a head this cannot read is reported as
    // null rather than turning the route that names the damage into a 500.
    let head = Ledger::open(dir)
        .and_then(|l| l.latest_head())
        .ok()
        .map(|h| as_value(&h, "SignedHead"))
        .transpose()?
        .unwrap_or(Value::Null);
    let faults: Vec<Value> = report
        .faults
        .iter()
        .map(|f| {
            json!({
                "index": f.index,
                "id": f.id,
                // The Fault's Display carries its fix, because the reader
                // repairing this is an agent.
                "fault": f.fault.to_string(),
            })
        })
        .collect();
    let path = std::fs::canonicalize(dir)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ledger_dir.to_string());
    Ok(json!({
        "ok": report.ok(),
        "entries": report.entries,
        "attestations_verified": report.attestations_verified,
        "attestations_unverified": report.attestations_unverified,
        // Of those verified, how many were signed under a published seed.
        // The console must qualify its count with this or it presents a
        // laptop fixture signature as attribution.
        "attestations_under_published_seed": report.attestations_under_published_seed,
        "faults": faults,
        "head": head,
        // The exact offline command that reaches the same verdict without
        // this server. The console reports; it never claims to have verified.
        "reproduce": format!("gantry ledger verify {path}"),
    }))
}

// -- the console shell ------------------------------------------------------

fn scorecard(ledger_dir: &str) -> Result<String, ApiError> {
    Ok(scorecard_html(&snapshot(ledger_dir)?))
}

/// A self-contained static console: the scorecard, generated from the
/// snapshot. Slice 11 replaces this with the six-view console under
/// `assets/`; until it lands, a non-API path serves this rather than nothing.
pub fn scorecard_html(snapshot: &ScoreSnapshot) -> String {
    let overall = snapshot
        .overall
        .map(|n| n.to_string())
        .unwrap_or_else(|| "N/A".into());
    let mut rows = String::new();
    for p in &snapshot.scores {
        let (score, cls) = match p.score {
            Some(n) if n >= 4 => (n.to_string(), "good"),
            Some(n) if n >= 3 => (n.to_string(), "ok"),
            Some(n) => (n.to_string(), "low"),
            None => ("N/A".to_string(), "na"),
        };
        rows.push_str(&format!(
            "<tr class=\"{cls}\"><td>{:02}</td><td>{}</td><td class=\"score\">{score}</td><td>{}</td></tr>\n",
            p.primitive, p.name, p.evidence
        ));
    }
    format!(
        "<!doctype html><meta charset=utf-8><title>Gantry conformance</title>\
<style>body{{font:15px system-ui;margin:2rem;max-width:60rem}}table{{border-collapse:collapse;width:100%}}\
td,th{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}}.score{{font-weight:700;text-align:center}}\
tr.good{{background:#e6f4ea}}tr.ok{{background:#fff8e1}}tr.low{{background:#fdecea}}tr.na{{color:#888}}\
.overall{{font-size:1.4rem;margin:1rem 0}}</style>\
<h1>Gantry conformance, scored from its own telemetry</h1>\
<p class=overall><b>Overall level: {overall}</b> (the minimum across scored primitives, not the average)</p>\
<table><tr><th>#</th><th>Primitive</th><th>Score</th><th>Evidence</th></tr>\n{rows}</table>\
<p>Rules {}, {} events scored. Overall is the minimum by rule: one weak layer caps the whole.</p>",
        snapshot.rules_version, snapshot.events_scored
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timestamp_normalises_so_a_since_window_compares_as_a_string() {
        assert_eq!(
            normalise_ts("2026-08-05T09:14:02Z").as_deref(),
            Some("2026-08-05T09:14:02.000")
        );
        assert_eq!(
            normalise_ts("2026-08-05T09:14:02.123Z").as_deref(),
            Some("2026-08-05T09:14:02.123")
        );
        assert_eq!(
            normalise_ts("2026-08-05").as_deref(),
            Some("2026-08-05T00:00:00.000")
        );
        // The seam this exists for: a fractional ts sorts after a whole-second
        // window bound rather than before it.
        assert!(
            normalise_ts("2026-08-05T09:14:02.123Z") > normalise_ts("2026-08-05T09:14:02Z"),
            "a fraction must not push an event before the second it falls in"
        );
        // A zone offset is refused, never assumed to be UTC.
        assert_eq!(normalise_ts("2026-08-05T09:14:02+02:00"), None);
        assert_eq!(normalise_ts("last tuesday"), None);
        assert_eq!(normalise_ts("2026-8-5"), None);
    }

    #[test]
    fn a_malformed_escape_is_refused_rather_than_decoded_to_something_else() {
        assert_eq!(percent_decode("ev-1%2F2").as_deref(), Some("ev-1/2"));
        assert_eq!(percent_decode("a+b").as_deref(), Some("a+b"));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("trailing%"), None);
    }
}
