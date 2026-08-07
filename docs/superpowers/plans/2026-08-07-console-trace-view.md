# Console trace view implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an eighth console view that draws the ledger as swimlanes on a clock, one lane per recorded actor, with an arrow only where a producer recorded a peer.

**Architecture:** Two producer changes land first, because the view depends on correlation the record does not carry today: `policy.decision` gains `request_id` and `call_hash`, and `/api/verify` starts returning the `seq_gaps` it already computes. Then a new front-end module `assets/trace.js` derives lanes, edges and markers from `/api/events` and renders inline SVG plus DOM marks. Nothing new is computed on the server for the graph itself: the view is a rendering of the existing events route.

**Tech Stack:** Rust (no new crates), vanilla ES modules in `assets/` with no build step, zsh for the render gate, headless Chrome via `--dump-dom`.

Spec: `docs/superpowers/specs/2026-08-07-console-trace-view-design.md`.

## Global Constraints

- No new dependency. Anything in `[dependencies]` needs an entry in `docs/DEPENDENCIES.md`, and this slice adds none.
- No `unwrap` or `expect` outside tests and `main`. Enforced by clippy in `ci/run.sh`.
- Every error carries a fix, not just a cause. A `Fault` with an empty fix does not ship.
- `assets/` is text only, no build step, no absolute URL, no font, no CDN. Grep for `http` in `assets/` must return only the SVG namespace and the existing inline data URI.
- DOM is built as nodes through `el()`, never as concatenated HTML. There is no `innerHTML` escape hatch, on purpose: every value comes from the ledger.
- The console API is read-only. This slice adds no POST, PUT, PATCH or DELETE, and no button that writes.
- The front end never renders a truncated read as a whole one, never renders `absent` or `unverified` attestation as a pass, and never renders a null score as zero.
- Voice for every comment, commit message and document: direct and technical, sentence case, no emoji, no exclamation marks, no long dashes of any kind.
- Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` before each commit. `ci/run.sh` is the full gate.
- One slice at a time. The slice is not done until `docs/proof/21.md` exists and was produced by running the thing.

---

## File structure

**Created**

- `assets/trace.js`: all derivation and rendering for the view. Exports `derive(events)` (pure, returns lanes, edges, marks, spans) and `trace(host, route)`. Kept out of `views.js` because that file is already 45 KB and this is a self-contained view with its own geometry.
- `docs/proof/21.md`: the proof document.

**Modified**

- `src/broker.rs:428`, inject `request_id` and `call_hash` into the `policy.decision` subject.
- `src/console.rs:396`, register `/trace.js` in `ASSETS`.
- `src/console.rs:875`, the inbox prefers the recorded correlation over the adjacency walk.
- `src/console.rs:1084`, `/api/verify` returns `seq_gaps`.
- `assets/ui.js:4`, add `svgEl`, the namespaced sibling of `el`.
- `assets/views.js:943`, export `trace` into the `views` map.
- `assets/index.html:21`, nav entry and the keyhints line.
- `assets/app.js:248`, the number-key range becomes 1 to 8.
- `assets/console.css`, trace styles.
- `docs/CONSOLE-API.md`, `seq_gaps` on `/api/verify`, and the two new `policy.decision` subject fields.
- `docs/EVENT-SCHEMA.md`, the two new subject fields.
- `tests/broker.rs`, `tests/console.rs`, `tests/invariants.rs`, new tests.
- `ci/console-render.sh`, the trace renders, and its assertions.

---

### Task 1: `policy.decision` carries the call it decided

**Files:**
- Modify: `src/broker.rs:420-430`
- Modify: `docs/EVENT-SCHEMA.md`
- Test: `tests/broker.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: every `policy.decision` subject gains two string fields, `request_id` and `call_hash`, matching the values on the `tool.request` that preceded it in the same `BrokerRun::call`. Tasks 2, 6 and 7 read them.

Context: `request_id` (`src/broker.rs:374`) and `call_hash` (`src/broker.rs:382`) are both in scope at the append site. `Decision` (`src/policy.rs:327`) stays unchanged: the policy computes a decision and has no business knowing a broker request id, so the two fields are injected into the serialised subject at the append site instead.

- [ ] **Step 1: Write the failing test**

Add to `tests/broker.rs`:

```rust
#[test]
fn a_decision_names_the_call_it_decided_rather_than_relying_on_adjacency() {
    let dir = workdir("decision-names-call");
    let led = dir.join("ledger-decision-names-call");
    {
        let mut run = BrokerRun::open(
            Ledger::init(&led).unwrap(),
            tracked_policy(),
            "broker-test",
            &pinning(&dir),
        )
        .unwrap();
        run.register_builtins().unwrap();
        // A held call, so the decision under test is one an approver answers.
        run.call("Bash", "git push origin main").unwrap_err();
        run.seal("complete").unwrap();
    }

    let evs = events(&led);
    let request = evs
        .iter()
        .find(|e| e["kind"] == "tool.request")
        .expect("the run recorded a tool.request");
    let decision = evs
        .iter()
        .find(|e| e["kind"] == "policy.decision")
        .expect("the run recorded a policy.decision");
    let req_subject = subject(&led, request);
    let dec_subject = subject(&led, decision);

    assert_eq!(
        dec_subject["request_id"], req_subject["request_id"],
        "the decision must name the request it decided, so a reader correlates without walking the log"
    );
    assert_eq!(
        dec_subject["call_hash"], req_subject["call_hash"],
        "the decision must name the call hash, which is what an approval binds to"
    );
    // The decision it computed is untouched by the addition.
    assert_eq!(dec_subject["verdict"], "hold");
    assert!(dec_subject["rule"].as_str().is_some());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test broker a_decision_names_the_call_it_decided -- --nocapture`
Expected: FAIL. `dec_subject["request_id"]` is `Null` while `req_subject["request_id"]` is a string, so the first assertion reports a mismatch.

- [ ] **Step 3: Write minimal implementation**

In `src/broker.rs`, replace the `decision_subject` construction at lines 423 to 430:

```rust
        let mut decision_subject = serde_json::to_value(&decision).map_err(|e| {
            Fault::new(
                format!("decision does not serialise: {e}"),
                "report this as a bug; Decision is serialisable by construction",
            )
        })?;
        // The decision names the call it decided. Without this a reader has to
        // pair each decision with the tool.request before it in the log, which
        // is a correlation the record does not carry and which does not
        // survive interleaved calls. An approval binds to the call hash, so
        // the hold and the grant that answers it are linkable from the record
        // alone.
        if let Some(obj) = decision_subject.as_object_mut() {
            obj.insert("request_id".to_string(), json!(request_id));
            obj.insert("call_hash".to_string(), json!(call_hash));
        }
        self.core.append("policy.decision", decision_subject)?;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test broker a_decision_names_the_call_it_decided`
Expected: PASS.

Then the whole broker suite, because several tests read decision subjects:
Run: `cargo test --test broker`
Expected: PASS. If a test asserted an exact subject object rather than individual fields, widen it to assert fields.

- [ ] **Step 5: Record the schema change**

In `docs/EVENT-SCHEMA.md`, under the `policy.decision` subject, add:

```markdown
- `request_id`: the broker request this decision answered, matching the
  `tool.request` of the same call.
- `call_hash`: the call's own identity, the value an `approval` binds to. A
  reader correlates a hold with the grant that released it from these two
  fields and never from position in the log.
```

- [ ] **Step 6: Run the schema compatibility check**

Run: `ci/run.sh`
Expected: PASS. Both fields are additive.

- [ ] **Step 7: Commit**

```bash
git add src/broker.rs tests/broker.rs docs/EVENT-SCHEMA.md
git commit -m "feat: a decision names the call it decided

policy.decision carried no request_id and no call_hash, so every reader
correlating a hold with its approval had to pair each decision with the
tool.request immediately before it in the log. That is a link the record does
not carry, and it does not survive two calls interleaving.

Injected at the append site rather than added to Decision, because the policy
computes a verdict and has no business holding a broker request id.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: the inbox reads the recorded correlation

**Files:**
- Modify: `src/console.rs:875-980`
- Test: `tests/console.rs`

**Interfaces:**
- Consumes: `request_id` and `call_hash` on the `policy.decision` subject, from Task 1.
- Produces: no shape change to `/api/approvals`. The route's output is identical; only how it correlates changes.

Context: `src/console.rs:890-910` keeps a `pending` tuple of the last `tool.request` and pairs it with the next `policy.decision`. Ledgers written before Task 1 carry no fields to read and must keep working: `docs/proof/08-run.sh` builds one, and the fixtures under `docs/proof/fixtures/` are older still. So the recorded fields are preferred and adjacency remains as the fallback.

- [ ] **Step 1: Write the failing test**

Add to `tests/console.rs`. It builds a ledger where adjacency gives the wrong answer, which is the case the old code cannot get right:

```rust
/// Two calls interleave: request A, request B, then the decision for A. An
/// adjacency walk pairs A's decision with B's request and reports a hold
/// against the wrong call. The recorded correlation gets it right.
#[test]
fn a_hold_is_correlated_by_the_recorded_call_and_not_by_position() {
    let dir = workdir("inbox-correlation").join("ledger");
    let mut ledger = Ledger::init(&dir).unwrap();
    for ev in [
        event(
            "run-3000",
            0,
            "2026-08-07T10:00:00.000Z",
            "run.open",
            json!({"workload": "interleaved", "restored_checkpoint": null}),
        ),
        event(
            "run-3000",
            1,
            "2026-08-07T10:00:01.000Z",
            "tool.request",
            json!({"request_id": "run-3000-req-1", "call_hash": "sha256:aaa", "tool": "Bash", "args": {"command": "git push origin main"}}),
        ),
        event(
            "run-3000",
            2,
            "2026-08-07T10:00:02.000Z",
            "tool.request",
            json!({"request_id": "run-3000-req-2", "call_hash": "sha256:bbb", "tool": "Bash", "args": {"command": "ls"}}),
        ),
        event(
            "run-3000",
            3,
            "2026-08-07T10:00:03.000Z",
            "policy.decision",
            json!({
                "verdict": "hold",
                "rule": "r-publish",
                "capability": "vcs.publish",
                "message": "this call needs an approval before it proceeds",
                "request_id": "run-3000-req-1",
                "call_hash": "sha256:aaa"
            }),
        ),
        event(
            "run-3000",
            4,
            "2026-08-07T10:00:04.000Z",
            "run.seal",
            json!({"outcome": "complete"}),
        ),
    ] {
        ledger.append(ev).unwrap();
    }

    let addr = serve(&dir);
    let body = get(addr, "/api/approvals").json();
    let holds = body["holds"].as_array().expect("holds is an array");
    assert_eq!(holds.len(), 1, "one call was held");
    assert_eq!(
        holds[0]["call_hash"], "sha256:aaa",
        "the hold names the call its own decision named, not the request that happened to precede it"
    );
    assert_eq!(holds[0]["request_id"], "run-3000-req-1");
    assert_eq!(holds[0]["state"], "waiting");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test console a_hold_is_correlated_by_the_recorded_call -- --nocapture`
Expected: FAIL with `holds[0]["call_hash"]` equal to `sha256:bbb`, because the adjacency walk took the most recent `tool.request`.

- [ ] **Step 3: Write minimal implementation**

In `src/console.rs`, inside the loop at line 893, replace the opening of the `policy.decision` arm:

```rust
            Some("policy.decision") => {
                // The decision names its own call since the slice that added
                // the fields. Older ledgers carry neither, so the adjacency
                // walk stays as a fallback rather than dropping their holds
                // off the inbox; it is only correct while calls do not
                // interleave, which is why the recorded pair wins.
                let recorded = match (
                    subject["request_id"].as_str(),
                    subject["call_hash"].as_str(),
                ) {
                    (Some(id), Some(hash)) => Some((id.to_string(), hash.to_string())),
                    _ => None,
                };
                let Some((request_id, call_hash)) = recorded.or_else(|| pending.take()) else {
                    continue;
                };
```

Leave the rest of the arm unchanged. `pending.take()` now runs only in the fallback, so a `tool.request` whose decision recorded its own correlation leaves `pending` set. That is harmless: the next decision needing the fallback is one from an older ledger where nothing records correlation at all.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test console`
Expected: PASS, including the existing `the_inbox_names_every_held_call_and_what_the_record_says_about_it`, whose fixture has no interleaving and must give the same answer either way.

- [ ] **Step 5: Commit**

```bash
git add src/console.rs tests/console.rs
git commit -m "fix: the inbox correlates a hold by what the decision recorded

The walk paired every decision with the tool.request immediately before it,
which is right only while calls do not interleave. Two requests before one
decision put the hold against the wrong call, with the wrong approve command
under it.

The adjacency walk stays as a fallback so ledgers written before the decision
carried its own correlation keep their holds on the inbox.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `/api/verify` returns the gaps it already found

**Files:**
- Modify: `src/console.rs:1084-1128`
- Modify: `docs/CONSOLE-API.md`
- Test: `tests/console.rs`

**Interfaces:**
- Consumes: `gantry::ledger::SeqGap` (`src/ledger.rs:61`), already on `VerifyReport::seq_gaps`.
- Produces: `/api/verify` gains `seq_gaps: [{run_id, after, before, missing}]`, ordered as the report produces them. Task 8 renders it. `ok` is unchanged and stays false only on faults.

Context: `SeqGap` derives `Debug, Clone, PartialEq, Eq` and not `Serialize`. The JSON is built by hand in the handler, which keeps the derive surface out of `ci/schema-compat`.

- [ ] **Step 1: Write the failing test**

Add to `tests/console.rs`:

```rust
/// A run that skips a seq number. The hole is reported and is not a fault:
/// the record cannot tell a killed harness from an event a producer numbered
/// and never appended, so ok stays true and the gap is a finding.
#[test]
fn verify_reports_a_seq_gap_and_the_ledger_still_reads_ok() {
    let dir = workdir("verify-seq-gap").join("ledger");
    let mut ledger = Ledger::init(&dir).unwrap();
    for ev in [
        event(
            "run-4000",
            0,
            "2026-08-07T11:00:00.000Z",
            "run.open",
            json!({"workload": "gapped", "restored_checkpoint": null}),
        ),
        // seq 1 and 2 are never appended.
        event(
            "run-4000",
            3,
            "2026-08-07T11:00:03.000Z",
            "run.seal",
            json!({"outcome": "complete"}),
        ),
    ] {
        ledger.append(ev).unwrap();
    }

    let addr = serve(&dir);
    let body = get(addr, "/api/verify").json();
    assert_eq!(body["ok"], true, "a hole in seq is a finding and never a fault");
    let gaps = body["seq_gaps"].as_array().expect("seq_gaps is an array");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0]["run_id"], "run-4000");
    assert_eq!(gaps[0]["after"], 0);
    assert_eq!(gaps[0]["before"], 3);
    assert_eq!(gaps[0]["missing"], 2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test console verify_reports_a_seq_gap -- --nocapture`
Expected: FAIL at `body["seq_gaps"].as_array()`, panicking with "seq_gaps is an array", because the key is absent.

- [ ] **Step 3: Write minimal implementation**

In `src/console.rs`, before the `Ok(json!({...}))` at line 1114:

```rust
    // The gaps the report already found. A hole in seq is a finding, not a
    // fault: a removed entry faults on the chain or on a signed head, so a
    // hole is an event that was never appended, and the log cannot tell a
    // harness killed mid-run from a producer that numbered an event it failed
    // to write. Until now nothing on the console could see one at all.
    let seq_gaps: Vec<Value> = report
        .seq_gaps
        .iter()
        .map(|g| {
            json!({
                "run_id": g.run_id,
                "after": g.after,
                "before": g.before,
                "missing": g.missing,
            })
        })
        .collect();
```

and add `"seq_gaps": seq_gaps,` to the returned object, after `"faults": faults,`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test console verify_reports_a_seq_gap`
Expected: PASS.

Run: `cargo test --test console`
Expected: PASS.

- [ ] **Step 5: Record the contract change**

In `docs/CONSOLE-API.md`, under `GET /api/verify`, add `seq_gaps` to the example body and this paragraph after it:

```markdown
`seq_gaps` is every hole in a run's `seq`, naming the run, the last seq before
the hole, the first after it, and how many are missing. It is a finding and
never a fault, so `ok` stays true with gaps present: a removed entry faults on
the chain or on a signed head, which means a hole is an event that was never
appended, and the record cannot tell a harness killed mid-run from a producer
that numbered an event it failed to write. The front end draws it as a hole in
the record and must not present it as tampering.
```

- [ ] **Step 6: Commit**

```bash
git add src/console.rs tests/console.rs docs/CONSOLE-API.md
git commit -m "feat: the verify route returns the seq gaps it already found

Ledger::seq_gaps has existed since the anchoring slice and gantry ledger
verify prints it. The API dropped it on the floor, so no console has ever been
able to show a hole in the record.

Reported as a finding with ok still true, matching the CLI and proof 18.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: lanes, and the view exists

The nav grows from seven entries to eight, which is why the number-key range
and the keyhints line both move in this task.

**Files:**
- Create: `assets/trace.js`
- Modify: `assets/ui.js`, `assets/views.js:943`, `assets/index.html`, `assets/app.js:248`, `assets/console.css`, `assets/WIRING.md`
- Modify: `src/console.rs:396`
- Test: `ci/console-render.sh`

**Interfaces:**
- Consumes: `/api/events` via `api.events(params)` from `assets/api.js`.
- Produces: `assets/trace.js` exports `derive(events)` returning `{lanes: [{id, marks}], marks, edges, spans, t0, span}` where a mark is `{ev, lane, at, offsetMs, deltaMs, peer}`, and `trace(host, route)` as the view function. Tasks 5 to 9 extend both.

- [ ] **Step 1: Add the SVG element helper**

In `assets/ui.js`, directly after `el`:

```javascript
// The namespaced sibling of el. document.createElement builds an
// HTMLUnknownElement for a tag like <line>, which lays out as nothing at all,
// so the trace view needs this and the rest of the console does not.
export function svgEl(tag, props, ...children) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}
```

- [ ] **Step 2: Write the derivation and the view**

Create `assets/trace.js`:

```javascript
// The trace view: the ledger as swimlanes on a clock.
//
// A lane is an actor that wrote an event. Nothing else is a lane, and no lane
// is invented. An arrow needs two ends and an event records one, so this file
// holds no table mapping an event kind to a source and a destination: an edge
// is drawn only where a producer recorded a peer, and everything else is a
// marker on a single lane. The picture starts sparse, and that sparseness is
// the finding. It names the handoffs this system does not observe.

import { api } from '/api.js';
import { el, clear, mono, panel, loading, actorId, attMark, attRowClass,
         subjectSummary, num, tsShort } from '/ui.js';

export const EVENT_PAGE_MAX = 1000;

// The one place a peer is read. Each entry names the subject field the
// producer actually writes, so a new lane means a producer recorded
// something, never that this list grew an opinion.
const PEER_FIELD = {
  'model.call': (s) => (s.provider ? `provider:${s.provider}` : null),
  'tool.request': (s) => (s.tool ? `tool:${s.tool}` : null),
  'subagent.spawn': (s) => (s.child_id ? `agent:${s.child_id}` : null),
};

function peerOf(ev) {
  const f = PEER_FIELD[ev.kind];
  if (!f) return null;
  return f(ev._subject || {});
}

export function derive(events) {
  const lanes = new Map();
  const laneFor = (id) => {
    if (!lanes.has(id)) lanes.set(id, { id, marks: [] });
    return lanes.get(id);
  };

  const t0 = events.length ? new Date(events[0].ts).getTime() : 0;
  const tEnd = events.length ? new Date(events[events.length - 1].ts).getTime() : 0;
  const span = Math.max(tEnd - t0, 1);

  const marks = [];
  let prevAt = t0;
  for (const ev of events) {
    const laneId = actorId(ev.actor);
    const at = new Date(ev.ts).getTime();
    const mark = {
      ev,
      lane: laneId,
      at: Number.isNaN(at) ? t0 : at,
      offsetMs: Number.isNaN(at) ? 0 : at - t0,
      deltaMs: Number.isNaN(at) ? 0 : at - prevAt,
      peer: peerOf(ev),
    };
    if (!Number.isNaN(at)) prevAt = at;
    laneFor(laneId).marks.push(mark);
    if (mark.peer) laneFor(mark.peer);
    marks.push(mark);
  }

  return { lanes: [...lanes.values()], marks, edges: [], spans: [], t0, span };
}

export async function trace(host, route) {
  const body = el('div', { class: 'view' }, loading('trace'));
  clear(host).append(body);

  const run = route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  const res = await api.events(run ? { run, limit: EVENT_PAGE_MAX } : { limit: EVENT_PAGE_MAX });
  const events = res.events || [];
  const model = derive(events);

  clear(body).append(
    panel('Trace', {
      sub: `${num(model.lanes.length)} lanes, ${num(events.length)} of ${num(res.total)} events drawn`,
    }, laneBoard(model)),
  );
}

function laneBoard(model) {
  return el('div', { class: 'lanes' }, model.lanes.map((lane) =>
    el('div', { class: 'lane', 'data-lane': lane.id },
      el('div', { class: 'lane-head' }, mono(lane.id),
        el('span', { class: 'faint' }, `${num(lane.marks.length)} events`)),
      el('div', { class: 'lane-track' }, lane.marks.map((m) => markNode(m, model))))));
}

function markNode(m, model) {
  const pct = (m.offsetMs / model.span) * 100;
  return el('button', {
    class: `mark ${attRowClass(m.ev)}`,
    'data-kind': m.ev.kind,
    'data-event': m.ev.id,
    style: `left:${Math.min(99.5, Math.max(0, pct))}%`,
    title: `${m.ev.kind} at ${tsShort(m.ev.ts)}`,
  }, attMark(m.ev), mono(m.ev.kind), subjectSummary(m.ev));
}
```

- [ ] **Step 3: Wire it into the console**

In `assets/views.js`, add the import at the top with the others and extend the export at line 943:

```javascript
import { trace } from '/trace.js';

export const views = { overview, ledger, run, trace, policy, trust, inbox, verify };
```

In `assets/index.html`, add the nav entry after Run and renumber the rest:

```html
    <a href="#/trace" data-view="trace">Trace<kbd>4</kbd></a>
    <a href="#/policy" data-view="policy">Policy<kbd>5</kbd></a>
    <a href="#/trust" data-view="trust">Trust<kbd>6</kbd></a>
    <a href="#/inbox" data-view="inbox">Inbox<kbd>7</kbd></a>
    <a href="#/verify" data-view="verify">Verify<kbd>8</kbd></a>
```

and change the keyhints line `<kbd>1</kbd> to <kbd>7</kbd> views` to `<kbd>1</kbd> to <kbd>8</kbd> views`.

In `assets/app.js:248`, change `if (n >= 1 && n <= 7)` to `if (n >= 1 && n <= 8)`.

In `src/console.rs:396`, add to `ASSETS` after the `/views.js` entry:

```rust
    ("/trace.js", include_str!("../assets/trace.js"), JS),
```

In `assets/WIRING.md`, add `/trace.js` to the asset table and to the module list, so the document keeps matching the code.

- [ ] **Step 4: Add the styles**

Append to `assets/console.css`:

```css
/* Trace. One row per lane, marks positioned along a shared clock. */
.lanes { display: flex; flex-direction: column; gap: 2px; }
.lane { display: grid; grid-template-columns: 22ch 1fr; align-items: center; }
.lane-head { display: flex; justify-content: space-between; gap: 8px; padding-right: 10px; }
.lane-track { position: relative; height: 34px; border-top: 1px solid var(--rule); }
.lane-track .mark {
  position: absolute; top: 4px; transform: translateX(-50%);
  display: inline-flex; align-items: center; gap: 4px;
  max-width: 30ch; overflow: hidden; white-space: nowrap;
  font: inherit; background: var(--panel); border: 1px solid var(--rule);
  border-radius: 3px; padding: 1px 5px; cursor: pointer;
}
.lane-track .mark[data-kind="policy.decision"] { border-color: var(--warn); }
```

Use the variable names already defined at the top of `console.css`. If `--rule`, `--panel` or `--warn` are named differently there, use the existing names rather than adding new variables.

- [ ] **Step 5: Build and render by hand**

Run:
```bash
cargo build
target/debug/gantry console <a ledger directory> --port 8899 &
open http://127.0.0.1:8899/#/trace
```
Expected: one row per actor on the ledger, marks spread along each row, and the panel subtitle naming the lane count and the drawn-of-total events.

- [ ] **Step 6: Add the trace to the render gate**

In `ci/console-render.sh`, add `trace` to the `VIEWS` array, then after the existing per-view assertions:

```zsh
# The lane labels are actors read out of the fixture ledger at check time, so
# this cannot drift into asserting a constant.
for actor in ${(f)"$(grep -ho '"id":"[^"]*"' $L/events.jsonl | sed 's/.*"id":"//;s/"//' | sort -u)"}; do
  expect trace "$actor" "a lane is an actor that wrote an event on the fixture ledger"
done
refute trace "undefined" "a lane or mark built from a field the API no longer returns"
```

- [ ] **Step 7: Run the gate**

Run: `cargo build && ci/console-render.sh`
Expected: PASS, with the trace view among the rendered ones.

- [ ] **Step 8: Prove the assertion can fail**

Temporarily change `actorId(ev.actor)` in `assets/trace.js` to `actorId(ev.actorr)`, rebuild, run `ci/console-render.sh`.
Expected: FAIL naming a missing lane label. Revert, rebuild, confirm PASS.

- [ ] **Step 9: Commit**

```bash
git add assets/ src/console.rs ci/console-render.sh
git commit -m "feat: a trace view whose lanes are actors that wrote events

One lane per actor on the record, marks along a shared clock. No lane is
invented and a lane with no events is not drawn, so the layout is a property
of the capture rather than a house style.

No edges yet. The file holds no kind-to-topology table and will not grow one:
an arrow asserts a handoff and an event records one end of it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: edges, and the count that says what was refused

**Files:**
- Modify: `assets/trace.js`, `assets/console.css`
- Test: `tests/invariants.rs`, `ci/console-render.sh`

**Interfaces:**
- Consumes: `derive(events)` from Task 4.
- Produces: `derive` returns `edges: [{from, to, at, offsetMs, ev, durationMs, back}]`, and the rendered page carries the string `edges observed` with a count, plus `inferred: 0`.

- [ ] **Step 1: Write the failing structural test**

Add to `tests/invariants.rs`:

```rust
/// An arrow asserts a handoff, and an event records one end of it. A table
/// mapping an event kind to a source and a destination lane would make every
/// event an arrow and the diagram would be complete and partly untrue, which
/// is the defect this project exists to prevent, one layer down from a scorer
/// that reads configuration. Every peer in trace.js is read out of a subject
/// field, so this asserts the shape that keeps it that way.
#[test]
fn the_trace_view_derives_no_edge_from_an_event_kind_alone() {
    let src = std::fs::read_to_string("assets/trace.js").unwrap();
    let peers = src
        .split_once("const PEER_FIELD = {")
        .expect("trace.js declares PEER_FIELD, the one place a peer is read")
        .1
        .split_once("};")
        .expect("PEER_FIELD is a closed object literal")
        .0;
    for line in peers.lines().filter(|l| l.contains("=>")) {
        assert!(
            line.contains("s."),
            "every PEER_FIELD entry reads a subject field, and this one does not: {line}"
        );
    }
    // The rendered edge count states both halves, so a reader knows what the
    // picture refused to draw and not only what it drew.
    assert!(
        src.contains("inferred: 0"),
        "the legend prints the inferred count, which is zero by construction and printed anyway"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test invariants the_trace_view_derives_no_edge -- --nocapture`
Expected: FAIL on the `inferred: 0` assertion, because the legend does not exist yet.

- [ ] **Step 3: Write the edge derivation**

In `assets/trace.js`, inside `derive`, after the mark loop and before the return:

```javascript
  // An edge exists where a producer recorded a peer, and nowhere else. The
  // return leg of a tool call is a second edge, drawn only because
  // tool.result carries the request_id of the request it answers.
  const edges = [];
  const openByRequest = new Map();
  for (const m of marks) {
    const s = m.ev._subject || {};
    if (m.peer) {
      edges.push({
        from: m.lane, to: m.peer, at: m.at, offsetMs: m.offsetMs, ev: m.ev,
        durationMs: typeof s.latency_ms === 'number' ? s.latency_ms : null,
        back: false,
      });
      if (s.request_id) openByRequest.set(s.request_id, m);
    }
    if (m.ev.kind === 'tool.result' && s.request_id && openByRequest.has(s.request_id)) {
      const req = openByRequest.get(s.request_id);
      edges.push({
        from: req.peer, to: m.lane, at: m.at, offsetMs: m.offsetMs, ev: m.ev,
        durationMs: typeof s.duration_ms === 'number' ? s.duration_ms : null,
        back: true,
      });
    }
  }
```

Return `edges` in place of the empty array.

- [ ] **Step 4: Draw them and print the legend**

Add `svgEl` to the `/ui.js` import, then:

```javascript
// Edges are drawn in one SVG layer behind the marks, because a line between
// two rows is not a child of either.
function edgeLayer(model, laneIndex) {
  const rowH = 34;
  const height = Math.max(model.lanes.length * rowH, rowH);
  return svgEl('svg', {
    class: 'edges', viewBox: `0 0 1000 ${height}`,
    preserveAspectRatio: 'none', 'aria-hidden': 'true',
  }, model.edges.map((e) => {
    const from = laneIndex.get(e.from);
    const to = laneIndex.get(e.to);
    if (from === undefined || to === undefined) return null;
    const x = Math.min(998, Math.max(2, (e.offsetMs / model.span) * 1000));
    return svgEl('line', {
      x1: x, y1: from * rowH + rowH / 2,
      x2: x, y2: to * rowH + rowH / 2,
      class: e.back ? 'edge edge-back' : 'edge',
    });
  }));
}

function legend(model) {
  return el('div', { class: 'trace-legend' },
    el('span', {}, `${num(model.edges.length)} edges observed`),
    // Printed even though it is zero by construction. A diagram people trust
    // has to say what it refused to draw.
    el('span', { class: 'faint' }, 'inferred: 0'),
    el('span', { class: 'faint' },
      'an arrow is drawn only where a producer recorded a peer; every other event is a marker on one lane'));
}
```

In `trace`, build `const laneIndex = new Map(model.lanes.map((l, i) => [l.id, i]));` and pass both into the panel:

```javascript
    panel('Trace', {
      sub: `${num(model.lanes.length)} lanes, ${num(events.length)} of ${num(res.total)} events drawn`,
    }, legend(model), el('div', { class: 'lane-stack' }, edgeLayer(model, laneIndex), laneBoard(model))),
```

Append to `assets/console.css`:

```css
.lane-stack { position: relative; }
.lane-stack .edges { position: absolute; inset: 0 0 0 22ch; width: calc(100% - 22ch); height: 100%; pointer-events: none; }
.edge { stroke: var(--accent); stroke-width: 1.5; }
.edge-back { stroke-dasharray: 3 2; }
.trace-legend { display: flex; gap: 14px; align-items: baseline; padding: 6px 0; }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --test invariants the_trace_view_derives_no_edge`
Expected: PASS.

- [ ] **Step 6: Assert it in the render gate**

In `ci/console-render.sh`, after the Task 4 trace assertions:

```zsh
expect trace "edges observed" "the legend states how many edges the record carried"
expect trace "inferred: 0" "the legend states what the picture refused to draw"
# The fixture runs a Bash call, so a tool lane exists and an edge reaches it.
expect trace "tool:Bash" "a peer lane created from the tool a tool.request recorded"
```

- [ ] **Step 7: Prove it can fail**

Change `s.tool` to `s.toool` inside `PEER_FIELD`, rebuild, run `ci/console-render.sh`.
Expected: FAIL naming the missing `tool:Bash`. Revert, rebuild, confirm PASS.

- [ ] **Step 8: Commit**

```bash
git add assets/ tests/invariants.rs ci/console-render.sh
git commit -m "feat: edges where a producer recorded a peer, and nowhere else

PEER_FIELD is the one place a peer is read and every entry reads a subject
field, which an invariant test asserts structurally. The legend prints the
inferred count as well as the observed one, because a diagram people trust has
to say what it refused to draw.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: the filter bar, and the two numbers it reports

**Files:**
- Modify: `assets/trace.js`, `assets/console.css`
- Test: `ci/console-render.sh`

**Interfaces:**
- Consumes: `derive` from Tasks 4 and 5, and `api.events` params.
- Produces: `parseFilter(text)` returning `{server, client, words}`, and `matches(ev, filter)` returning a boolean. The expression round-trips through `location.hash` as `#/trace?f=<expression>`.

- [ ] **Step 1: Write the parser and the predicate**

Add to `assets/trace.js`:

```javascript
// Terms the API can answer. Everything else runs here, over the page the API
// returned, which is why the bar reports both numbers.
const SERVER_FIELDS = new Set(['kind', 'run', 'actor', 'since']);
const CLIENT_FIELDS = new Set(['lane', 'verdict', 'rule', 'capability', 'tool', 'provider', 'att', 'call', 'request']);

export function parseFilter(text) {
  const server = {};
  const client = [];
  const words = [];
  for (const raw of String(text || '').trim().split(/\s+/).filter(Boolean)) {
    const negate = raw.startsWith('!');
    const token = negate ? raw.slice(1) : raw;
    const i = token.indexOf(':');
    const field = i > 0 ? token.slice(0, i) : null;
    const value = i > 0 ? token.slice(i + 1) : token;
    if (field && SERVER_FIELDS.has(field) && !negate) server[field] = value;
    else if (field && (SERVER_FIELDS.has(field) || CLIENT_FIELDS.has(field))) client.push({ field, value, negate });
    else words.push(value.toLowerCase());
  }
  return { server, client, words };
}

const FIELD_OF = {
  lane: (ev) => actorId(ev.actor),
  actor: (ev) => actorId(ev.actor),
  kind: (ev) => ev.kind,
  run: (ev) => ev.run_id,
  att: (ev) => ev._attestation_state,
  verdict: (ev) => (ev._subject || {}).verdict,
  rule: (ev) => (ev._subject || {}).rule,
  capability: (ev) => (ev._subject || {}).capability,
  tool: (ev) => (ev._subject || {}).tool,
  provider: (ev) => (ev._subject || {}).provider,
  call: (ev) => (ev._subject || {}).call_hash,
  request: (ev) => (ev._subject || {}).request_id,
};

export function matches(ev, filter) {
  for (const t of filter.client) {
    const read = FIELD_OF[t.field];
    const got = String(read ? read(ev) ?? '' : '');
    const hit = got === t.value || got.includes(t.value);
    if (hit === t.negate) return false;
  }
  if (filter.words.length) {
    const hay = JSON.stringify(ev).toLowerCase();
    if (!filter.words.every((w) => hay.includes(w))) return false;
  }
  return true;
}
```

- [ ] **Step 2: Wire it into the view**

In `trace`, replace the fetch and derive with:

```javascript
  const expr = route.query.f ? decodeURIComponent(route.query.f) : (run ? `run:${run}` : '');
  const filter = parseFilter(expr);
  if (run) filter.server.run = run;
  const res = await api.events({ ...filter.server, limit: EVENT_PAGE_MAX });
  const page = res.events || [];
  const events = page.filter((ev) => matches(ev, filter));
  const model = derive(events);
```

and render the bar above the legend:

```javascript
function filterBar(expr, shown, page, total, filter) {
  const clientRan = filter.client.length > 0 || filter.words.length > 0;
  const truncated = Number(total) > page;
  const input = el('input', {
    class: 'filter-input mono', type: 'text', value: expr, 'data-filter': '',
    placeholder: 'kind:policy.decision verdict:deny capability:vcs.publish',
    'aria-label': 'trace filter',
    onchange: (e) => { location.hash = `#/trace?f=${encodeURIComponent(e.target.value)}`; },
  });
  return el('div', { class: 'filters' }, input,
    el('span', { class: 'mono' }, `${num(shown)} of ${num(page)} drawn`),
    el('span', { class: 'faint' }, `${num(total)} match the server-side part of this filter`),
    // A client-side filter over a page is a filter over a page. Reporting
    // three results while the log holds more would be a complete-looking
    // rendering of an incomplete read, which is the failure this console
    // refuses everywhere else.
    clientRan && truncated
      ? el('span', { class: 'warn-text' },
        `${filter.client.map((t) => t.field).concat(filter.words.length ? ['text'] : []).join(', ')} ran in the browser over the first ${num(page)} matching events, not over the log. `,
        el('a', { href: `#/trace?f=${encodeURIComponent(narrower(filter))}` }, 'narrow the server-side read'))
      : null);
}

// The same expression with only the terms the API can answer, which is the
// read that makes the count whole.
function narrower(filter) {
  return Object.entries(filter.server).map(([k, v]) => `${k}:${v}`).join(' ');
}
```

- [ ] **Step 3: Add the style**

```css
.filter-input { flex: 1 1 40ch; min-width: 24ch; padding: 4px 8px; }
```

- [ ] **Step 4: Render by hand and check the round trip**

Serve a ledger with a denial, open `#/trace?f=verdict%3Adeny`, confirm only denials draw and the input shows `verdict:deny`. Edit it to `kind:model.call`, press enter, confirm the hash and the picture both change.

- [ ] **Step 5: Assert it in the render gate**

Next to the existing `ROUTE[...]` entries in `ci/console-render.sh`:

```zsh
ROUTE[tracefiltered]="trace?f=verdict%3Adeny"; ORIGIN_OF[tracefiltered]=$ORIGIN
```

add `tracefiltered` to the render list, and after collection:

```zsh
expect tracefiltered "drawn" "the filter bar states how many of the page it drew"
expect tracefiltered "match the server-side part of this filter" "the bar states what the server matched, so a browser-side count is never read as the log"
expect tracefiltered "$DENY_RULE" "the filtered trace drew the denial the fixture recorded"
refute tracefiltered "model.call" "an event the filter excluded, so the filter did not run"
```

`DENY_RULE` is read from the fixture ledger at the top of the script alongside the other extracted values, with the same grep and sed pattern the existing extraction uses.

- [ ] **Step 6: Run the gate and prove it can fail**

Run: `cargo build && ci/console-render.sh`
Expected: PASS.

Then make `matches` return `true` unconditionally, rebuild, re-run.
Expected: FAIL on the refute for `model.call`. Revert, rebuild, confirm PASS.

- [ ] **Step 7: Commit**

```bash
git add assets/ ci/console-render.sh
git commit -m "feat: a trace filter that says which half of it ran on the server

Terms the events route answers are pushed down; the rest run in the browser
over at most a page. The bar prints both numbers and, when a browser-side term
ran over a truncated page, names the terms and links to the read that makes the
count whole. A filter reporting three results over a page implies the log holds
three.

The expression round-trips through the hash, so a trace is a link.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: detail pane, deltas and the held span

**Files:**
- Modify: `assets/trace.js`, `assets/views.js:61`, `assets/console.css`
- Test: `ci/console-render.sh`

**Interfaces:**
- Consumes: `eventDetail` from `assets/views.js`, `derive` from Tasks 4 to 6.
- Produces: `derive` returns `spans: [{from, to, ms, callHash, rule}]` for hold-to-approval pairs. Route `#/trace/event/<event id>` opens the pane without an interaction, which is what makes it reachable under `--dump-dom`.

- [ ] **Step 1: Export the detail builder**

In `assets/views.js:61`, change `function eventDetail(box, ev)` to `export function eventDetail(box, ev)`. Nothing else changes; the existing callers are in the same module.

- [ ] **Step 2: Derive the held spans**

In `assets/trace.js`, inside `derive`, after the edge loop:

```javascript
  // A hold and the approval that answered it, linked by the call hash both
  // record. Before the decision carried its own call hash this pair was only
  // reachable by position, which is why it is drawn now and was not before.
  const spans = [];
  const heldAt = new Map();
  for (const m of marks) {
    const s = m.ev._subject || {};
    if (m.ev.kind === 'policy.decision' && s.verdict === 'hold' && s.call_hash) {
      heldAt.set(s.call_hash, m);
    }
    if (m.ev.kind === 'approval' && s.call_hash && heldAt.has(s.call_hash)) {
      const held = heldAt.get(s.call_hash);
      spans.push({ from: held, to: m, ms: m.at - held.at, callHash: s.call_hash, rule: s.rule });
      heldAt.delete(s.call_hash);
    }
  }
```

Return `spans` in place of the empty array.

- [ ] **Step 3: Draw the span and the deltas**

In `markNode`, extend the title:

```javascript
    title: `${m.ev.kind} at ${tsShort(m.ev.ts)}, +${(m.offsetMs / 1000).toFixed(3)}s from first, +${(m.deltaMs / 1000).toFixed(3)}s from previous`,
```

and add:

```javascript
function spanList(model) {
  if (!model.spans.length) return null;
  return el('div', { class: 'trace-spans' }, model.spans.map((s) =>
    el('div', { class: 'trace-span' },
      el('b', {}, `held ${(s.ms / 1000).toFixed(1)}s`),
      mono(s.rule || 'no rule on the approval'),
      el('span', { class: 'faint mono' }, s.callHash))));
}
```

Render `spanList(model)` under the legend.

- [ ] **Step 4: Add the pane and its route**

```javascript
function detailPane(model, focusId) {
  const m = model.marks.find((x) => x.ev.id === focusId);
  if (!m) return null;
  const box = el('div', { class: 'trace-detail' });
  eventDetail(box, m.ev);
  return el('aside', { class: 'trace-aside' },
    el('div', { class: 'trace-aside-head' }, mono(m.ev.id), el('a', { href: '#/trace' }, 'close')),
    box);
}
```

Import `eventDetail` from `/views.js`. In `trace`, read the focus from the route and branch on the literal `event`:

```javascript
  // #/trace/<run id> and #/trace/event/<event id> share segment 1. The
  // literal "event" is the discriminator; anything else is a run id.
  const isEvent = route.segments[1] === 'event';
  const run = !isEvent && route.segments[1] ? decodeURIComponent(route.segments[1]) : null;
  const focusId = isEvent && route.segments[2] ? decodeURIComponent(route.segments[2]) : null;
```

and give each mark a click that routes rather than a handler that mutates:

```javascript
    onclick: () => { location.hash = `#/trace/event/${encodeURIComponent(m.ev.id)}`; },
```

- [ ] **Step 5: Style**

```css
.trace-aside { position: sticky; top: 0; border-left: 1px solid var(--rule); padding-left: 12px; }
.trace-spans { display: flex; flex-direction: column; gap: 3px; padding: 4px 0; }
.trace-span { display: flex; gap: 10px; align-items: baseline; }
```

- [ ] **Step 6: Assert in the render gate**

The fixture already builds a hold and an approval. Add:

```zsh
ROUTE[tracedetail]="trace/event/$EVENT"; ORIGIN_OF[tracedetail]=$ORIGIN
```

with `EVENT` read from the fixture ledger the way the existing ledger-row deep link already reads it, and:

```zsh
expect tracedetail "$EVENT" "the pane opened by its own route, without a click"
expect trace "held " "a hold and the approval that answered it, linked by the call hash both record"
```

- [ ] **Step 7: Run the gate and prove it can fail**

Run: `cargo build && ci/console-render.sh`
Expected: PASS.

Then change `s.call_hash` to `s.call_hashh` in the span derivation, rebuild, re-run.
Expected: FAIL on the `held ` assertion. Revert, rebuild, confirm PASS.

- [ ] **Step 8: Commit**

```bash
git add assets/ ci/console-render.sh
git commit -m "feat: a detail pane, per-mark deltas and a real held span

The span between a hold and the approval that answered it is drawn from the
call hash both events record, which is a link that did not exist on the record
until this slice put it there.

The pane opens from its own route, so the render gate reaches it without a
browser driver.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: holes in a lane

**Files:**
- Modify: `assets/trace.js`, `assets/console.css`
- Test: `ci/console-render.sh`

**Interfaces:**
- Consumes: `seq_gaps` from `/api/verify` (Task 3), reachable through `state.verify` in `assets/api.js`, which `app.js` populates before any view mounts.
- Produces: a gap row per gap whose run appears in the drawn events.

- [ ] **Step 1: Read the gaps and place them**

Import `state` from `/api.js`. In `trace`, after `derive`:

```javascript
  // The verify route is read once before any view mounts, so this is the last
  // report and not a second read. A gap belongs to a run, so only gaps whose
  // run is on screen are drawn.
  const gaps = ((state.verify && state.verify.seq_gaps) || []).filter(
    (g) => model.marks.some((m) => m.ev.run_id === g.run_id),
  );
```

and render:

```javascript
function gapList(gaps) {
  if (!gaps.length) return null;
  return el('div', { class: 'trace-gaps' }, gaps.map((g) =>
    el('div', { class: 'trace-gap' },
      el('b', {}, `${num(g.missing)} events missing`),
      el('span', {}, ` between seq ${num(g.after)} and ${num(g.before)} on `),
      mono(g.run_id),
      // A finding, never a fault. The record cannot tell a harness killed
      // mid-run from a producer that numbered an event it failed to write.
      el('span', { class: 'faint' },
        'a hole in the record, not an alteration; an altered entry faults on the chain instead'))));
}
```

- [ ] **Step 2: Style it as a hole and not as a fault**

```css
.trace-gaps { display: flex; flex-direction: column; gap: 3px; padding: 4px 0; }
.trace-gap { border-left: 3px dashed var(--rule); padding-left: 8px; }
```

Deliberately not the deny or fault colour. A gap in the same red as a chain fault would assert a distinction the record cannot make.

- [ ] **Step 3: Add a gapped run to the render fixture**

In `ci/console-render.sh`, after the fixture ledger is built, append one event whose `seq` skips, using the same binary invocation the fixture already uses to write events. Read the gap numbers back out of the ledger for the assertion rather than hardcoding them, matching how the other extracted values work.

- [ ] **Step 4: Assert it**

```zsh
expect trace "events missing" "a hole in the record, read off the verify route"
expect trace "not an alteration" "a gap is a finding and the page says so"
refute trace "tampered" "a gap rendered as tampering, which is a distinction the record cannot make"
```

- [ ] **Step 5: Run the gate and prove it can fail**

Run: `cargo build && ci/console-render.sh`
Expected: PASS.

Then rename `seq_gaps` to `seqGaps` in the Task 3 handler, rebuild, re-run.
Expected: FAIL on `events missing`. Revert, rebuild, confirm PASS.

- [ ] **Step 6: Commit**

```bash
git add assets/ ci/console-render.sh
git commit -m "feat: a hole in the record is drawn as a hole

seq gaps reached the API in this slice and now reach the page. Styled apart
from a fault on purpose: a removed entry faults on the chain, so a gap is an
event that was never appended, and the log cannot tell a killed harness from a
producer that numbered an event it failed to write.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: lane statistics

**Files:**
- Modify: `assets/trace.js`
- Test: `ci/console-render.sh`

**Interfaces:**
- Consumes: `derive` output from Tasks 4 to 8.
- Produces: `laneStats(model)` returning a table, one row per lane, sorted by denials.

- [ ] **Step 1: Build the table**

Add `table` and `td` to the `/ui.js` import, then:

```javascript
function laneStats(model) {
  const rows = model.lanes.map((lane) => {
    const marks = lane.marks;
    const denials = marks.filter((m) => (m.ev._subject || {}).verdict === 'deny').length;
    const holds = marks.filter((m) => (m.ev._subject || {}).verdict === 'hold').length;
    const heldMs = model.spans
      .filter((s) => s.from.lane === lane.id)
      .reduce((a, s) => a + s.ms, 0);
    const unattested = marks.filter((m) => m.ev._attestation_state !== 'verified').length;
    return { lane, marks, denials, holds, heldMs, unattested };
  }).sort((a, b) => b.denials - a.denials || b.marks.length - a.marks.length);

  // A peer lane holds no marks of its own, because nothing on the record was
  // written by it. Its row reads "no events of its own" rather than a zero
  // that would read as a lane that ran and did nothing.
  return table(
    [
      { label: 'lane', width: '24ch' }, { label: 'events', num: true, width: '8ch' },
      { label: 'denials', num: true, width: '9ch' }, { label: 'holds', num: true, width: '8ch' },
      { label: 'held', num: true, width: '9ch' }, { label: 'unattested', num: true, width: '11ch' },
      { label: 'first', num: true, width: '10ch' }, { label: 'last', num: true, width: '10ch' },
    ],
    rows.map((r) => el('tr', {},
      td(mono(r.lane.id), 'nowrap'),
      td(r.marks.length ? mono(num(r.marks.length)) : el('span', { class: 'faint' }, 'no events of its own'), 'num'),
      td(r.denials ? el('span', { class: 'tag tag-deny' }, num(r.denials)) : el('span', { class: 'faint mono' }, '0'), 'num'),
      td(r.holds ? el('span', { class: 'tag tag-warn' }, num(r.holds)) : el('span', { class: 'faint mono' }, '0'), 'num'),
      td(mono(r.heldMs ? `${(r.heldMs / 1000).toFixed(1)}s` : '0s'), 'num'),
      td(r.unattested ? el('span', { class: 'warn-text mono' }, num(r.unattested)) : el('span', { class: 'faint mono' }, '0'), 'num'),
      td(r.marks.length ? mono(`+${(r.marks[0].offsetMs / 1000).toFixed(2)}s`) : el('span', { class: 'faint' }, 'none'), 'num'),
      td(r.marks.length ? mono(`+${(r.marks[r.marks.length - 1].offsetMs / 1000).toFixed(2)}s`) : el('span', { class: 'faint' }, 'none'), 'num'),
    )),
    { empty: 'no events on this filter, so no lane has statistics' },
  );
}
```

Render it in a second panel: `panel('Lanes', { sub: 'sorted by denials, because that is the lane worth opening', flush: true }, laneStats(model))`.

- [ ] **Step 2: Render by hand**

Confirm the lane holding the fixture's denial sorts first and its held total matches the span drawn above it.

- [ ] **Step 3: Assert it**

```zsh
expect trace "sorted by denials" "the lane statistics strip"
expect trace "unattested" "the per-lane attestation count, which must not render as a pass"
```

- [ ] **Step 4: Run the gate**

Run: `cargo build && ci/console-render.sh`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add assets/ ci/console-render.sh
git commit -m "feat: per-lane statistics, sorted by denials

Events, denials, holds, total held time, unattested count and the first and
last offset per lane. Sorted by denials because that is the lane a reader
opens next.

A peer lane reads as having no events of its own rather than zero, because a
zero there would describe a lane that ran and did nothing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: the proof document

**Files:**
- Create: `docs/proof/21.md`
- Modify: `CLAUDE.md`, and `README.md` if the self-score moves

**Interfaces:**
- Consumes: everything above.
- Produces: the document that closes the slice.

- [ ] **Step 1: Run the full gate**

Run: `ci/run.sh`
Expected: PASS at every step, with the trace renders inside `ci/console-render.sh`.

- [ ] **Step 2: Run the adversarial case and record it**

For each assertion added in Tasks 4 to 9, rename the field it reads, rebuild, run `ci/console-render.sh`, and record the exact failure text. This is the evidence the check can fail, and it is the section a proof document exists for. Revert each rename before the next.

Fields to break, one at a time: `actor` in the lane derivation, `s.tool` in `PEER_FIELD`, `matches` returning true unconditionally, `s.call_hash` in the span derivation, `seq_gaps` in `src/console.rs`, and `_attestation_state` in the lane statistics.

- [ ] **Step 3: Write `docs/proof/21.md`**

Sections, matching `docs/proof/20.md`: what was built, the adversarial case with the recorded failure text for each rename, the evidence (commands run and their output), the conformance delta against `docs/PRIMITIVES.md`, and what is still carried by the document alone.

Name honestly in that last section: the view has no live update and reads on mount; `PEER_FIELD` covers three kinds, so every other kind is a marker and the picture is sparse by design; and a mark's position is a linear function of wall-clock time, so a run with one long wait compresses everything else.

- [ ] **Step 4: Update `CLAUDE.md`**

Add an architecture invariant naming what enforces the no-inferred-edge rule:

```markdown
- **An arrow asserts a handoff, and an event records one end of it.** The
  trace view draws an edge only where a producer recorded a peer, in the one
  place a peer is read (`PEER_FIELD` in `assets/trace.js`), and holds no table
  mapping an event kind to a source and a destination lane. Every other event
  is a marker on a single lane, and the legend prints `inferred: 0` beside the
  observed count, because a diagram people trust has to say what it refused to
  draw. The picture is sparse, and the sparseness names the handoffs this
  system does not observe; the fix is a producer recording a peer, never a
  renderer inferring one. Since this slice a decision names its own call:
  `policy.decision` carries `request_id` and `call_hash`, so a hold and the
  approval that answered it link from the record rather than from position in
  the log, and the inbox no longer correlates by adjacency. A hole in a run's
  seq reaches the page for the first time, drawn apart from a fault because
  the record cannot tell a killed harness from an event a producer numbered
  and never wrote. Enforced by `tests/invariants.rs`
  (`the_trace_view_derives_no_edge_from_an_event_kind_alone`),
  `tests/broker.rs`
  (`a_decision_names_the_call_it_decided_rather_than_relying_on_adjacency`),
  `tests/console.rs`
  (`a_hold_is_correlated_by_the_recorded_call_and_not_by_position`,
  `verify_reports_a_seq_gap_and_the_ledger_still_reads_ok`) and
  `ci/console-render.sh`
```

- [ ] **Step 5: Re-run the scan on this repository**

Run: `target/debug/gantry scan .`
Expected: the unenforced marker count is unchanged, or one lower if this slice closed one. If it moved, update `README.md` and say why in the proof document.

- [ ] **Step 6: Commit**

```bash
git add docs/proof/21.md CLAUDE.md README.md
git commit -m "docs: proof 21, a trace view that draws only observed edges

Records the adversarial case: each assertion proved able to fail by renaming
the field behind it, with the failure text.

Names what is still carried by the document alone: no live update, three kinds
with a recorded peer so the picture is sparse by design, and a linear time axis
that compresses a run with one long wait.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## Deferred, and why

- **The idle-gap squash checkbox.** In the spec, not in this plan. It is a reading aid on top of a working axis, it needs its own assertion that the ruler says where the axis is broken, and it is the first thing to add once the linear axis proves annoying in use. Named in `docs/proof/21.md` as a known ceiling rather than dropped quietly.
- **A JavaScript unit test runner.** There is none in this repository and adding one means a build step, which `assets/WIRING.md` rules out. The derivation is covered structurally by `tests/invariants.rs` and behaviourally through the render gate, which is the same shape as `tests/scan.rs` asserting the scanner holds no write-capable filesystem call.
