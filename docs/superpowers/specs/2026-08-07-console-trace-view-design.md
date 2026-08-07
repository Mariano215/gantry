# Trace view: a flow graph over the ledger

Slice 21. A seventh console view that draws the ledger as swimlanes on a
clock, the way a packet analyser draws a capture, so an operator can follow one
call across components and across runs instead of reading a table in append
order.

## Why this view and not a prettier waterfall

The Run view already draws every event of one run in append order with an
offset column. Two things it cannot answer, and both are the questions people
actually arrive with:

- Which component did this, and what did it hand to what. The waterfall has a
  kind column, not a topology.
- What happened to that held call. The retry that consumes an approval is a new
  run with a new request id (`docs/proof/14.md`), so the hold, the approval and
  the release sit in two different waterfalls and neither shows the whole
  thing.

The trace view answers both from the same events, with no new producer of
truth.

## The rule this view is under

An arrow asserts a handoff. A Gantry event records one end of it: `actor` is
who wrote the event. Nothing on the record says the gateway handed a call to
the broker.

So the view draws an edge only where a producer recorded a peer, and draws
everything else as a marker on a single lane. It holds no `kind` to
`(source, destination)` table. A topology table would make every event an
arrow and the diagram would be complete and partly untrue, which is the defect
`CLAUDE.md` already rules on: a view that reads configuration instead of
telemetry is wrong.

The consequence is that the picture starts sparse. That sparseness is the
finding. It names the handoffs this system does not observe, the same way
`gantry drift` reports `unobservable` rather than `match`. Where the view
needs another arrow the fix is a producer recording a peer, never a renderer
inferring one.

The legend states this on screen: `n edges observed, 0 inferred`. The second
number is zero by construction and is printed anyway, because a diagram people
trust has to say what it refused to draw.

## Lanes

A lane id is an event's `actor`, verbatim, serialised: `agent:gantry-run`,
`agent:gantry-broker`, `system:sensor-bus`, `user:mariano@local`. Peer lanes
are created only from a value a producer recorded: `provider:anthropic`,
`tool:Bash`, and a child lane from a `subagent.spawn`.

No lane is invented, and a lane with no events is not drawn. Lane order is
first appearance, left to right, so the layout is a property of the capture
rather than a house style.

## What each kind draws

| kind | lane | recorded peer | drawn as |
|---|---|---|---|
| `model.call` | gateway run | `provider`, `model` | arrow out and back, span from `latency_ms`, carrying `tokens`, `cost_usd`, `outcome` |
| `tool.request` | broker | `tool` | arrow to the tool lane; `sandbox` is an attribute of the mark, not a lane |
| `tool.result` | broker | correlates by `request_id` | return arrow, with `duration_ms`, `outcome`, `taint` |
| `policy.decision` | broker | none | gate marker, coloured by `verdict`, labelled with `rule`, `gate` and `capability` |
| `approval` | the approver | `call_hash`, `rule` | marker on the human lane |
| `approval.use` | broker | `grant_id`, `call_hash` | connector to that approval |
| `subagent.spawn` | parent | the child | arrow opening a new lane |
| `sensor.verdict`, `sensor.fail`, `rung.change`, `drift.report`, `state.checkpoint`, `ledger.anchor` | their own actor | none | markers |
| `run.open`, `run.seal` | the run's actor | none | lane bounds; an unsealed run ends in an open bracket, never a closed one |

A `policy.decision` is a marker and not an arrow because it is genuinely a
self-event: the broker decided. Drawing it as a handoff would be the first lie
the table would tell.

## Correlation, and the one producer change

`policy.decision` carries no `call_hash` and no `request_id`. Its subject is
`Decision` (`src/policy.rs:327`): verdict, capability, rule, rung, effect,
gate, obligation, request, identity, message.

`src/console.rs:890` therefore correlates a decision to its call by adjacency,
pairing each decision with the `tool.request` immediately before it in the
log. That holds for the inbox, which reads the log in order. It does not hold
for a view whose purpose is following one call while others interleave, and it
is a link the record does not carry, which is an inferred edge one layer down
from the ones this view refuses to draw.

The change: `src/broker.rs:395` adds `request_id` and `call_hash` to the
`policy.decision` subject, and the inbox reads them instead of walking
adjacency. Additive subject fields, governed by `ci/schema-compat`.

After it, hold to approval to `approval.use` to retry is an observed chain, and
"follow this call" is one filter on `call_hash` that spans every run the call
appears in.

## Filter bar

Space-separated `field:value`, AND by default. `!field:value` negates. A bare
word is a substring match over the drawn row. Fields: `kind`, `actor`, `lane`,
`run`, `verdict`, `rule`, `capability`, `tool`, `provider`, `att`, `call`,
`request`, `since`.

The expression is written into the URL hash verbatim, so a trace is a link
somebody can paste into a finding and land on the same picture.

`/api/events` supports `kind`, `run`, `actor`, `since`, `limit` and `offset`
server side. Every other term runs in the browser, over at most 1000 rows. A
client-side filter reporting "3 results" over a page implies the log holds 3,
so the bar reports both halves:

    3 of 1000 drawn · 14,203 match the server-side part of this filter

and when a client-side term ran over a truncated page it names which terms
could not be pushed down, and links to the narrower server-side read that makes
the answer whole. This is the existing rule in `docs/CONSOLE-API.md` about
never showing a page of a truncated set as the set, applied to filtering.

## Detail pane

Selecting a mark docks the existing `eventDetail` content as a right-hand
pane: envelope fields, position in the chain, `prev_hash`, attestation state
and attestation trust, then the subject payload. A verified signature under a
published seed still renders as `verified (fixture)`, unchanged from slice 11.

## Time

Each mark carries delta from the previous mark and delta from the first. A
`policy.decision` reading `hold` and the `approval` that answers it draw a
span between them labelled with its real duration, which is reachable once the
correlation change above lands.

One checkbox squashes idle gaps longer than one second, because a twelve second
wait beside three hundred millisecond calls otherwise collapses the run into a
single pixel. While it is on, the ruler states that the axis is broken and
where. Off by default: a broken axis is a reading aid, not the default truth.

## Holes in a lane

`Ledger::seq_gaps` exists (`src/ledger.rs:679`) and `gantry ledger verify`
prints gaps. `/api/verify` does not return them: `src/console.rs:1122`
serialises faults and attestation counts only, so nothing on the console has
ever shown a gap.

Add `seq_gaps` to that payload and to the contract. The trace draws each gap as
a break in the affected lane, labelled with the run, the seq either side and
the count missing. It is styled as a hole and never as a fault, matching
`docs/proof/18.md`: the log cannot tell a harness killed mid-run from an event
a producer numbered and failed to write, and calling that an alteration would
assert a distinction the record cannot make.

## Lane statistics

A collapsible strip under the graph, one row per lane: events, denials, holds,
total held time, unattested count, first and last offset. Sortable. Sorting by
denials is how a reader finds the lane worth opening.

## Rendering

Inline SVG for lanes, edges and the ruler. DOM elements for the marks, so
selection, the detail pane and the existing keyboard navigation in `app.js`
work unchanged.

No dependency and no build step, same as the rest of `assets/`. `el()` in
`ui.js` calls `createElement`, so it needs a sibling that takes the SVG
namespace, which is about three lines.

## Changes outside the front end

1. `src/broker.rs` adds `request_id` and `call_hash` to the `policy.decision`
   subject.
2. `src/console.rs`: the inbox reads those two fields instead of walking
   adjacency; `/api/verify` returns `seq_gaps`.
3. `docs/CONSOLE-API.md` records both contract changes.
4. `docs/EVENT-SCHEMA.md` records the two added subject fields.

## The gate

`ci/console-render.sh` grows a fixture with two concurrent runs, a hold, an
approval, a retry that spends it, and a seq gap. Rendered headless under flags
that leave only loopback resolvable, as the existing check already does, the
dumped DOM must carry:

- every lane label, taken from the fixture's actors
- the observed edge count, and `inferred: 0`
- the held span with its real duration
- the gap text, naming the run and both seq numbers
- the truncation note, when the fixture exceeds the page
- a follow-call filter that pulls the same `call_hash` out of both runs

Each assertion is proved able to fail by renaming the field behind it, the
discipline slice 20 used. With no browser present the check names the fix and
exits non-zero rather than skipping.

Unit coverage in `tests/console.rs` for the lane and edge derivation, including
one test that an event with no recorded peer produces a marker and never an
edge, and one that no code path can produce an edge from a kind alone.

Proof document `docs/proof/21.md`, with the adversarial case, the evidence and
the conformance delta, produced by running it.

## Out of scope

- Live streaming. The view reads on mount and on demand, like every other view.
  A polling flow graph is a different problem and the console has no push.
- Any control that writes. `docs/CONSOLE-API.md` is read-only and this view
  adds no exception. A held call shows the `gantry approve` command, as the
  inbox does; a human runs it under their own identity.
- Cross-ledger tracing. One ledger per console.
