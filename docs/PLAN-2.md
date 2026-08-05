# Plan 2: post-nine, four slices

`docs/PLAN.md` covers slices 00 through 09. All nine are built and each has a
proof. This file covers what comes after, and it exists because the honest
answer to "is it done" is no in three specific places.

The same rules apply. One slice at a time. A slice is done when
`docs/proof/NN.md` exists, contains the adversarial case, the evidence and the
conformance delta, and was produced by running the thing rather than by
reasoning about it.

## Where the project actually stands

Overall level 3, set by seven layers sitting at 3. Four layers reach 4.
Nothing is below 3. That is a real number derived from telemetry, and it is
also a plateau: the next point costs more than the last nine did.

Three gaps are named in `CLAUDE.md` or visible in the score, and they are the
whole of this plan:

1. **No producer emits attestations.** `ledger::verify_with_actor_keys` checks
   them and the tests exercise both branches, but the laptop profile writes
   null, so no run has ever carried one. A verification path that only tests
   reach is the exact defect this project exists to catch. It is the most
   serious item here and it is first.
2. **The console is one page.** A scorecard, re-rendered per request. The
   ledger holds around twenty event kinds, run structure, policy decisions,
   trust history and a signed head, and none of it is visible. Anyone who
   arrives from the README opens the console and sees a table.
3. **`[UNENFORCED] ci/permission-mode-hook`.** `authority.permission_mode`
   records `unobserved` unless something sets `CLAUDE_PERMISSION_MODE`, and
   nothing sets it automatically. The last marker in `CLAUDE.md`.

A fourth item is a scoring cap rather than a gap: primitive 01 is held at 3 by
"no lifecycle telemetry" on instruction changes. It is the cheapest available
move from 3 to 4 and it lands last, because it is worth nothing if the record
underneath it is not attested.

## Slice 10: attested events and a read-only console API

Two halves that share one proof, because the console's credibility depends on
the attestation: a UI that renders the ledger is only as trustworthy as the
signatures on the rows it renders.

**Attestation producer.** The gateway and the broker sign what they append.
The actor key comes from the profile; `config/actor-keys.json` is already the
registry and `Envelope::attestation_bytes` already defines the signed bytes,
so this is wiring a signer into `RunCore`, not designing a scheme. A profile
that declares an actor key and cannot load it refuses to start rather than
appending unsigned, which is the same rule the skill key registry already
follows.

**Read-only API.** `ScoreSnapshot`, `SignedHead` and `Policy` already derive
`Serialize`, and `Ledger::events_with_subjects` already returns exactly what a
UI needs. The API is a router over data that exists.

| Route | Returns |
|---|---|
| `GET /api/score` | the `ScoreSnapshot` the scorecard renders |
| `GET /api/head` | the latest signed tree head |
| `GET /api/events` | envelopes with subjects, filterable by `kind`, `run`, `actor`, `since`, `limit` |
| `GET /api/events/:id` | one envelope with its subject and attestation state |
| `GET /api/runs` | runs derived from `run.open` and `run.seal`, with counts and seal state |
| `GET /api/policy` | the loaded policy, plus how many times each rule fired |
| `GET /api/trust` | each capability's replayed rung and clean-run count |
| `GET /api/verify` | the result of a full ledger verification, plus the CLI command that reproduces it offline |

Read-only, by decision, not by omission. See the decisions section.

**Proof.** Serve a ledger, read every route, and confirm the API answers only
from the record: mutate a stored event by hand and confirm `/api/verify`
reports the fault and the UI shows the ledger as broken rather than serving a
clean page over a tampered log. Then strip an attestation and confirm the row
reports unverified rather than silently rendering as fine.

## Slice 11: the operator console

Static assets the binary serves. Six views over the API above.

- **Overview.** Overall level, the twelve primitives, the signed head, event
  volume over time, and what is currently unattested. The landing page for a
  newcomer and the first screen in a demo.
- **Ledger.** The event stream as a living list. Filter by kind, run, actor.
  Expand a row to its subject, its authority block, its attestation state and
  its position in the tree. This is the view that makes the product legible:
  everything else is a summary of it.
- **Run.** One run as a waterfall. Model calls, tool requests, policy
  decisions, sandbox executions, sensor verdicts, in sequence, with the denial
  reasons inline. An incident review reads this and nothing else.
- **Policy.** Every rule, its gate, its message, and how many times it fired.
  A rule that never fires is visible, which is the reachability argument made
  operational rather than only enforced at load.
- **Trust.** Each capability's rung, the runs behind it, and the events that
  promoted or demoted it. The trust budget is the most novel thing in the
  system and currently the least visible.
- **Verify.** The verification result, the head, and the exact offline command
  that reproduces it. The console never claims to have verified anything it
  did not.

**Proof.** Drive the console against a ledger built by the slice 08 script and
confirm every number on screen traces to an event id. Then serve a tampered
ledger and confirm the console refuses to present it as healthy.

## Slice 12: the permission-mode hook

A `SessionStart` hook that exports `CLAUDE_PERMISSION_MODE` so an unwrapped
session records its real mode instead of `unobserved`. Closes the last
`[UNENFORCED]` marker and makes primitive 12's divergence check real in runs
rather than only in tests.

**Proof.** Run under a mode that differs from the tracked
`permissions.defaultMode` and confirm the divergence lands in
`authority.diverged` without being told what the mode was.

## Slice 13: instruction lifecycle telemetry

A sensor that fires when the instruction pack changes, emitting an event the
scorer can read. This is what lifts primitive 01 off its cap of 3.

**Proof.** Change the pack without review and confirm the sensor blocks;
change it with review and confirm the score moves. The score must move because
the telemetry moved.

## Decisions

**No build step, no framework, no package manager.** The UI is hand-written
HTML, CSS and ES modules under `assets/`, embedded with `include_str!` and
served by the binary. This is not a preference. `CLAUDE.md` requires the UI to
be static assets the binary serves with no second process; the air-gap
constraint forbids a CDN font or a remote script; and `docs/DEPENDENCIES.md`
is a census that a `node_modules` tree would make meaningless. A framework
would ship faster on day one and would cost the strongest claim the project
makes. The views are tables, a timeline and a filter. Vanilla covers it.

**The console is read-only.** It cannot approve, promote, demote or write.
A UI that can promote a rung is an authority surface and needs its own
identity story, which the laptop profile does not have. Adding buttons before
adding authentication would put an unauthenticated write path in front of the
trust budget. Approval flows wait for the identity work.

**Loopback by default, unchanged.** The API inherits the console's existing
bind. An operator who exposes it does so explicitly, and the read-only rule is
what makes that survivable rather than reckless.

**Verification stays server-side.** Ed25519 verification in browser JavaScript
without a dependency is possible and would be the wrong kind of clever. The
API verifies; the UI reports the result and prints the offline command. A
console that appeared to verify locally while trusting a server response would
be a lie of exactly the type the scorer exists to prevent.

**Attestation before UI.** If the two were reversed, the first thing a visitor
would see is a beautiful rendering of an unsigned log.

## The order, and why

Attestation first because it is an integrity gap and everything above it
inherits its credibility. The API next because the console cannot exist
without it. The console next because it is what makes the rest legible. The
hook and the instruction sensor last because they are small, independent, and
each moves exactly one number.
