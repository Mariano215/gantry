# Console API

The read-only HTTP interface the operator console renders. Loopback by
default, served by the same binary that serves the static assets, from the
same process. Slice 10 builds it; slice 11 consumes it.

This file is the contract. The backend implements exactly these shapes and
the front end assumes exactly these shapes, so the two can be built in
parallel without meeting in the middle.

## Rules

- **Read-only.** There is no POST, PUT, PATCH or DELETE. The console cannot
  approve, promote, demote or append. A UI that can move a rung is an
  authority surface and needs an identity story the laptop profile does not
  have.
- **Every response is derived from the ledger on the request.** Nothing is
  cached across requests. A page is the current state of the log or it is
  wrong.
- **Errors are Faults.** Status 400 for a bad query, 404 for an unknown id,
  500 for a read failure, body `{"cause": "...", "fix": "..."}`, matching the
  `Fault` the CLI prints. An error names the action to take, same rule as
  everywhere else.
- **Content type** is `application/json; charset=utf-8` on `/api/*` and
  `text/html; charset=utf-8` on everything else.
- **Unknown `/api/*` paths are 404 with a Fault body.** Unknown non-API paths
  serve the console shell, so the front end owns its own routing.

## `GET /api/score`

The `ScoreSnapshot` the current scorecard already renders, serialised
directly. Field names are `serde` defaults on `gantry::scorer::ScoreSnapshot`.

```json
{
  "scores": [
    {
      "primitive": 1,
      "name": "Instruction",
      "score": 3,
      "evidence": "instruction pack version-pinned on every run.open; no lifecycle telemetry, so capped at 3",
      "sample_event": "ev-01H..."
    }
  ],
  "overall": 3,
  "rules_version": "scoring-2",
  "events_scored": 14
}
```

`score` is `null` for N/A: the layer was never exercised. `overall` is the
minimum across non-null scores, or `null` if every layer is N/A. The front end
renders `null` as N/A and never as zero.

## `GET /api/head`

The latest signed tree head, `gantry::ledger::SignedHead`.

```json
{
  "size": 14,
  "root_hash": "sha256:...",
  "ts": "2026-08-05T09:14:02Z",
  "key_id": "ledger-local-1",
  "sig": "base64..."
}
```

## `GET /api/events`

Envelopes with their subjects inlined, newest last, exactly as
`Ledger::events_with_subjects` produces them plus one derived field.

Query parameters, all optional and combinable:

| Parameter | Effect |
|---|---|
| `kind` | exact match on `kind`, repeatable for a set |
| `run` | exact match on `run_id` |
| `actor` | substring match on the serialised `actor` |
| `since` | ISO 8601; events with `ts` at or after it |
| `limit` | maximum returned, default 200, maximum 1000 |
| `offset` | skip this many after filtering, for paging |

```json
{
  "events": [
    {
      "v": 2,
      "id": "ev-...",
      "run_id": "run-1754380000000",
      "parent_id": null,
      "seq": 3,
      "ts": "2026-08-05T09:14:02Z",
      "kind": "policy.decision",
      "actor": {"kind": "system", "id": "system:broker"},
      "authority": {"policy_version": "sha256:...", "diverged": []},
      "subject_hash": "sha256:...",
      "redacted": [],
      "prev_hash": "sha256:...",
      "attestation": null,
      "_subject": {"tool": "Bash", "verdict": "deny", "rule": "r-destructive-shell"},
      "_attestation_state": "verified",
      "_attestation_trust": "fixture"
    }
  ],
  "total": 14,
  "returned": 1,
  "offset": 0
}
```

`_attestation_state` is derived per event and is one of:

- `verified`: signature checked against a key in `config/actor-keys.json` and
  good.
- `unverified`: an attestation is present but no registered key matches its
  key id. Counted, never passed.
- `forged`: an attestation under a registered key id that fails the check.
  This is a fault, and `/api/verify` reports it too.
- `absent`: no attestation on the event.

The front end must show these four states distinctly. Rendering `absent` and
`verified` the same way would be the exact failure this project exists to
prevent.

`_attestation_trust` says what a `verified` signature is worth, and it is the
second half of the same rule:

- `registered`: signed under a key whose seed is held by its owner. This is
  attribution.
- `fixture`: signed under a key whose seed is published, as the tracked laptop
  key's is. The signature is real and proves which run wrote the event, but
  anyone holding the repository can produce one, so it is not attribution.

The console must qualify a verified badge with this. A laptop run and an
HSM-backed deployment must not render identically, because the difference is
the entire claim. The field is meaningful only alongside `verified`; it reads
`registered` otherwise and carries no weight there.

Note on `_subject`: it is the stored payload passed through verbatim, so its
shape follows the event kind. A `policy.decision` subject names the outcome in
`verdict`, not `decision`.

## `GET /api/events/:id`

One event, same shape as an element of `events` above, plus its position:

```json
{
  "event": { "...": "as above" },
  "index": 3,
  "tree_size": 14
}
```

404 with a Fault body if the id is not on the ledger.

## `GET /api/runs`

Runs derived from `run.open` and `run.seal`, newest first.

```json
{
  "runs": [
    {
      "run_id": "run-1754380000000",
      "opened_at": "2026-08-05T09:14:01Z",
      "sealed_at": "2026-08-05T09:14:05Z",
      "sealed": true,
      "workload": "repo-audit",
      "events": 9,
      "kinds": {"model.call": 1, "tool.request": 3, "policy.decision": 3},
      "denials": 1,
      "unattested": 9
    }
  ]
}
```

`sealed_at` is `null` and `sealed` is `false` for a run that never sealed. An
unsealed run is a crashed or in-flight run and the console shows it as such;
the scorer already treats the seam as evidence, so the UI must not hide it.

## `GET /api/policy`

The loaded policy plus firing counts from the ledger.

```json
{
  "profile": "laptop",
  "version": "sha256:8330dcc...",
  "capabilities": [
    {"id": "repo.write", "rung": "assisted", "effect": "write.shared", "rollback": "git.revert"}
  ],
  "rules": [
    {
      "id": "r-destructive-shell",
      "decision": "deny",
      "message": "This command is destructive and ...",
      "fired": 3
    }
  ]
}
```

`fired` counts `policy.decision` events naming that rule id. A rule with
`fired: 0` is shown, not hidden: an unfired deny rule is either dead weight or
a control that has never been tested, and both are worth seeing.

## `GET /api/trust`

Each capability's rung replayed from the ledger, never read from config.

```json
{
  "capabilities": [
    {
      "capability": "repo.write",
      "declared_rung": "assisted",
      "earned_rung": "autonomous",
      "clean_since_rung": 3,
      "history": [
        {"ts": "...", "event_id": "ev-...", "kind": "rung.change", "from": "assisted", "to": "autonomous", "approver": "user:mariano@local"}
      ]
    }
  ]
}
```

`declared_rung` comes from the policy and `earned_rung` from replay. When they
differ, the earned one is what the broker gates on, and the console must make
which is which unmistakable.

## `GET /api/approvals`

The approval inbox: every call whose `policy.decision` resolved to `hold`, and
what the record says has happened to it since. Derived from the ledger on the
request, like everything else here.

```json
{
  "holds": [
    {
      "call_hash": "sha256:2508e913...",
      "rule": "r-publish",
      "message": "This call gates pre at rung led for effect irreversible and needs an approval event before it can proceed. ...",
      "capability": "vcs.publish",
      "tool": "Bash",
      "target": "git push origin main",
      "held": 2,
      "first_held_at": "2026-08-05T13:28:49.809Z",
      "last_held_at": "2026-08-05T13:31:02.114Z",
      "request_id": "run-1785936529805-req-3",
      "run_id": "run-1785936529805",
      "decision_event": "run-1785936529805-4",
      "state": "waiting",
      "releases_next_call": false,
      "approve_command": "gantry approve /path/to/ledger run-1785936529805-req-3 <approver>",
      "grants": [
        {
          "grant_id": "run-1785936547330-0",
          "verdict": "deny",
          "approver": "user:mariano@local",
          "ts": "2026-08-05T13:29:07.330Z",
          "event_id": "run-1785936547330-0",
          "request_id": "run-1785936530058-req-3",
          "permitted": true,
          "spent": false,
          "spent_at": null
        }
      ]
    }
  ],
  "blocked": 2,
  "released": 1,
  "approvers": "any",
  "ledger": "/path/to/ledger"
}
```

The row is one held call, not one held request. A grant binds to the call hash
rather than the request id, because the retry that consumes it is a new run
with a new request id (`docs/proof/14.md`), so repeated holds of the same call
under the same rule are one row with `held` counting them. `request_id` is the
most recent, which is the one an approver is answering, and it is what
`approve_command` names.

`releases_next_call` is the broker's own predicate, re-derived: an `approve`
grant, under an approver `trust_budget.promotion.approver` permits, that no
`approval.use` has spent. A console that showed a grant as releasing a call the
broker would still hold would be worse than showing nothing.

`state` is one of:

- `waiting`: no approval event names this call and rule. Nobody looked.
- `refused`: the most recent approval carries `verdict: deny`. Somebody looked
  and said no. This is not the same state as `waiting` and the front end must
  not render it as one, because that distinction is the whole reason a refusal
  is an event.
- `released`: a usable grant is on the ledger. The next identical call runs and
  spends it.
- `spent`: every approve grant for this call has been spent by an
  `approval.use`, and the call has been held again since. A single use grant
  rendered as still usable would be the worst row on the page.
- `ineffective`: an approve grant exists under an approver the trust budget
  does not permit, so the broker will not release the call. Reachable only on a
  profile whose approver is `named`.

`approvers` is `"any"` or the list from
`trust_budget.promotion.named_approvers`. Where it is `"any"` the console
cannot know who is at the terminal, so `approve_command` carries the
`<approver>` placeholder and the view says to replace it; where approvers are
named, the command names one.

**This route is read-only, and the front end must not grow a button that
resolves a hold.** It prints the command; a human runs it at a terminal under
their own identity. An approval written by a click on a loopback port would put
a name on the ledger that nothing stands behind, which is a different claim
from the one the approval path makes. The rule at the top of this file applies
here with no exception.

## `GET /api/verify`

A full verification on the request. This is the expensive route; the front end
calls it on demand, not on a poll.

```json
{
  "ok": true,
  "entries": 14,
  "attestations_verified": 14,
  "attestations_unverified": 0,
  "attestations_under_published_seed": 14,
  "faults": [
    {"index": 7, "id": "ev-...", "fault": "leaf hash does not match the stored envelope"}
  ],
  "seq_gaps": [
    {"run_id": "run-...", "after": 7, "before": 11, "missing": 3}
  ],
  "head": { "...": "the SignedHead above" },
  "reproduce": "gantry ledger verify /path/to/ledger"
}
```

`seq_gaps` is every hole in a run's `seq`, naming the run, the last seq before
the hole, the first after it, and how many are missing. It is a finding and
never a fault, so `ok` stays true with gaps present: a removed entry faults on
the chain or on a signed head, which means a hole is an event that was never
appended, and the record cannot tell a harness killed mid-run from a producer
that numbered an event it failed to write. The front end draws it as a hole in
the record and must not present it as tampering. The field has existed on the
verify report since slice 18 and reached this route in slice 21, so no console
before that could show a gap at all.

`ok` is false when `faults` is non-empty. The `reproduce` string is the exact
offline command that reaches the same verdict without the server, and the UI
shows it verbatim. The console never presents its own verification as
independent: it reports what the server found and hands the reader the command
that checks the server.

## What the front end must never do

- Render a null score as 0.
- Render `absent` or `unverified` attestation state as a pass.
- Show a healthy page over a ledger whose `/api/verify` returned `ok: false`.
  A verification failure takes over the UI; it is not a badge in a corner.
- Claim to have verified anything. It reports.
- Show a page of a set the API truncated without saying so. `/api/events`
  returns at most 1000 rows and reports `total`; a view that draws the page and
  not the number is a complete-looking rendering of an incomplete read. The
  page is the oldest matching events, not the newest, because limit and offset
  run over the log in append order, and a view that says "most recent" is
  describing a page nobody is looking at.
- Offer to approve, promote or append. `/api/approvals` names what is waiting
  and prints the command; the console has no identity story and a button here
  would put a name on the record that nothing stands behind.
