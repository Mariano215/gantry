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
  "head": { "...": "the SignedHead above" },
  "reproduce": "gantry ledger verify /path/to/ledger"
}
```

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
