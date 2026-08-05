# Event schema, v2 (slice 01)

Everything downstream is a consumer of this document. v1 was settled in slice
00 and then tested by writing a real trace by hand; the six changes below came
out of that proof (`docs/proof/00.md` section 7) and are applied here before
the ledger is written, which was the point of writing the trace first.

## Design constraints

1. **One event type, not many.** A kind discriminator and a kind-specific
   `subject`. Auditors read a uniform envelope; adding an event kind must not
   change how verification works.
2. **Canonical serialisation.** RFC 8785 JSON Canonicalisation Scheme. Field
   order and naming are part of the leaf hash, therefore schema-breaking.
3. **Attested individually, chained collectively.** An actor may attest an
   event by signing its `subject_hash` and core identity fields. Integrity of
   the whole log comes from the Merkle tree over envelopes and a ledger-signed
   tree head, not from the attestation: the tree gives inclusion proofs for a
   single event, the signed head gives a verifiable position. The v1 design of
   one signature covering `prev_hash` was circular (the actor cannot sign a
   hash the ledger assigns) and is replaced.
4. **Payload separable from evidence.** The envelope carries `subject_hash`
   only. The subject payload is stored beside the log and may expire under a
   retention rule while the envelope, the hash and every proof stay valid.
   Deleting an envelope is never permitted.
5. **Authority travels with every event.** Not just privileged ones. The
   cheapest way to answer "under whose authority" is to never have an event
   that cannot answer it.

## Envelope

The envelope is what the ledger stores, hashes and proves. The subject payload
travels next to it, keyed by `subject_hash`.

```json
{
  "v": 2,
  "id": "01JQ...",
  "run_id": "01JQ...",
  "parent_id": "01JQ... | null",
  "seq": 42,
  "ts": "2026-08-04T14:02:11.481Z",
  "kind": "tool.request",
  "actor": {
    "type": "agent | human | system",
    "id": "agent:reviewer | user:mariano@... | system:scorer",
    "identity_source": "oidc | local | none",
    "rung": "led | assisted | autonomous | null"
  },
  "authority": {
    "profile": "laptop | team | regulated",
    "policy_version": "sha256:...",
    "instruction_version": "sha256:...",
    "settings_hash": "sha256:...",
    "permission_mode": "default | acceptEdits | bypassPermissions | ... | unobserved",
    "diverged": ["host_permissions.permission_mode"]
  },
  "subject_hash": "sha256:...",
  "redacted": ["/args/password"],
  "prev_hash": "sha256:... | null",
  "attestation": {
    "alg": "ed25519",
    "key_id": "...",
    "value": "..."
  }
}
```

Changes from v1, each mapped to its proof-00 finding:

- **`subject` is out of the envelope, behind `subject_hash`** (finding e/2).
  Expiring a payload no longer changes the envelope, so the chain and every
  Merkle proof survive retention.
- **`authority.declared` is now `authority.diverged`, a list** (finding a/4).
  Empty means the running values match the tracked declaration. A non-empty
  list names each diverging field. Any event with a non-empty list caps
  primitive 12 at 2 for the run, and the reader of one event sees which field
  diverged without hunting for a `drift.report`.
- **`sig` is now `attestation`, optional, and excludes `prev_hash`**
  (finding 3). The attestation is the actor's signature over the JCS form of
  `{id, run_id, seq, ts, kind, actor, authority, subject_hash, redacted}`.
  `prev_hash` is assigned by the ledger at append and covered by the tree, not
  by the actor. `null` when the actor has no key, which is the `laptop`
  profile default.
- **`redacted`** paths are relative to the subject payload, since that is the
  only thing redaction can touch.

`seq` is monotonic within `run_id`. A gap in `seq` is the signal that a
harness was switched off mid-run. Detection, not prevention. See the note on
hooks in `docs/CLAUDE-CODE-INTEGRATION.md`.

## Leaf hash and tree

Defined here because a stranger cannot verify what is not written down
(finding 6).

- **Leaf bytes**: the envelope serialised under RFC 8785 JCS. UTF-8, no
  trailing newline.
- **Leaf hash**: RFC 6962. `SHA-256(0x00 || leaf_bytes)`.
- **Interior node**: `SHA-256(0x01 || left || right)`.
- **Empty tree root**: `SHA-256("")`.
- **Tree shape**: RFC 6962 section 2.1. `MTH` of n > 1 leaves splits at k,
  the largest power of two smaller than n.
- **`prev_hash`**: the leaf hash of the previous envelope in append order,
  `null` for the first. It is cheap local tamper detection; the tree is the
  proof mechanism.
- **Signed tree head**: `{size, root_hash, ts, key_id, sig}` where `sig` is
  ed25519 over the JCS form of `{size, root_hash, ts, key_id}`. Offline
  verification of one event needs the envelope, an inclusion proof and one
  signed head, nothing else.

## Kinds

| Kind | Primitive | Subject carries |
|---|---|---|
| `run.open` | 06 · 11 | Profile, workload id, resolved instruction pack, settings hash, restored checkpoint id. |
| `run.seal` | 11 | Outcome, event count, signed tree head at seal, cost total. |
| `model.call` | 02 · 03 · 11 | Provider, model, declared inputs and whether each arrived, window budget and actual, token counts, cost, latency, prompt hash. Never the raw prompt in `laptop`+ profiles where retention says otherwise: hash and store separately. |
| `tool.request` | 04 · 05 | Tool id, schema version, canonical args, sandbox kind, egress allowlist hash, credential handles requested. Emitted when the call is issued, so a call that blocks, hangs or dies is on the record while it is still outstanding (finding e/1). |
| `tool.result` | 04 · 05 | `request_id` of the matching `tool.request`, outcome (`ok`, `denied`, `blocked`, `timeout`, `killed`), result hash, taint flag, duration. A request with no result is exactly what an auditor wants to see, and now can. |
| `policy.decision` | 12 | Verdict (allow, deny, hold), the rule that fired, policy version, and the request it applied to. A deny is never inferred from an absent allow; it is an event. |
| `sensor.verdict` | 10 | Sensor id, kind (computational, inferential), lifecycle placement, pass or fail, whether it blocked, and the fix-naming message. |
| `approval` | 07 · 12 | Approver identity and source, **verdict (`approve`, `deny`)**, the `call_hash` and `rule` it answers, the `request_id` that prompted it, and a `grant_id`. A human refusing is an approval with `verdict: deny`, not an absent event (finding 5). Written by `gantry approve`, which refuses an approver the trust budget does not permit and refuses any request that did not resolve to `hold`, so an approval never reverses a denial. |
| `approval.use` | 07 · 12 | The `grant_id` spent, the `call_hash` and `request_id` it released, the approver, and `self_approved` when the approver is the calling identity. Emitted by the broker when a held call finds its approval, so a grant releases exactly one call. The `policy.decision` for that call still reads `hold`: the policy held it, and the release is a separate fact rather than a rewriting of the first one. |
| `capability.run` | 06 · 07 | Capability, the rung in force, and the outcome (`clean`, `sensor.fail`) of one orchestrated run. Added in slice 06: this is the unit the trust budget counts, so the rung a capability holds is replayable from these plus `rung.change`. |
| `rung.change` | 07 | Capability, from, to, trigger (earned, override, demotion), the sensor history that justified it, approver if any. |
| `state.checkpoint` | 06 | Checkpoint id, what it covers, the next step index, what a resume restores, and the accumulated per-step results. Slice 07 uses this as a complete restore point: a resume reads the last one for a task and continues, and the seam (a run that opened but never sealed) is the kill point. |
| `drift.report` | 12 | Declared value, running value, and the named fix. Emitted on a schedule, not only on change, so silence is evidence. |
| `score.snapshot` | all | Twelve scores with N/A where unexercised, the overall minimum, the scoring-rules version, and an evidence pointer per score. |
| `ledger.anchor` | 11 | Where the head was anchored (WORM path, RFC 3161 TSA, notary), the head anchored, and the receipt hash (finding 5). |
| `retention.expire` | 11 · 12 | The `subject_hash` expired, the retention rule that authorised it, and the actor. An expiry is an act under someone's authority and must be an event (finding 5). |
| `tool.register` | 04 | Tool id, schema version, schema hash, registry verdict. A rejected registration is recorded with the reason (finding 5). |
| `skill.resolve` | 09 | Skill id, version, verdict (`resolved`, `rejected`), signature state (`verified:<key>`, `unsigned`), resolved steps and scope. Added in slice 09: a rejected resolution carries the reason, so a broken skill's refusal is on the record, not just its absence. |
| `subagent.spawn` | 08 | Skill id, version, and the granted capability set a delegated run holds. From this event on, a call in the run whose capability is outside the grant is denied at the chokepoint with rule `r-delegation`. Added in the post-nine gap work. |
| `graph.query` | 03 | The graph queried, the symbol, the hits, `bytes_read` (index plus any staleness re-reads), `index_bytes`, and the stale nodes re-read. Added in the post-nine gap work so context management scores from telemetry. |

## Concurrency

`seq` is append order at the ledger, not causal order (finding f). Two
requests issued in one turn may complete in either order; `tool.result` events
carry `request_id`, so causal reconstruction never depends on `seq`
adjacency. A reader who needs issue order sorts `tool.request` events by
`ts`; a reader who needs completion order uses `seq`.

## Migration note

v1 events exist only in `docs/proof/00.md`, hand-written. No stored ledger
predates v2, so there is no data migration; the version bump exists so that a
v1 shape appearing anywhere downstream is a schema violation, not a quiet
acceptance.
