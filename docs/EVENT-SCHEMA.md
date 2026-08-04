# Event schema — slice 00

Everything downstream is a consumer of this document. Changing it later is the
one migration the project cannot afford, so it is settled before the ledger is
written.

## Design constraints

1. **One event type, not many.** A kind discriminator and a kind-specific
   `subject`. Auditors read a uniform envelope; adding an event kind must not
   change how verification works.
2. **Canonical serialisation.** RFC 8785 JSON Canonicalisation Scheme. Field
   order and naming are part of the signature, therefore schema-breaking.
3. **Signed individually, chained collectively.** Each event carries a
   signature over its own canonical form including `prev_hash`. Integrity of
   the whole log comes from the Merkle tree over events, not from the chain
   alone — the chain gives cheap local detection, the tree gives inclusion
   proofs for a single event.
4. **Payload separable from evidence.** Retention rules expire a payload while
   retaining its hash, so a log stays verifiable after personal or client data
   has been removed. Deleting an event is never permitted.
5. **Authority travels with every event.** Not just privileged ones. The
   cheapest way to answer "under whose authority" is to never have an event
   that cannot answer it.

## Envelope

```json
{
  "v": 1,
  "id": "01JQ...",
  "run_id": "01JQ...",
  "parent_id": "01JQ... | null",
  "seq": 42,
  "ts": "2026-08-04T14:02:11.481Z",
  "kind": "tool.call",
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
    "declared": true
  },
  "subject": { "…kind-specific…" },
  "redacted": ["/subject/args/password"],
  "prev_hash": "sha256:...",
  "sig": { "alg": "ed25519", "key_id": "…", "value": "…" }
}
```

`authority.declared` is false when the running value differs from the tracked
declaration. A run containing any `declared: false` event caps primitive 12 at
2 regardless of everything else, and the drift report names the divergence.

`seq` is monotonic within `run_id`. A gap in `seq` is the signal that a
harness was switched off mid-run. Detection, not prevention — see the note on
hooks in `docs/CLAUDE-CODE-INTEGRATION.md`.

## Kinds

| Kind | Primitive | Subject carries |
|---|---|---|
| `run.open` | 06 · 11 | Profile, workload id, resolved instruction pack, settings hash, restored checkpoint id. |
| `run.seal` | 11 | Outcome, event count, signed tree head at seal, cost total. |
| `model.call` | 02 · 03 · 11 | Provider, model, declared inputs and whether each arrived, window budget and actual, token counts, cost, latency, prompt hash. Never the raw prompt in `laptop`+ profiles where retention says otherwise — hash and store separately. |
| `tool.call` | 04 · 05 | Tool id, schema version, canonical args, sandbox kind, egress allowlist hash, credential handles used, result hash, taint flag. |
| `policy.decision` | 12 | Verdict (allow, deny, hold), the rule that fired, policy version, and the request it applied to. A deny is never inferred from an absent allow — it is an event. |
| `sensor.verdict` | 10 | Sensor id, kind (computational, inferential), lifecycle placement, pass or fail, whether it blocked, and the fix-naming message. |
| `approval` | 07 · 12 | Approver identity and source, what was approved, the policy that required it, elapsed time to decision. |
| `rung.change` | 07 | Capability, from, to, trigger (earned, override, demotion), the sensor history that justified it, approver if any. |
| `state.checkpoint` | 06 | Checkpoint id, what it covers, size, and what a resume from it restores. |
| `drift.report` | 12 | Declared value, running value, and the named fix. Emitted on a schedule, not only on change, so silence is evidence. |
| `score.snapshot` | all | Twelve scores with N/A where unexercised, the overall minimum, the scoring-rules version, and an evidence pointer per score. |

## Non-goals for slice 00

No storage engine, no transport, no signing implementation. Slice 00 produces
this document plus one hand-written trace of a real agent run expressed
entirely in this schema, which a stranger can reconstruct without the author.
If the trace cannot be written by hand, the schema is wrong and it is cheaper
to learn that now.
