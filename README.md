# Gantry

An LLM-agnostic control plane for agentic engineering. It implements the
twelve harness primitives as running services, ships as one static binary,
and scores itself from its own telemetry.

Read `docs/CONCEPT.md` for the thesis and `docs/PLAN.md` for the slice order.
Every slice ends in an adversarial proof under `docs/proof/`.

## What runs today

- **Evidence ledger** (`src/ledger.rs`): append-only Merkle log, signed tree
  heads, offline inclusion and consistency proofs. Nothing is trusted that is
  not on this record.
- **Model gateway** (`src/gateway.rs`): the one chokepoint every model call
  passes, normalising calls across providers and pinning instruction and
  policy versions per call.
- **Tool broker and policy engine** (`src/broker.rs`, `src/policy.rs`): one
  policy decision per tool call, an MCP-shaped registry that refuses loose
  definitions, denials that name their rule.
- **Sandbox, credential broker, egress control** (`src/sandbox.rs`,
  `src/secrets.rs`): per-run seatbelt isolation, secrets the model never sees,
  network denied except an allowlist.
- **Sensor bus** (`src/sensor.rs`): checks with lifecycle placement whose
  verdicts name the fix, and the rule that a sensor which cannot fail is
  reported broken rather than clean.
- **Orchestrator and trust budget** (`src/trust.rs`): rungs earned on clean
  sensor history under a named approver, demoted automatically by the next
  failure, all replayable from the ledger.
- **Durable state and corpus graph** (`src/durable.rs`, `src/graph.rs`):
  resume a killed run from its last checkpoint with nothing lost; a graph
  retrieval that reads a fraction of a flat scan, and reports when it loses.
- **Conformance scorer** (`src/scorer.rs`): the rubric as a running service,
  scoring the platform from telemetry.
- **Skills and delegation** (`src/skills.rs`): signed skill packages, a
  resolver that refuses a broken one rather than publishing it on its title,
  and delegation that can only narrow scope.

## Gantry scored by Gantry

The scores below are produced by `gantry score` reading a ledger that
exercised the layers, not by reading this file. The rules are data
(`config/scoring.json`), so anyone holding the ledger re-derives them. The
overall level is the **minimum** across scored primitives, never the average:
one weak layer caps the whole, which is the honest number and the one a mean
would hide.

| # | Primitive | Score | Why |
|---|---|---|---|
| 01 | Instruction | 3 | Instruction pack version-pinned per run; no lifecycle telemetry, so capped at 3. |
| 02 | Context delivery | 3 | Normalised model.call events with a pinned prompt hash. |
| 03 | Context management | 2 | Window budget and actual recorded per call. Graph retrieval is not yet ledgered, so telemetry caps this at 2. |
| 04 | Tool interface | 4 | MCP-shaped registry, taint on every result. |
| 05 | Execution environment | 4 | Commands run inside a seatbelt sandbox, recorded per request. |
| 06 | Durable state | 3 | A run resumed from a checkpoint: the seam is on the record. |
| 07 | Orchestration | 3 | A rung earned promotion under a named approver. |
| 08 | Sub-agents | 3 | Delegation narrows scope and refuses to widen; no per-sub-agent run telemetry yet. |
| 09 | Skills | 3 | Signed skill packages resolved or refused, never titled; key registry still per-call. |
| 10 | Verification | 4 | A sensor that could not fail was reported broken, not clean. |
| 11 | Observability | 3 | Requests, decisions and results all flow through the chokepoint onto the signed ledger. |
| 12 | Governance | 3 | Authority-as-code produced a named denial; permission-mode drift still unobserved, capping at 3. |

**Overall level: 2.** The floor is primitive 03: the graph retrieval works and
is measured (`docs/proof/07.md`), but it does not yet emit events, so the
scorer, which reads telemetry and not prose, will not credit above 2 until it
does. Four layers stand at 4. That gap between what the code does and what the
telemetry proves is the point of scoring from the ledger: the number cannot be
argued up.

Reproduce:

```
cargo build
zsh docs/proof/08-run.sh
```

## Building

Rust, one static binary. `cargo build`, `cargo test`. The suite runs offline
(no network), and `tests/invariants.rs` fails the build if the HTTP client is
referenced outside the gateway.

On this development machine a dashboard tool named `cc` shadows the C compiler
on `PATH`; `.cargo/config.toml` pins the linker and `CC` to `/usr/bin/cc` so
the build does not depend on `PATH` order.
