# Plan — nine slices, each ending in a proof

Design, code, test, proof, next. Two rules shape the order: evidence cannot be
retrofitted, so the ledger is slice one; and every slice must make the next one
safer to build, which is why the sandbox lands before the orchestrator.

A proof is **adversarial and written down**. Not "here is the feature working"
but "here is the attack, and here is the record of it failing." Each slice
commits `docs/proof/NN.md` — use the `/proof` command.

## The proving workload

A sandboxed repository security audit. A small crew of agents checks out a
repo, runs with no network route and no write access, and emits a signed
findings report where every finding carries an inclusion proof back to the
calls that produced it.

Chosen because it exercises the layers nobody builds — 04, 05, 10, 11, 12 under
real load — rather than the ones that demo well. The agents read untrusted
third-party code, which is the honest test of the sandbox. Findings must be
reproducible, which is the honest test of verification. And the output is a
deliverable someone would pay for, so the proof and the marketing are the same
artifact.

---

## 00 — Schemas before code

Event schema and policy schema. See `docs/EVENT-SCHEMA.md`.

**Proof.** A hand-written trace of one real agent run, expressed entirely in
the schema, that a stranger can read and reconstruct without the author
present. If it cannot be written by hand, the schema is wrong.

## 01 — Evidence ledger

Append-only Merkle log, signed tree heads, inclusion and consistency proofs,
offline verifier. Primitive 11 exists before anything can fail to be recorded.

**Proof.** Edit one byte of one historical record; the verifier names the entry
and the divergence point. Then verify a single event's inclusion offline given
nothing but the event and a signed head.

## 02 — Model gateway

Provider adapters, normalised call events, window accounting, instruction and
prompt versions pinned per call. The chokepoint that makes 02, 03 and 11
structural rather than optional.

**Proof.** One agent run against a frontier API, a cloud-hosted model, and a
local model on a machine with no route to the internet. Three ledgers, one
shape. Diff them in the document.

## 03 — Tool broker and policy engine

MCP as the wire protocol. Schema registry that refuses loose definitions,
output tainting, authority-as-code evaluated on every call.

**Proof.** A genuinely destructive command is denied, and the ledger names the
rule that fired, the policy version and the identity in force. Then try to
publish a tool declared as "run any shell command" and watch the registry
reject it.

## 04 — Sandbox, credential broker, egress control

Per-run isolation, allowlist enforced at the network namespace, secrets the
model never sees.

**Proof.** Ship a deliberately hostile tool that reads every environment
variable and posts them to an outside host, plus a prompt-injected document
instructing the agent to help it. Both fail. Both are in the ledger. This is
the launch demo.

## 05 — Sensor bus

Register a sensor with a lifecycle placement — pre-integration,
post-integration, continuous drift. Computational and inferential. Verdict
messages schema'd to name the fix, because the reader is an agent.

**Proof.** A failing sensor blocks the result; the agent reads the message,
corrects on rerun, and passes with no human in the loop, both attempts
recorded. Then break the sensor itself and confirm a sensor that cannot fail is
reported as broken, not as clean.

## 06 — Orchestrator and trust budget

Durable workflow, lifecycle hooks, retries, blocking gates, OIDC approvals,
rungs with sensor-driven promotion and automatic demotion.

**Proof.** A capability earns its way from assisted to autonomous on real
sensor history, promoted by a named approver, and is demoted automatically by
the next failure. Read the whole arc back out of the ledger as a story.

## 07 — Durable state and corpus graph

Plans, checkpoints and memory outside the model's attention. A persisted graph
over the codebase and documents the agent traverses instead of re-reading, with
staleness expiry.

**Proof.** Kill the container mid-run; resume; nothing lost and the ledger shows
the seam. Separately: same task, graph retrieval versus flat retrieval, token
and accuracy delta published including the cases where the graph lost.

## 08 — Conformance scorer and console

The rubric as a running service. Twelve live scores from real telemetry, N/A
where unexercised, overall level as the minimum, every score linked to
evidence. Scoring rules ship as re-runnable data.

**Proof.** Score the platform with itself and publish the result — low numbers
included — in the launch README. The rubric's worked example is the template:
three layers at 4 and an overall level of 2 is more persuasive than a clean
sheet, and it cannot be faked.

## 09 — Skills, sub-agents, templates

Signed skill packages with a resolver, delegation with narrowed scope, harness
templates for common service topologies. Last, because their value depends on
everything below already holding.

**Proof.** Break a skill's metadata deliberately and confirm the resolver
refuses to publish it rather than falling back to its title. Then delete a step
a skill references and confirm something fails before a run does.
