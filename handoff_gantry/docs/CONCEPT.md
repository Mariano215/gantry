# Gantry — concept and architecture decisions

Companion to `Agentic Platform Concept.dc.html`, which is the same content as
a designed document. This is the version a coding agent should read.

## Thesis

Agent = model + harness. The market built the model side. The harness — the
part that decides whether an action is permitted, records that it happened, and
can prove it to someone who was not in the room — is still hand-assembled at
every company that needs it.

The twelve-primitive rubric is a measuring instrument pointed at someone else's
system. Gantry is the same rubric pointed inward and satisfied by construction.
That inversion is the product.

The rubric's arithmetic is why this is a product and not an article: the overall
level is the **minimum** across applicable primitives, not the average. Nine
strong layers and one absent trust layer is a level 1 system. The layers nobody
builds are always 10, 11 and 12.

## Positioning

The open reference harness for agentic engineering. Security and evidence are
the substrate, not a module.

**What it is not.** Not an agent framework — it sits underneath LangGraph,
Temporal, Claude Code, a shell script. Not a chat product; the console is for
operators and auditors. Not an eval platform; evals are one kind of sensor.
Not a skills marketplace. Not a compliance product — it produces evidence, it
does not claim certification. Not a model.

## Nine services under twelve primitives

| Service | Primitives |
|---|---|
| Model gateway (provider adapters, window accounting) | 02 · 03 |
| Tool broker (MCP proxy, schema registry, output tainting) | 04 |
| Sandbox supervisor (isolation, egress allowlist, credential broker) | 05 |
| State store (plans, checkpoints, memory, corpus graph) | 03 · 06 |
| Orchestrator (durable workflow, hooks, gates, approvals) | 07 · 08 |
| Skill registry (signed packages, resolver) | 09 |
| Sensor bus (computational and inferential, lifecycle placement) | 10 |
| Evidence ledger (Merkle transparency log) | 11 · 12 |
| Policy engine and drift detector (authority as code) | 12 |
| Conformance scorer (the rubric as a running service) | all |

The instruction pack is version-controlled data consumed by the gateway rather
than a service, which is how primitive 01 gets its missing sensor.

## Decision — the trust budget

Three candidate human-in-the-loop models, each incomplete alone: policy gates
(precise, static), an autonomy ladder (legible, theatre without sensor data),
post-hoc review with rollback (fast, useless for irreversible work).

Collapsed into one mechanism. **Every capability holds a rung. The rung decides
where the human stands. Sensors decide the rung.**

- Human-led — gate is pre-action and blocking.
- Assisted — pre-action for the irreversible subset only.
- Autonomous — post-action review with rollback.

Promotion requires N runs at the current rung with zero sensor failures and zero
human overrides, and is a signed ledger event with a named approver. Demotion is
automatic on failure and needs no meeting. This is maturity anchor 5 made
operational: a failure moves a rung and adds a sensor.

## Decision — profiles

Strictness must be selectable without becoming a lie. One profile sets
isolation, gate placement, anchoring and identity together; rung defaults come
from it and stay overridable per capability.

| Profile | Isolation | Identity | Ledger | Rung default |
|---|---|---|---|---|
| `laptop` (default) | OCI + seccomp, empty egress allowlist | local accounts | local file | autonomous, post-hoc review |
| `team` | kernel-level sandbox | OIDC | anchored daily to object storage | assisted |
| `regulated` | microVM | OIDC required, no local fallback | HSM/TPM keys, external timestamping | assisted, no promotion without named approver |

The constraint that makes this safe: **the scorer reads what is actually
running, never the profile name.** `laptop` scores 3 on primitive 05 and
therefore caps the overall level at 3, stated on the dashboard. `regulated`
refuses to start when a requirement is unavailable rather than degrading
quietly.

## Decision — no blockchain

An auditor wants integrity, attribution, time and completeness. A hash-chained
log with per-entry signatures from a TPM or HSM key delivers the first three.
Completeness is a process control that comes from one architectural chokepoint;
no ledger design supplies it.

A blockchain adds distributed consensus, which solves exactly one problem:
mutual distrust between parties who cannot agree on who operates the log. In a
single-tenant install the operator *is* the client. There is no counterparty.
Consensus buys nothing and charges throughput, key ceremony, operational
surface, and peers — fatal for the air-gap requirement.

**Build instead:** an append-only Merkle transparency log, RFC 6962
construction. Signed tree heads, inclusion proofs, consistency proofs, offline
verification. Anchoring is a pluggable one-liner — WORM store, RFC 3161
timestamp authority, an internal notary, or a public chain if a client insists
on the word. The architecture never depends on it.

There is also a credibility argument. "Transparency log, the construction that
secures certificate issuance on the public web" is a language a PKI team
already trusts. "Blockchain" makes you the tenth vendor.

## Decision — stack

The core language and the UI language are two decisions. Treating them as one
is how Rust-versus-Blazor becomes a false choice.

**Rust for the control plane.** One static binary, megabyte container, no
runtime to install air-gapped. Memory safety is not a preference in a component
whose job is gating privileged actions. Mature crypto and TLS, and real
libraries for namespaces, seccomp and eBPF, which is where primitive 05 lives.
Cost: smaller contributor pool, slower first quarter.

**Go is the honest alternative.** Most of the deployment story, a larger
contributor pool, and the ecosystem you would otherwise reimplement — policy
engines, container runtimes, telemetry, transparency logs — is already
Go-native. Cost: a GC in the hot path, and a weaker answer when a CISO asks why
they should trust the gatekeeper.

**C# is not the core, and the .NET advantage is still worth capturing.** In a
.NET bank or pharma, a codebase the client's own team can read and extend is a
real sales advantage. That belongs in a first-class C# SDK. As the core it pulls
the whole runtime into the container and makes an OSS-first project an island.

**Verdict.** Rust control plane, one binary, serving a static web console — no
second process. Agnosticism lives in the SDKs: Python and TypeScript first
because that is where agent authors are, then C# and Go. A .NET shop that wants
a Blazor console builds it against the same API, which is the correct proof that
the API is the product.

## Agnosticism — six axes and their seams

Agnosticism is cheap to claim and expensive to keep. Each axis needs a named
seam and a conformance test in CI, or it decays into "works with one provider,
compiles with the others."

- **Model provider** — one gateway, adapters behind it. Seam is a normalised
  call event. Test: same run against three providers, three byte-comparable
  ledger shapes.
- **Air-gapped** — the hardest constraint and the one that disciplines the
  rest. No phone-home, no hosted control plane, no licence check, no CDN font.
  Test: full suite with an empty network namespace.
- **Cloud or bare metal** — Compose for a laptop, Helm for a cluster, same
  binary. Storage and secrets behind interfaces with filesystem+SQLite
  defaults.
- **Target tech stack** — a sensor is a container plus a contract that emits a
  verdict and a fix-naming message. Whether it is pytest, clippy or ArchUnit is
  the workload's business.
- **Agent framework** — two integration depths. Shallow: point any harness at
  the gateway and broker, inherit 04, 05, 11, 12. Deep: use the orchestrator
  and state store, get 06 through 10.
- **Identity** — OIDC for human approvers so approvals carry a directory
  identity. Local accounts for air-gapped and solo cases. An approval without a
  resolvable identity is not an approval, and the ledger records which kind it
  was.

## Settled

- **Governance in the open repo.** Evidence mappings ship — control crosswalks,
  which events satisfy which control. Interpretation and attestation stay as
  the service.
- **Sandbox floor.** `laptop` is the default and needs no nested
  virtualisation. Real OCI containment, scores 3 not 4, says so.
- **Scorer.** Built in, and the scoring rules ship as data so a third party can
  re-run them against an exported ledger and reach the same twelve numbers
  without trusting the binary. Without that, self-scoring is marketing.
- **Attribution.** Both sources credited in the README above the architecture:
  the twelve-primitive decomposition, and Böckeler's guide/sensor taxonomy
  (martinfowler.com, April 2026).

## Still open

- **Name collision.** Gantry is also a long-running Joomla template framework.
  Check crates.io and npm before publishing a package name. Keel and Ratchet
  are the fallbacks.
- **Audit crew scope.** The proving workload needs a boundary or it becomes a
  security product. Proposal: secrets, dependency provenance and
  authorisation-boundary findings only. No SAST engine, no rule authoring, no
  dashboard.
