# Gantry — bootstrap handoff

Target repo: **https://github.com/Mariano215/gantry** (currently empty)

## What this package is

A seed for a Claude Code session that will build Gantry from nothing. It is a
**specification and instruction bundle, not source code and not a UI design
handoff.** Nothing here should be copied into the repo unchanged except the
files explicitly marked as repo seeds below.

The design artifact from the concept phase (`Agentic Platform Concept.dc.html`)
is a reasoning document. It records what was decided and why. It is not a mock
of the product UI and there is no UI to recreate yet.

## What Gantry is, in one paragraph

An LLM-agnostic, cloud-agnostic control plane for agentic engineering, shipped
as a container. It implements the twelve-primitive harness model as running
services so that a team inherits verification, observability and governance on
the day they install it rather than building those three layers themselves and
failing. It scores its own installation against the rubric continuously, from
real telemetry, with every score linked to evidence in a signed append-only
ledger.

## Repo seeds — copy these in as the first commit

| File | Lands at | Why first |
|---|---|---|
| `seed/CLAUDE.md` | `CLAUDE.md` | Primitive 01. The project cannot preach instruction packs and have none. |
| `seed/settings.json` | `.claude/settings.json` | Primitive 12. Declared authority from commit one, tracked, not local. |
| `seed/commands/proof.md` | `.claude/commands/proof.md` | Primitive 09. Every slice ends in a proof document; that should be a command, not a habit. |
| `docs/*.md` | `docs/` | The specification set. |

## Reference set — read, do not copy

| File | What it is |
|---|---|
| `docs/PRIMITIVES.md` | The twelve-primitive rubric. Canonical. Not authored by this session. |
| `docs/HARNESS-ENGINEERING.md` | Böckeler's taxonomy plus the integration work. Canonical. |
| `docs/CONCEPT.md` | Architecture decisions and their reasoning. |
| `docs/PLAN.md` | Nine slices, each ending in an adversarial proof. |
| `docs/EVENT-SCHEMA.md` | Slice 00. Everything downstream consumes this. |
| `docs/CLAUDE-CODE-INTEGRATION.md` | Which Claude Code extension point carries which primitive. |
| `Agentic Platform Concept.dc.html` | The concept document as designed. Open in a browser. |

## Where to start

Read `docs/CONCEPT.md`, then `docs/PLAN.md`, then `docs/EVENT-SCHEMA.md`.
Then do slice 00 — settle the event schema and the policy schema and nothing
else. Resist writing the ledger until the schema has survived being written
out by hand for one real agent run.

Two open decisions are recorded at the end of `docs/CONCEPT.md`. Neither
blocks slice 00.
