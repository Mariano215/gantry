# Kickoff prompt

There is no live link between the design session and your working copy. The
sync is manual and takes a minute:

```
git clone https://github.com/Mariano215/gantry.git
cd gantry
# unzip the handoff package into ./handoff_gantry
cp handoff_gantry/seed/CLAUDE.md ./CLAUDE.md
mkdir -p .claude/commands && cp handoff_gantry/seed/settings.json .claude/settings.json
cp handoff_gantry/seed/commands/proof.md .claude/commands/proof.md
mkdir -p docs && cp handoff_gantry/docs/*.md docs/
claude
```

Then paste this as the first message:

---

Read CLAUDE.md, then docs/CONCEPT.md, docs/PLAN.md, docs/EVENT-SCHEMA.md,
docs/CLAUDE-CODE-INTEGRATION.md. docs/PRIMITIVES.md and
docs/HARNESS-ENGINEERING.md are canonical reference — read them, do not edit
them.

This repo is empty. We are building Gantry: an LLM-agnostic control plane that
implements the twelve harness primitives as running services, ships as a
container, and scores its own installation from real telemetry.

Do slice 00 only, and nothing else.

Slice 00 is two schemas and one hand-written trace. Specifically:

1. Review docs/EVENT-SCHEMA.md critically and tell me where it is wrong before
   you accept it. I want the disagreements, not a summary.
2. Draft docs/POLICY-SCHEMA.md to the same standard — authority as code,
   evaluable per tool call, diffable against what is actually running. It must
   express the trust-budget rungs and the three profiles from docs/CONCEPT.md.
3. Write docs/proof/00.md using the /proof command: a real agent run,
   hand-written entirely in the event schema, that I can reconstruct without
   you. Pick a run that exercises a denial and an approval, not a happy path.

Do not write Rust. Do not create a cargo project. Do not scaffold directories
beyond docs/. If the schema cannot be written out by hand for a real run, that
is the finding and I want to hear it now rather than after the ledger exists.

Two things are still open and neither blocks this slice: the name collision
check, and the audit-crew scope boundary. Both are recorded at the end of
docs/CONCEPT.md.

---

## After slice 00

Same shape each time. Name the slice, forbid the next one, demand the
adversarial proof:

```
Slice 00 is closed — docs/proof/00.md exists and I have read it.

Do slice 01 only: the evidence ledger. Append-only Merkle log, signed tree
heads, inclusion and consistency proofs, offline verifier. Rust, one crate.

The proof is not "the ledger works". Edit one byte of one historical record and
show me the verifier naming the entry and the divergence point. Then verify a
single event's inclusion offline given nothing but the event and a signed head.

Add ci/ledger-append-only while you are here — CLAUDE.md claims it enforces the
append-only invariant and right now that claim is false.
```

That last paragraph is the pattern worth keeping. CLAUDE.md names an enforcing
check for every rule it states, and several of them do not exist yet. Each
slice should close the gap between what that file claims and what is true,
because a guide with nothing checking it caps the project at maturity 3 — which
is the whole thesis.
