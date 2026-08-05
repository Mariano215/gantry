# Claude Code as the first client

This changes the shape of v0. A coding agent with a hook system, an MCP client,
a permission model and an instruction file already exposes an extension point
for most of the twelve. Gantry does not need to be an agent runtime to deliver
the `laptop` profile — it needs to sit in those sockets and write to the
ledger. Weeks, not months, and the user changes no tools.

**Verify specifics against current documentation before building.** Extension
surfaces move. The mapping below is the shape, not the API.

## Socket map

| Socket | Primitives | What Gantry puts there |
|---|---|---|
| `CLAUDE.md` / `AGENTS.md` | 01 | Generated from a version-controlled instruction pack, with the checker that fails the build when a rule it declares is violated in the diff. The file stops being hand-edited prose. |
| Pre-tool hook | 04 · 07 · 12 | The policy decision — allow, deny, hold for approval — against declared authority. Decision, rule that fired and identity in force land in the ledger before the call proceeds. |
| Post-tool hook | 10 · 11 | Sensor dispatch. Fast computational sensors run here; verdicts return as fix-naming messages the agent acts on, not a wall of failing output. |
| MCP servers | 04 · 05 | Gantry registers as one server proxying the rest, so every tool passes the schema registry and credential broker. Existing MCP tools work unmodified — the point of not inventing a protocol. |
| Session start / end hooks | 06 · 11 | Open and seal the run. Restore plan and checkpoint on start; write the signed run summary on end, so a session has a beginning and an end an auditor can point at. |
| Skills / slash commands | 09 | Signed skill packages installed into the directory the agent already reads, with the resolver that refuses invalid metadata instead of falling back to a title. |
| Subagent definitions | 08 | Roles with narrowed tools and a per-role policy, so a delegated agent inherits less authority than its parent rather than the same. |
| Settings / permissions | 05 · 12 | Declared in version control and diffed against what is actually loaded. This is the drift check, and it is the exact failure from the rubric's worked example. |

## The honest limitation

**A hook is an enforcement point, not a security boundary.** A user who edits
their own settings can remove it, so hooks alone cannot carry primitive 05 —
that is what the sandbox and the egress namespace are for.

What hooks *can* do is make removal visible. The settings hash goes into every
run's opening event and `seq` is monotonic within a run, so a harness switched
off mid-run leaves a dated gap in the record. Detection rather than prevention,
and it must be labelled that way in the score. Anyone claiming hook-based
"enforcement" as a security control is wrong, and saying so plainly is a
differentiator.

## The onboarding wedge

Nobody installs a control plane. They will run a scan on their own repo and
argue with the score.

| Command | State | What it does |
|---|---|---|
| `gantry scan <repo-dir>` | Built, slice 16 | Reads what is already there: instruction files, hooks, test gates, declared permissions, MCP config, CI. Scores twelve primitives with a file path or an explicit "looked in X and Y, found nothing" behind every number, and lists the `[UNENFORCED]` markers the repository's own rule file carries. Read-only, offline, no account. See `docs/proof/16.md`. |
| `gantry apply` | Not built | Would scaffold missing layers as a reviewable diff, never a silent write, ranked by the rubric's remediation order. No subcommand exists. |
| `gantry up` | Not built | Would bring up ledger, broker and sandbox on the `laptop` profile, so the scan stops being a snapshot and becomes live telemetry. No subcommand exists. The pieces run today as separate commands (`gantry broker`, `gantry console`, `gantry score`); nothing composes them. |
| `gantry ledger verify` | Built, slice 01 | Checks the ledger offline. `gantry score <ledger-dir>` re-runs the published scoring rules against it. Anyone can run both against an exported ledger they were handed. |

`gantry scan` is the growth engine, not `gantry up`. It was built first.

### What the scan's number means, and what it does not

The scan reads files, so it measures the presence of a control, never the
control running. It resolves three states per primitive: absent (0), an
artifact with nothing enforcing it (2), and an artifact a check file names (3).
It awards no 1, because a habit with no artifact leaves nothing in a tree to
read; no 4 or 5, because `docs/PRIMITIVES.md` anchor 4 is enforcement by the
system rather than by discipline, and a file only says a check is wired; and no
N/A, because a tree does not show which primitives the workload exercises.

`gantry score` is the other number and it reads a ledger. Every predicate in
`config/scoring.json` is a statement about events that happened, which is why
it is the only one of the two that can award 4. The two are not averaged. The
static scan under-reads a running system, since a recorder is runtime state and
primitive 11 can read 0 on disk while telemetry reads 3, and it can over-read a
dead one, since a check file naming a check says the check is wired and not
that it works. Where they disagree, the telemetry number measured something
running.

## Build Gantry under Gantry

Point it at its own repo the week slice 01 can run at all. Every proof document
then gets written from a real ledger instead of assembled by hand, and the
launch score is a byproduct of construction rather than an exercise.

The rubric's worked example shows the shape: the CI added to catch mistakes
caught its author's mistakes within minutes of existing. That is the note to
launch on.
