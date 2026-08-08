# The Twelve-Primitive Agent Harness Maturity Rubric

A condensation, deliberately lossy, written for this scanner's ceiling argument
and self-contained so an offline build needs nothing else. The canonical text is
the Agent Harness Maturity Specification,
https://github.com/Mariano215/agent-harness-maturity/blob/main/SPEC.md. What to
build to reach a level, rather than what a level means, lives in harness-kit,
https://github.com/Mariano215/harness-kit.

Last reconciled against harness-kit contracts 0.1.0 · spec 0.1.0-draft.

## The core claim

**Agent = Model + Harness.** The model is one part of the machine. Reliability,
trust and governance live in the harness built around it. When an agent fails,
the useful question is not "which model" but "which layer of the harness ran
out of road."

The framework decomposes a harness into twelve primitives. Each exists because
the one before it hit a wall: instructions are passive, so context must be
delivered; delivered context floods the window, so it must be managed; and so
on up to the trust layer, where most organizations are thinnest.

Twelve is one practitioner's decomposition, not an industry standard. It could
be nine or fifteen. What survives scrutiny is the ordering logic and the
trust-layer conclusion. Concede the arbitrariness if challenged; the concession
builds credibility.

## How to score

Score each primitive 0 to 5 against the anchors below. For every score, record
concrete evidence: a file path, a quote, a config value, or an explicit "no
evidence found, looked in X and Y." A score without evidence is an opinion.

Three rules that change the arithmetic:

1. **A primitive the workload never exercises scores N/A**, never 5 and never
   0. Absence of a need is not maturity, and it is not a gap.
2. **The overall level is the minimum across applicable primitives, not an
   average.** A system is as governed as its weakest layer. Averaging is how a
   missing trust layer hides behind nine strong ones.
3. **A primitive carried only by guides caps at 3.** See the control-type
   section below. Anchor 4 requires enforcement by the system rather than by
   discipline, and a rule with nothing checking it is discipline.

### Maturity anchors

- **0 Absent.** No evidence the primitive exists.
- **1 Ad hoc.** Exists informally. Depends on one person's habits. No artifact
  to inspect.
- **2 Partial.** An artifact exists but is not enforced or not applied
  consistently. Tests exist, nothing gates on them.
- **3 Defined.** Documented, consistently applied, someone owns it.
- **4 Managed.** Enforced by the system rather than by discipline. Violations
  are caught mechanically.
- **5 Compounding.** Failures feed back into the harness. A miss becomes a
  retrieval rule, a dangerous command becomes a gate, a correction becomes
  memory, a repeated workflow becomes a skill. The next run starts from a
  better place.

Level 5 is rare and is the honest differentiator. Most shops, including good
ones, sit at 1 to 2 on the trust layer. Saying so in a report is credible
precisely because it includes the reviewer.

## Control type: guides and sensors

Every primitive is carried by guides, by sensors, or by both. This axis is
drawn from Böckeler (see the companion document) and it is what makes anchor 4
testable rather than intuitive.

- A **guide** is feedforward. It steers before the agent acts: an instruction
  file, a tool schema, a policy, a captured procedure.
- A **sensor** is feedback. It observes after the agent acts and lets it
  self-correct: a test, a linter, a hook, a trace, an approval record. A
  sensor's message must name the fix, not merely report a failure, because an
  agent reads that message and acts on it.
- Sensors are **computational** (deterministic, cheap, run on every change) or
  **inferential** (LLM judgment, slow, reserved for checkpoints).

The test to apply at every layer: *show me what breaks when someone ignores
this rule.* If nothing breaks, it is a 3.

## The twelve primitives

### 01 Instruction

**What it is:** who the agent is, the work, the tone, constraints, coding and
review rules. Moves repeated guidance out of the conversation and into the
environment.
**Control type:** guide only. The sensor is a review process on instruction
changes; without one this caps at 3.
**Evidence:** system prompts, instruction files (CLAUDE.md, AGENTS.md, cursor
rules), prompt version history, the review process for prompt changes.
**Strong looks like:** instructions versioned and reviewed like production
code.
**Common gap:** prompts edited live in a dashboard with no history. Nobody can
say what the agent's instructions were last Tuesday.
**Limit it hits:** instructions are passive. They can say "follow convention"
but cannot discover it.

### 02 Context delivery

**What it is:** handing the model the actual material. The relevant file, the
failing test, the stack trace, the logs.
**Control type:** guide (what material each task type gets) plus computational
sensor (did the referenced material actually reach the prompt).
**Evidence:** file-reference mechanisms, retrieval hooks, how a task's inputs
reach the prompt.
**Strong looks like:** every task type has a defined set of material that
reaches the model.
**Common gap:** the agent is asked about systems it has never been shown, and
the resulting hallucination is blamed on the model.
**Limit it hits:** dumping everything in floods the window.

### 03 Context management

**What it is:** deciding what enters the model right now. Retrieval, reranking,
summaries, compaction, caches, and structural or semantic knowledge graphs
(dependency maps, call graphs, cross-document relationship graphs).
**Control type:** guide (budget and selection policy) plus computational sensor
(window accounting, staleness expiry).
**Evidence:** retrieval config, summarization steps, window budgets, cache
strategy, a queryable graph over the corpus.
**Strong looks like:** deliberate selection against a stated budget, with stale
material expired.
**Common gap:** entire wikis stuffed into every prompt. Wrong context is worse
than missing context: it is a plausible distraction that fails confidently.

### 04 Tool interface

**What it is:** structured calls with a name, a description and a schema. The
model requests an action instead of describing one.
**Control type:** guide (the schema) plus computational sensor (input
validation, and treating tool output as untrusted).
**Evidence:** tool definitions, schema strictness, input validation, how tool
results are treated.
**Strong looks like:** tight schemas, validated inputs, tool output treated as
untrusted data.
**Common gap:** vague schemas ("run any shell command"), and tool results piped
straight into decisions without validation.

### 05 Execution environment

**What it is:** where commands run and with what access. Filesystem scope,
network policy, credentials, sandboxing.
**Control type:** sensor-dominant and computational. A permission written into
a policy file but not enforced by the sandbox is a guide pretending to be a
control.
**Evidence:** container or sandbox config, permission model, secrets handling,
network egress rules.
**Strong looks like:** the model cannot reach secrets even if it tries. Policy
lives in architecture, not in a polite instruction.
**Common gap:** the agent runs with the developer's full credentials on the
host machine. **Score gaps here with security-finding severity.**

### 06 Durable state

**What it is:** the workbench that survives the turn. Plan files, checkpoints,
task state, session summaries, memory stores, a persisted graph of the corpus.
**Control type:** computational sensor. State either survives a restart or it
does not, and that is testable.
**Evidence:** state files, checkpoint logic, what survives a crash, a graph the
agent can traverse instead of re-reading the corpus.
**Strong looks like:** progress inspectable outside the model's attention. A
crash costs minutes, not the session.
**Common gap:** everything lives in the conversation. Every session starts from
zero.

### 07 Orchestration

**What it is:** how the work moves. Lifecycle hooks, retries, approval gates,
human hand-offs, step ordering, routing.
**Control type:** guide (the defined lifecycle) plus computational sensor (the
gate that actually blocks).
**Evidence:** hook config, retry policy, gate definitions, escalation paths.
**Strong looks like:** a defined lifecycle with human gates at irreversible
steps.
**Common gap:** one loop that either succeeds or dies. A human finds out from
the output, or never.

### 08 Sub-agents

**What it is:** work split into specialists with narrow jobs, narrow context
and narrow tools.
**Control type:** guide (role and scope definitions) plus inferential sensor
(whether returned work meets the parent's brief).
**Evidence:** delegation patterns, agent role definitions, how results return
to the parent.
**Strong looks like:** bounded specialists whose scope matches the split in the
work itself.
**Common gap:** either one agent does everything, or a swarm exists for show
with no consistency across members. A single-purpose tool that never needs
delegation scores N/A here, not 0.

### 09 Skills

**What it is:** reusable procedures loaded at the right time. When to use,
what inputs, what steps, which tools.
**Control type:** guide only, by construction. What lifts skills above 3 is a
sensor that fires when one is skipped or when its referenced steps stop
resolving.
**Evidence:** skill or playbook files, slash commands, runbooks, how repeated
workflows are captured.
**Strong looks like:** repeated expertise named and callable. New team members,
human or agent, inherit it.
**Common gap:** process lives in one person's head or one old thread.

### 10 Verification (trust layer)

**What it is:** the agent says "done," the harness says "show me." Tests,
builds, type checks, screenshots, evals.
**Control type:** sensor by definition, both kinds. Computational gates run on
every change; inferential review is reserved for checkpoints. **Verification
that never blocks anything is a 2.**
**Evidence:** what gates a result before it ships, and whether confidence alone
can pass.
**Strong looks like:** no output reaches a user or client without passing a
check the model cannot fake.
**Common gap:** the final sentence is trusted because it sounds confident. This
is the most common and most silent failure in the field.

### 11 Observability (trust layer)

**What it is:** the recorder for the run. Traces, tool-call timelines, cost,
latency, prompt versions, approval events.
**Control type:** sensor with no guide. Nothing steers it. Either the run was
recorded or it was not.
**Evidence:** trace storage, replay ability, cost attribution, what an incident
review can actually reconstruct.
**Strong looks like:** any failure traceable to the call where it started. "The
agent messed up" becomes a debuggable ticket.
**Common gap:** infrastructure monitoring (service up, CPU fine) mistaken for
agent observability (what the model saw, which tools ran, who approved).
**N/A:** never. Any system that makes a model call can record that call. A
system with no record scores 0.

### 12 Governance (trust layer)

**What it is:** who the agent acts as, what it is authorized to do, under which
policy, with which approvals, and the record that proves it.
**Control type:** guide (the declared policy and scope) plus sensor (the
approval record, and a drift check that reports when the running system differs
from the declaration).
**Evidence:** identity and credential scoping for the agent, an authorization
policy someone owns, approval gates on irreversible or regulated actions,
retention of the approval record, and the mapping from that record to whatever
regime applies.
**Strong looks like:** the agent's authority is declared in a reviewable
artifact rather than inherited from whoever set the machine up, and every
privileged action leaves a record an auditor can read without the engineer
present.
**Common gap:** the authority is real but undeclared. A permission mode, a
service account or an API scope lives in someone's local config, nobody wrote
down what the agent may do, and no check reports when the running system
differs from the stated policy.
**N/A condition:** only when the agent acts on nothing outside its own process,
holds no identity, and touches no regulated or personal data. A read-only local
tool can qualify. Anything with write access to a shared system does not.
**Limit it hits:** governance is the primitive every compliance mapping runs
through. A gap here does not stay technical; it becomes the finding an auditor
writes.

## Grouping, for presentation

Do not grind through all twelve in a pitch. Name the groups and slow down only
on trust.

| Group | Primitives | What the group answers |
|---|---|---|
| Knowing | 01 to 03 | Does the model have the right material in front of it, and only that? |
| Acting | 04 to 05 | Can it do things, and is what it can reach actually bounded? |
| Continuity | 06 to 07 | Does work survive the turn, and does anything gate the irreversible steps? |
| Scaling | 08 to 09 | Is the work split sensibly, and is repeated expertise captured? |
| Trust | 10 to 12 | Can it prove it is done, can you reconstruct what happened, and can you say under whose authority it acted? |

## Harnessability

Not every system can carry the same harness, and remediation cost depends on
it. Strongly-typed languages afford type-checking sensors a dynamic codebase
cannot have cheaply. Clear module boundaries afford architectural fitness
functions. A conventional framework reduces the space of things the agent might
invent, which is what makes a small set of controls sufficient. Legacy systems
face the paradox directly: the harness is most needed exactly where it is
hardest to build.

Use harnessability to qualify remediation cost in a report, not to move a
score. A 2 is a 2 whether it is cheap or expensive to lift; harnessability
tells the reader which one they are buying.

## Ranking gaps

Rank by business risk first:

- Verification (10), observability (11) and governance (12) gaps outrank
  everything for regulated or client-facing work. Capability without trust is a
  liability.
- Execution environment (05) gaps are security findings and carry
  security-finding severity.
- A missing primitive the workload never exercises is a note, not a gap.

Where business risk is comparable, break the tie with this remediation order,
derived from an ablation finding that gains localize to tools, middleware and
long-term memory rather than to the system prompt:

1. Tool interface
2. Context management
3. Durable state
4. Orchestration
5. Instruction

Execution environment is exempt from this ordering. Its gaps are sequenced by
severity, not by expected gain.

For each remediation, also say **where in the lifecycle** the control belongs:
a fast pre-integration check that runs on every change, an expensive
post-integration check at a checkpoint, or continuous background drift
detection. A gap list is a complaint; a gap list with placement is a plan
someone can staff.

## The diagnostic question

When any agent failure is described, walk the chain instead of blaming the
model. Was the instruction missing, the context wrong, the schema vague, the
environment open, the state lost, the orchestration absent, the work
undelegated, the skill missing, the verification skipped, the trace
unavailable, the authority undeclared? And did the system learn anything from
the last failure? The layer that ran out of road is the finding.

One follow-up sharpens it: for whichever layer failed, was it carried by a
guide, by a sensor, or by both? A layer that failed with a guide and no sensor
did not fail unexpectedly. Nothing was ever going to catch it.
