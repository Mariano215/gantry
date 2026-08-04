# Harness Engineering: the paper, and how it joins the twelve primitives

Companion to the twelve-primitive rubric. Self-contained.

**Source:** Böckeler, Birgitta. "Harness Engineering for Coding Agent Users."
martinfowler.com, 02 April 2026.
https://martinfowler.com/articles/harness-engineering.html

Everything in Part 1 is hers. Everything in Part 2 and Part 3 is integration
work: the join between her taxonomy and the twelve-primitive coverage model,
and a worked example of applying both.

---

# Part 1: The paper

## Thesis

To let coding agents operate with less human supervision, you build systematic
control mechanisms around them. A harness combines anticipatory guidance with
continuous feedback. Harness quality, not model quality, decides how much
supervision can safely be removed.

The pressure is simple: an agent produces faster than a person can check.
Review was always the bottleneck, and an agent moves the bottleneck from
writing to checking. A human reading every diff does not scale.

## Guides and sensors

Two complementary control mechanisms.

**Guides are feedforward.** They anticipate the agent's behaviour and steer it
*before* it acts. Documentation, rules, schemas, executable constraints.

**Sensors are feedback.** They observe *after* the agent acts and help it
self-correct. Their signal should be optimized for LLM consumption: a linter
message that says what to change, not merely that something failed. The agent
reads that message and acts on it.

The two failure modes, and this is the load-bearing part of the paper:

- **Feedback-only systems produce repetitive failures.** The agent makes the
  same mistake, gets corrected, makes it again. Nothing accumulates.
- **Feedforward-only systems encode rules without validating effectiveness.**
  You write standards nobody checks. They go stale, then start actively
  misleading. This one is worse in practice, because documentation looks like
  coverage.

## Computational and inferential controls

**Computational controls** are deterministic, fast (milliseconds to seconds),
CPU-based. Tests, linters, type checkers, structural analysis. Reliable, but
limited to structural validation.

**Inferential controls** use LLMs or specialized models for semantic judgment.
Slower, more expensive, non-deterministic, but capable of contextual judgment a
linter cannot reach: is this test meaningful, is this over-engineered. Code
review agents and LLM-as-judge patterns.

The practical strategy: computational controls on every change, inferential
controls reserved for expensive checkpoints.

## The steering loop

Humans iteratively improve the harness based on observed failures. When an
issue recurs, the feedforward and feedback mechanisms need enhancement, not the
instance. In Böckeler's words, the human's job is to **steer** the agent by
iterating on the harness.

AI can help build the harness itself: generating structural tests, synthesizing
rules from observed patterns, scaffolding custom linters.

## Keep quality left

Controls distribute across the lifecycle by cost and speed, following
continuous integration principles.

- **Pre-integration** (fast, frequent): linters, basic test suites, initial
  code review agents.
- **Post-integration** (expensive, selective): mutation testing, full
  architecture reviews.
- **Continuous background monitoring** (drift detection): dead code analysis,
  test quality assessment, dependency scanning, runtime SLO degradation.

Push expensive sensors rightward; keep fast feedback loops early.

## Three regulation categories

Harnesses regulate toward different desired states.

**Maintainability harness.** Internal code quality. The most mature category
today. Computational sensors reliably detect duplicate code, cyclomatic
complexity, coverage gaps, architectural drift, style violations. Inferential
sensors partially address redundant tests and over-engineering, unreliably.
Significant gaps remain on the higher-impact problems: misdiagnosis,
over-engineering, misunderstood requirements.

**Architecture fitness harness.** Enforces architecture characteristics via
fitness functions. Skills describing performance requirements paired with
performance tests; logging standards paired with debugging instructions that
prompt the agent to reflect on observability quality.

**Behaviour harness.** Functional correctness. Böckeler calls this the elephant
in the room, and says plainly that mature solutions do not exist. Current
practice relies on feedforward specifications plus feedback from AI-generated
test suites and manual testing, which remains insufficient. Approved fixtures
show promise selectively. Her conclusion: "we still have a lot to do to figure
out good harnesses for functional behaviour."

This matters for reporting. A low behaviour score is a statement about the
state of the art as much as about the system under review.

## Harnessability and ambient affordances

Not all codebases support equivalent harnesses. Strongly-typed languages afford
type-checking sensors. Clearly-defined module boundaries enable architectural
constraints. Frameworks reduce agent uncertainty. Legacy systems face the
paradox that harnesses are most needed where they are hardest to build.

**Ambient affordances** are the structural properties of the environment that
make it legible, navigable and tractable to agents. Greenfield teams can embed
harnessability decisions early; legacy teams must retrofit into degraded
codebases.

## Harness templates

Service topology codification extends to bundled guides and sensors for common
architectural patterns: CRUD business services, event processors, data
dashboards. Technology and architecture choices determine which harnesses are
available, which can in turn drive tool selection. Templates face
synchronization problems as teams customize them; version management and
contribution processes remain unsolved.

## Ashby's law

Ashby's Law of Requisite Variety: a regulator must possess complexity matching
the system it regulates. LLM agents can generate nearly anything, so committing
to predefined topologies reduces output variety and makes full coverage
achievable with a smaller set of controls. Standardization is not bureaucracy
here; it is variety reduction, and it is what lets a modest harness suffice.

## The role of the human

Experienced developers function as an implicit harness: absorbed conventions,
intuitive complexity aversion, organizational alignment, paced deliberation.
Agents lack social accountability, aesthetic judgment, contextual intuition and
organizational memory. They cannot distinguish load-bearing conventions from
habits, or weigh trade-offs against team goals.

Her framing: "A good harness should not necessarily aim to fully eliminate
human input, but to direct it to where our input is most important." Harnesses
externalize human experience but have limits. They optimize where human effort
is spent rather than removing the need for it.

## Open questions she names

- Keeping harnesses coherent as guides and sensors multiply, and preventing
  contradictory signals.
- Evaluating harness coverage and quality, analogous to code coverage.
- Whether silent sensors indicate high quality or inadequate detection.
- Coordinating controls scattered across delivery pipelines as one system.
- Trusting agents to navigate trade-offs when instructions conflict.

Emerging practices she cites: layered architecture with custom linters and
drift scanning, pre-push hooks with heuristic linter triggering, increased LSP
integration, and "janitor army" patterns combining agents with custom linters.

---

# Part 2: The integration

## Where her framework stops

The paper classifies *kinds* of control: feedforward or feedback, computational
or inferential, early or late. That taxonomy is genuinely useful and it answers
a question the twelve-primitive rubric never asked.

What it does not provide is a **coverage model**. After reading it you still
cannot answer "what are the parts of a harness, and which one is missing here?"
There is no enumeration, no scoring, no way to hand a client a number. She names
this as an open question herself: evaluating harness coverage remains unsolved.

The twelve primitives are exactly that missing piece. The two compose cleanly
because they answer different questions.

| | Question answered |
|---|---|
| Böckeler's taxonomy | What *kind* of control is this, and when does it run? |
| Twelve primitives | What must be *covered*, and which layer ran out of road? |

## The join

Her axis is laid over the twelve layers. For each primitive, ask what kind of
control carries it.

| # | Primitive | Carried by | Note |
|---|---|---|---|
| 01 | Instruction | Guide | Pure feedforward. Caps at 3 unless something reviews or tests the instructions. |
| 02 | Context delivery | Guide + sensor | Rules about what a task gets, plus a check that it arrived. |
| 03 | Context management | Guide + sensor | A stated budget, plus accounting against it. |
| 04 | Tool interface | Guide + computational sensor | The schema steers; input validation catches. |
| 05 | Execution environment | Sensor (computational) | A permission in a doc but unenforced by the sandbox is a guide wearing a badge. |
| 06 | Durable state | Sensor (computational) | State survives a restart or it does not. Testable, so test it. |
| 07 | Orchestration | Guide + sensor | A defined lifecycle, plus a gate that actually blocks. |
| 08 | Sub-agents | Guide + inferential sensor | Role definitions steer; judging whether returned work met the brief needs judgment. |
| 09 | Skills | Guide | Guide by construction. Rises above 3 only when something fires if a skill is skipped or its steps stop resolving. |
| 10 | Verification | Sensor, both kinds | Sensor by definition. Verification that never blocks anything is a 2. |
| 11 | Observability | Sensor, no guide | The one layer with no feedforward component. Either the run was recorded or it was not. |
| 12 | Governance | Guide + sensor | Declared policy, plus the approval record and a drift check that the declaration still matches reality. |

## The rule this produces

**A layer carried only by guides caps at 3 out of 5.**

The maturity scale already said level 4 means "enforced by the system rather
than by discipline." That was a judgment call a reviewer had to make. The
control-type question turns it into a test anyone can apply:

> Show me what breaks when someone ignores this rule. If nothing breaks, it is
> a 3.

This is the most common real-world finding, including at well-run
organizations: excellent written standards, and nothing that fails when they
are violated. Naming it as a structural property rather than a discipline
problem reframes the finding from blame to design, which is also what makes it
land in a client conversation.

## What the integration deliberately does not add

- **No thirteenth primitive.** Ashby's law is already the topology-commitment
  argument inside the framework, and the steering loop is anchor 5
  (Compounding) restated. Cite them in prose; do not re-encode them as scores.
- **No harness-template scoring.** Böckeler names templates as an unsolved
  problem. Scoring against an unsolved practice produces noise.
- **No change to the twelve.** Her material is an axis over them, not a
  competing decomposition.

## How to run a review with both

1. **Walk the chain.** Which layer ran out of road? Use the diagnostic question
   from the rubric.
2. **Ask the control-type question for that layer.** Guide, sensor, or both. A
   layer that failed with a guide and no sensor did not fail unexpectedly.
3. **Score with the cap rule applied**, N/A where a workload never exercises a
   layer, overall level as the minimum rather than the average.
4. **Name the regulation category** under review: maintainability, architecture
   fitness, or behaviour. Behaviour harnesses are immature industry-wide, which
   is what makes a low score there credible rather than an accusation.
5. **Rank by business risk**, break ties with the remediation order, and place
   each remediation in the lifecycle: pre-integration, post-integration, or
   continuous drift detection.

Step 5 is what turns a gap list into a plan someone can staff.

---

# Part 3: Worked example

The framework applied to the reviewer's own agent harness, an internal system
that composes agent configuration across several machines. Included because a
self-audit with a published low score is more persuasive than a client case
study, and because every finding below was silent.

## Starting position

The harness was squarely in the feedforward-only failure mode. Extensive
guides: hundreds of lines of coding standards, roughly thirty captured skills,
instruction files in every repository, a routing table. Almost no sensors. And
several guides had gone false without anyone noticing. The main contributor
guide instructed the reader to run two scripts that had not existed for weeks;
anyone following it failed with no way to learn why.

The proof that the steering loop had never been run: two separate commits
existed whose entire content was adding the same missing one-character fix.
Same defect, repaired by hand, twice, with nothing added to prevent a third.

## Four silent failures

None produced an error message. This is the point: the dangerous failure is not
the loud one.

1. **A sensor that could not fail.** The check for leaked personal data
   swallowed its own errors and reported clean while searching nothing. Once
   corrected it found eight hits immediately.
2. **Undeclared authority.** The agent ran under a permission setting that
   lived only in an untracked local file, while the tracked configuration
   claimed something else. The existing check confirmed the value was legal,
   never that anyone had chosen it. A textbook governance gap: real authority,
   undeclared.
3. **A capability routing on nothing.** One skill's metadata block was invalid,
   so the parser dropped it and the system fell back to reading its title. It
   had been picking up work by accident for weeks.
4. **A loop that depended on English.** The self-healing step decided whether
   anything had changed by reading a tool's human-readable output. Under any
   other locale setting, the only closed loop in the system stops silently.

## Scores

| Layer | Before | After | Why it moved |
|---|---|---|---|
| 01 Instruction | 2 | 4 | Guide rewritten, and a checker now fails the build when a rule in it is violated. |
| 10 Verification | 1 | 4 | No pre-integration checks existed, and three correct checkers sat in the repository invoked by nothing. Now one gate, run locally and in CI, which found four real defects on its first run. |
| 11 Observability | 1 | 2 | The operation that rewrites the whole configuration left no record of what it changed. It writes a log now, but only on one of the two paths that invoke it. |
| 12 Governance | 1 | 4 | Authority now declared in version control, with a drift check that reports, and names the fix, when the running system differs from the declaration. |

**Overall level moved from 1 to 2.** Three layers jumped to 4 and the headline
barely shifted, because the overall score is the minimum and observability is
still the floor. An organization scoring itself on averages would have claimed
3.5 and shipped a press release.

That gap between the component scores and the overall level is the most useful
thing to show a client. It demonstrates the rule doing its job.

## A closing detail worth keeping

The CI added as part of the repair failed twice on its first runs, both times
on assumptions that had never been checked. The tool built to catch mistakes
caught its author's mistakes within minutes of existing.

That is the steering loop working, not a setback, and it is the honest note to
end on: the harness is not a thing you finish. It is the thing that tells you
what you got wrong this week.
