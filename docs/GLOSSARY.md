# Glossary

Gantry's vocabulary is small but dense, and most of it is invented here rather
than borrowed. This page defines every term the running system uses, and ends
with the terms the documents use that no code implements yet.

## How this page is grouped

Not alphabetically. The terms come in families, and the family is the actual
lesson: `rung`, `effect`, `gate` and `capability` are one idea in four words,
and reading them a dozen entries apart teaches nothing. So the groups are the
questions you might be trying to answer.

1. [Start here](#start-here) is the handful of words every other entry assumes.
2. [Understanding the record](#understanding-the-record) is the ledger: what an
   event is, how it is hashed, signed and proved.
3. [Understanding the authority](#understanding-the-authority) is the policy:
   what a call is allowed to do and who says so.
4. [Understanding what runs](#understanding-what-runs) is the broker, the
   sandbox and the credential path.
5. [Understanding the checks](#understanding-the-checks) is sensors and their
   liveness.
6. [Understanding the score](#understanding-the-score) is the conformance
   scorer and the twelve numbers.
7. [Declared, not enforced](#declared-not-enforced) is the terms you will meet
   in these docs that no code implements yet. Read it before you quote one.

Use your browser's find function if you already know the word you want.

Every entry names the file or the command where you meet the term in the
running system, so you can go and look.

---

## Start here

**Harness.** Everything around the model. The model writes the code; the
harness decides whether the command it just proposed may run, what credentials
it can see, what happens when a check fails, and whether anyone can reconstruct
that afterwards. Gantry is a harness, and it is also a way of measuring one.
Defined in `docs/PRIMITIVES.md`.

**Primitive.** One of twelve layers a harness decomposes into, numbered 01
Instruction through 12 Governance. Each scores 0 to 5. The full rubric with
scoring anchors is `docs/PRIMITIVES.md`; the short version is the table in
`README.md`. Twelve is one practitioner's decomposition, not a standard, and
the rubric says so.

**Maturity anchor.** The 0 to 5 scale a primitive is scored against. The
boundary that matters is 3 to 4: a layer carried only by a written rule caps at
3, and 4 requires the system to catch violations mechanically. This is why
`CLAUDE.md` makes every rule name the check that enforces it.

**Overall level.** The minimum across the primitives a workload exercises,
never the average. One missing layer is what an attacker or an auditor finds,
so averaging it away would be the wrong arithmetic. Printed by `gantry score`.

**Chokepoint.** The single code path every call of a kind passes. Model calls
pass `src/gateway.rs`, tool calls pass `src/broker.rs`. It exists so that
completeness of the record is a structural property rather than a discipline: a
call cannot avoid being recorded without avoiding the only function that makes
it. `tests/invariants.rs` fails the build if the HTTP client is referenced
outside the gateway.

**Guide and sensor.** A guide steers before the action (an instruction file, a
tool schema, a policy). A sensor observes after it and reports (a test, a
linter, a hook, an approval record). The distinction is the whole reason a
project can look well governed and score 2: guides are cheap and sensors are
the thing nobody builds. Taken from Böckeler's taxonomy, credited in
`README.md`.

**Fault.** Gantry's error type: a `cause` and a `fix`, printed as
`<cause>. Fix: <fix>`. The fix must name an action, because the reader is
usually an agent, not a person. `src/lib.rs`. The console returns the same
shape as JSON on an API error.

---

## Understanding the record

The ledger is an append-only Merkle transparency log, RFC 6962 construction.
`src/ledger.rs` and `src/merkle.rs`. You meet it through `gantry ledger`.

**Event.** One thing that happened, in a uniform shape. Nineteen kinds are
documented in `docs/EVENT-SCHEMA.md` (`run.open`, `tool.request`,
`policy.decision`, `sensor.verdict`, `score.snapshot` and so on), and two of
those nineteen have no producer yet. There is one event type with a `kind`
discriminator rather than many types, so adding a kind never changes how
verification works.

**Envelope.** The part of an event the ledger stores, hashes and proves:
identity, sequence, timestamp, kind, actor, authority block, a hash of the
payload, and an optional signature. It never contains the payload itself.
`src/event.rs`.

**Subject.** The kind-specific payload of an event: the arguments of a tool
call, the verdict of a decision, the fields of a checkpoint. It lives beside
the log in `payloads/<hex>.json`, keyed by its own hash, not inside the
envelope.

**Subject hash.** `sha256:<hex>` over the RFC 8785 canonical JSON form of the
subject. The envelope carries this instead of the payload so a payload can
expire under a retention rule while the envelope, the chain and every proof
stay valid. Deleting an envelope is never permitted; deleting a payload is.

**Canonical JSON (RFC 8785, JCS).** The one byte-exact serialisation of a JSON
value. Field order and naming are therefore part of the hash, which makes them
schema-breaking changes rather than cosmetic ones. `event::jcs_bytes`.

**Run.** One invocation, from a `run.open` event to a `run.seal` event, sharing
a run id. `seq` is monotonic within a run. A run that opened and never sealed
is a crashed or in-flight run, and nothing hides it.

**prev_hash.** The leaf hash of the previous envelope in append order. Cheap
local tamper detection. It cannot protect the newest entry, because nothing
chains after it, which is why the tree exists.

**Leaf hash and tree.** RFC 6962: a leaf is `SHA-256(0x00 || bytes)`, an
interior node is `SHA-256(0x01 || left || right)`. The Merkle root summarises
the whole log in one hash.

**Signed tree head.** `{size, root_hash, ts, key_id, sig}`, written on every
append and signed by the ledger's own ed25519 key. It is what protects the
newest entry: alter that entry and the recomputed root stops matching a head
that was already signed. `gantry ledger verify` checks every head and faults if
any tail of the log has no head covering it, which was a real hole found in
review (`docs/proof/01.md`).

**Inclusion proof.** The sibling hashes that let someone recompute the root
from one envelope alone, proving that event is in the log at that size. Produce
one with `gantry ledger prove <dir> <index>`, check it with
`gantry ledger verify-inclusion <bundle.json> <pubkey>`. The bundle is about
1.7 KB and the check needs no server and no network.

**Consistency proof.** The hashes that prove an older signed head is a prefix
of a newer tree, so history was appended to and not rewritten. Produced by
`gantry ledger consistency <dir> <m>`.

**Attestation.** An optional ed25519 signature by the actor that produced the
event, over the fields the actor controls (`Envelope::attestation_bytes`). It
excludes `prev_hash`, because the ledger assigns that at append and an actor
cannot sign a hash it has not seen yet. Distinct from the tree head signature:
the head signs the log, the attestation signs one event.

**Actor key registry.** `config/actor-keys.json`, the tracked list of keys an
attestation may verify against. It refuses to load at all if any entry is
corrupt or has no owner, rather than silently trusting fewer keys, because a
partly loaded trust root is worse than none. Same loader as the skill key
registry (`skills::KeyRegistry::load`).

**Attestation state.** Per event, one of four values, and the console must show
them apart: `verified` (checked against a registered key and good), `forged` (a
registered key id whose signature fails, which is a fault), `unverified` (no
registered key matches its key id, counted and reported), `absent` (no
signature). Rendering `absent` and `verified` the same way is the exact failure
this project exists to prevent. `docs/CONSOLE-API.md`.

**Published seed.** A signing key whose private half is in version control.
The tracked laptop key is one (`config/actor-key-fixture.seed`), so a fresh
checkout can produce signed runs with no key ceremony. The registry marks it
`seed_published: true`, and every reporting path carries that: `gantry ledger
verify` prints a second line saying such signatures prove which run wrote the
event and not who operated it, and the API returns `_attestation_trust:
"fixture"` rather than `"registered"`. A profile other than `laptop` that
declares a published key refuses to start. This distinction exists because
without it a laptop run and an HSM-backed deployment print the same sentence
(`docs/proof/10.md`).

**Retention and expiry.** The lawful way to remove data: append a
`retention.expire` event naming the subject hash, then delete the payload. The
envelope and every proof survive. `gantry ledger expire` refuses to delete a
payload no envelope references, and refuses an event submitted under any other
kind. A payload that vanishes with no expiry event on record is a verification
fault.

**Secret scan.** `gantry ledger scan-secrets <dir>` greps every stored byte
(envelopes, heads, payloads) for the values of the `GANTRY_HANDLE_*`
environment variables, names the handle and file on a hit, and never echoes the
value.

---

## Understanding the authority

The policy is data: `config/policy.json`, loaded and evaluated by
`src/policy.rs`. The document that explains its shape is
`docs/POLICY-SCHEMA.md`.

**Policy version.** `sha256:` over the canonical form of the policy with the
version field itself removed, computed by the loader. A hand-written value that
does not match the content refuses to load. Two installations run the same
policy or they do not, and the answer is a string comparison.

**Capability.** A named bundle of tool patterns with one effect class and one
rung, for example `repo.read` covering `Read(**)`, `Grep(**)`, `Glob(**)`.
Authority is granted to capabilities, never to individual calls.

**Undeclared is denied.** A tool that matches no capability is denied under the
synthesized rule id `r-default`. A tool nobody scoped is not a tool the agent
may call.

**Effect class.** What the call does to the world, not how risky it feels:
`read`, `write.local` (the sandbox discards it), `write.shared` (a compensating
action could undo it), `irreversible` (nothing available to the harness can
recall it). Egress is `irreversible`, because a byte that has left cannot be
unsent, and that one classification is what makes the gate table safe.

**Rung.** How much autonomy a capability currently holds: `led`, `assisted` or
`autonomous`. It decides where the human stands, and sensors decide it.

**Trust budget.** The rules for moving a rung, declared in the policy.
Promotion needs N clean runs at the current rung and a permitted approver, and
is itself a ledger event. Demotion is automatic on failure and needs no
meeting. The asymmetry is deliberate: earning authority takes a signature,
losing it takes a failure. `src/trust.rs`.

**Earned rung.** The rung replayed from the ledger's `capability.run` and
`rung.change` events, starting at the declared rung. It is never stored in a
field, so a third party recomputes it from the signed record. The broker gates
on the earned rung, not the declared one, so a recorded demotion tightens the
gate on the very next call. See it with `gantry trust history <ledger> <cap>`,
or in the console's Trust view, which marks which of the two is gated on.

**Gate placement.** `pre`, `post` or `none`, derived from the rung and the
effect class rather than written by the rule author. `irreversible` is `pre` at
every rung including autonomous, because autonomous means post-hoc review with
rollback and there is no rollback for an unrecallable act.

**Rollback handle.** A string a capability declares (`git.worktree`) that a
`post` gate requires. A capability that resolves to `post` with no handle
refuses to load, and at runtime a gate that would become `post` without one
degrades to `pre` instead. Nothing executes the rollback; the handle is a
declaration the loader checks, not a running undo.

**Verdict.** The outcome of one evaluation: `allow`, `deny` or `hold`. Exactly
one `policy.decision` event is written per call, whichever it is. A denial is
never inferred from a missing allow. A `hold` call does not execute.

**Rule id.** Every decision names one rule, so a denial stays explicable
afterwards. Two ids are synthesized rather than written in the rules list:
`r-default` (no capability declares this tool) and `r-delegation` (the
capability is outside a sub-agent's grant).

**Ordered rules, first match wins.** Determinism is what lets an event name one
rule.

**Shadowed rule.** A rule no call can ever reach because an earlier, broader
rule already matched. The policy refuses to load. The check is deliberately
conservative, only flagging coverage it can prove, so it cannot produce a false
positive and it can miss a clever pair of overlapping globs.

**Host permission list.** The agent harness's own allow and deny lists, for
Claude Code `.claude/settings.json`. It is a backstop, not the policy: a host
`deny` short-circuits before Gantry's hook runs, so the denial is real and
leaves no `policy.decision` and no named rule. Enforcement without evidence.

**Host parity.** The check that every host `deny` entry, replayed through the
policy, resolves to something other than allow, so a short-circuited denial is
at least explicable after the fact. `gantry policy check config/policy.json
.claude/settings.json`.

**Profile.** One name that sets isolation, gates, anchoring and identity
together: `laptop`, `team` or `regulated`. `laptop` is the default and the only
one implemented end to end (see [Declared, not
enforced](#declared-not-enforced)). The rule that keeps profiles honest is that
the scorer reads what is running and never the profile name.

**Instruction pack.** The version-controlled file the gateway hands the model
as its system message, `instructions/pack.md`. Its hash is pinned onto every
event, so changing it is a recorded change rather than a quiet one.

**Pinning.** Recording the identity of the thing in force at the time of the
call: the instruction pack hash, the policy version, the settings hash. It
answers "what was the agent told last Tuesday" without a reconstruction
project. `gateway::Pinning`.

**Authority block.** The part of every envelope that answers "under whose
authority", carried on ordinary events and not only privileged ones: profile,
policy version, instruction version, settings hash, permission mode, and the
list of fields that diverged. The cheapest way to answer the question is to
never have an event that cannot.

**Permission mode.** The mode the host agent is actually running under
(`default`, `acceptEdits`, `bypassPermissions`, others). Gantry reads it from
`CLAUDE_PERMISSION_MODE`, which `.claude/hooks/permission-mode.sh` injects into
any Bash command containing `gantry`. When nothing sets it, the event records
`"unobserved"`, never a guess.

**Divergence.** The running value disagreeing with the tracked declaration.
Two are computed today, both landing in `authority.diverged` on every event of
the run: `host_permissions.settings_hash` (the settings file on disk differs
from the git HEAD blob) and `host_permissions.permission_mode` (the observed
mode differs from `permissions.defaultMode`). The two are independent and are
listed separately.

**Drift.** The general name for the same idea across all declared values in
`profile_requirements`. Divergence in the two fields above runs. The scheduled
whole-profile drift scan does not; see the last section.

---

## Understanding what runs

**Gateway.** The one path every model call takes, `src/gateway.rs`. It
normalises across providers, pins instruction and policy version per call, and
appends a `model.call` event whether the call succeeded or failed.

**Broker.** The one path every tool call takes, `src/broker.rs`. Per call it
appends a `tool.request`, evaluates the policy to exactly one
`policy.decision`, executes only on allow, and appends a `tool.result` in every
case, including denial. `gantry broker call <ledger> <tool> <target>`.

**Tool registry.** The broker executes nothing whose definition it has not
accepted. Definitions are MCP-shaped (`name`, `description`, `inputSchema`) and
a definition that names no typed properties is refused, because a tool that
takes anything is a tool nobody scoped. Both outcomes are recorded as
`tool.register` events.

**Taint.** The flag on a `tool.result` marking the content as untrusted data
rather than instruction. Every successful tool result carries it. When tainted
content reaches a model prompt the run records a `taint.note`. Taint is
evidence today, not a control: no policy rule keys on it and nothing marks the
model's reply tainted in turn.

**Sandbox.** Per-run isolation for every command the broker executes,
`src/sandbox.rs`. On macOS the backend is seatbelt (`/usr/bin/sandbox-exec`)
with a generated profile. The active backend is recorded on every
`tool.request` as `sandbox`, so the declaration in the policy is observable
rather than asserted; where the backend binary is missing it records `none` and
the isolation claim is honestly unmet rather than silently bypassed.

**Seatbelt profile.** What the generated sandbox actually denies: all network
except the egress allowlist, and all writes outside the run's own workdir.
Reads are not restricted. The environment is cleared, so a hostile `env` in the
sandbox sees `PATH`, `HOME`, `TMPDIR` and nothing of the parent's.

**Egress allowlist.** `profile_requirements.egress.allow`, translated into the
sandbox profile as `remote ip` entries. Empty on the laptop profile, and the
empty list is what makes the deny total. A pattern rule can be evaded by an
extra space; the sandbox cannot, which is why `docs/proof/04.md` attacks both.

**Credential handle.** The name an agent holds in place of a secret, written
`{{handle:NAME}}` in a command. The broker reads the value from
`GANTRY_SECRET_NAME` and injects it into the sandboxed child's environment as
`GANTRY_HANDLE_NAME`, after the policy allowed the call. The value never enters
the command string, an event or a Fault. A handle the matched capability does
not declare in its `credentials` list is refused, and the handle form is
deliberately not valid shell, so an unsubstituted handle fails loudly instead of
running. `src/secrets.rs`.

**Delegation and scope narrowing.** A parent run grants a sub-agent a subset of
its own capabilities and records a `subagent.spawn` event. From that event on,
a call whose capability is outside the grant is denied at the same chokepoint
as everything else, under rule `r-delegation`. The narrowing is enforced where
every call already passes, not in the skill runner's diligence. Widening is
refused. `gantry skill run <ledger> <package-dir> <parent-caps-csv>`.

**Skill package.** A directory with a manifest and step files, optionally
signed. `src/skills.rs`.

**Resolve.** Checking a skill package before anything runs it: metadata
present, every referenced step file exists, signature verifies against a
registered key. A package that fails is refused, never published on its title,
and the refusal is a `skill.resolve` event. An unverifiable signature is
refused rather than downgraded to unsigned, because a claim that fails to check
is a lie and not an absence. `gantry skill resolve`.

**Skill key registry.** `config/skill-keys.json`, the tracked trust root for
skill signatures, with the same whole-file refusal rules as the actor key
registry. A key passed on the command line is added for one resolution, never a
replacement.

**Checkpoint.** A `state.checkpoint` event carrying the whole accumulated
result vector, written after each completed step. Resume needs nothing but the
ledger. `gantry durable run` and `gantry durable resume`.

**Seam.** The visible join where a run died and another picked up: a run id
that appears in `run.open` and never in `run.seal`, plus the later run
declaring which checkpoint it restored. No special marker event is needed; the
append-only log plus the seal discipline already encode it. `durable::seam`.

**Corpus graph.** A persisted index over a set of files that answers a symbol
query by reading a fraction of what a flat scan reads. `gantry graph query`
ledgers each retrieval as a `graph.query` event with `bytes_read`,
`index_bytes` and the stale files re-read. It reports its losses: a symbol
added after indexing is missed until an expiry re-read recovers it, at a
measured byte cost. It is a token index without edges, so "traverse instead of
re-read" is really "consult the index instead of re-read".

**Template.** A validated bundle of policy, providers, scoring rules, sensors
and instruction pack. `gantry template validate` loads every part through the
same validators the runtime uses, so a shadowed rule or a sensor with no fix
refuses the whole bundle. `gantry template init` copies one into a new
directory, generates a fresh actor key for it, and never overwrites an existing
file.

---

## Understanding the checks

`src/sensor.rs`. You meet these through `gantry sensor live`,
`gantry sensor gate` and the verdicts on the ledger.

**Sensor.** A check with an id, a placement, a shell command with `{target}`
substituted, and a `fix` message. Exit zero passes. A sensor whose `fix` is
empty, or whose check never references `{target}`, refuses to load.

**Fix message.** What a failing verdict carries. It must name the action to
take, because an agent reads it and acts on it. This is the same rule the
policy applies to every deny and hold message.

**Computational and inferential.** Computational sensors are deterministic and
cheap enough to run on every change. Inferential ones are model judgments,
recorded as such so a reader knows the verdict is a judgment and not a proof.
Only computational sensors have a runner today.

**Negative control.** Content the sensor must reject, one entry per branch of
its check. It is what makes the sensor's own liveness checkable. A sensor with
none refuses to load.

**Positive control.** Content the sensor must accept. It exists because a
widened check has a second failure mode: firing on everything, which gets the
sensor switched off, which is worse than the narrow check it replaced. The
tracked `no-private-key` sensor declares six negative controls and two positive
ones taken verbatim from this system's own config files and a real ledger
envelope.

**Liveness.** Running every control before any verdict is trusted. It is a
fixed property of the sensor bus, not itself a declared sensor, which is what
keeps the regress one level deep.

**Broken.** The verdict for a sensor that passed a negative control or rejected
a positive one. It is never reported as a clean pass, so a green board of dead
sensors cannot happen. The seal records it too, as
`sealed-with-broken-sensor`.

**Blocking.** Whether a failing verdict stops the artifact. Verification that
never blocks anything is a 2 on the rubric.

**Liveness sweep.** `gantry sensor live <sensor.json>...` runs every control
standalone, with no artifact. `ci/run.sh` runs it on every push and the
workflow adds a weekly cron, so a sensor that rots between pushes is caught by
the schedule rather than by the next unlucky verdict. Sample output:

```
sensor no-private-key is live: it rejects every negative control it declares (6) and accepts every positive one (2)
```

**Placement.** `pre_integration`, `post_integration` or `continuous`. Recorded
on every verdict. Nothing dispatches on it; see the last section.

---

## Understanding the score

`src/scorer.rs`, rules in `config/scoring.json`, run by `gantry score <ledger>`.

**Conformance scorer.** The rubric as a running service. Every predicate is a
statement about ledger events, so it never reads a profile name or a config
value to decide a number. It cannot be talked into a better one.

**Scoring rules.** Data, not code: per primitive, a base event kind and a list
of levels, each with predicates and an evidence sentence. Shipping them as data
is what lets a third party re-derive the same twelve numbers from an exported
ledger without trusting the binary.

**Predicate.** One event kind plus an optional JSON pointer and a `present` or
`equals` test. Each predicate in a level is matched independently against the
event set. Naming an outcome rather than a control in a predicate is a known
trap: an early version of the primitive 01 rule scored a failing gate higher
than a passing one, which paid for breakage. `docs/proof/13.md`.

**Evidence sentence.** The string printed beside a score, saying which
telemetry earned it. A score without evidence is an opinion.

**N/A.** A primitive the ledger never exercised. Not 0, which would say the
layer is broken, and not a generous guess. N/A rows are ignored by the overall
minimum, so building a new layer can only hold or lower the overall level,
never inflate it.

**Score snapshot.** The `score.snapshot` event the scorer appends to the ledger
it just scored, so the act of the platform observing itself is on the same
append-only record. The scorer ignores `score.snapshot` events when scoring, so
this does not recurse.

**Self-score.** The twelve numbers in `README.md`, produced by running
`gantry score` over a ledger that exercised the layers. It sits at overall 3
because that is the minimum, and the minimum is the honest figure.

---

## Declared, not enforced

Terms you will meet in `docs/`, in `CLAUDE.md` or in the policy schema that no
code implements today. They are listed because a term that reads as a running
control and is not is worse than a missing one.

**`drift.report` and `gantry drift`.** `docs/POLICY-SCHEMA.md` describes a
command that walks `profile_requirements`, reads each `observed_by` source and
emits one report per field on a schedule. There is no such subcommand and
nothing emits the event kind. What runs is the per-event `authority.diverged`
list, covering the settings hash and the permission mode.

**`observed_by`.** Every profile requirement names an observation source.
Three are read today. The settings hash and the permission mode are compared
against their declarations, and a mismatch lands in `authority.diverged`. The
sandbox backend is recorded beside the declared isolation on every `run.open`,
so a reader can compare the two, but nothing computes the comparison. The rest
are declarations waiting for the drift scan.

**`ledger.anchor` and anchoring.** The event kind is in the schema and
`profile_requirements.ledger.anchoring` is in the policy. Nothing anchors a
head anywhere. Until it does, replacing the whole log with an internally
consistent older state is undetectable by verification alone, which is the
known limit of any transparency log with no head gossip.

**`team` and `regulated` profiles.** Named in `README.md`,
`docs/CONCEPT.md` and `docs/POLICY-SCHEMA.md` with their own isolation,
identity and anchoring rows. The only profile-sensitive behaviour in the code
is the refusal to start a non-laptop profile that declares a published signing
seed. `on_unavailable: refuse` is not implemented, and neither is any isolation
backend other than seatbelt.

**OIDC identity.** The identity source on every event is `local`. OIDC appears
in the profile table and in `docs/CONCEPT.md` and has no implementation.

**Rollback execution.** A rollback handle is a declared string the loader
checks. No code performs a rollback.

**Sensor placement dispatch.** `placement` is recorded on every verdict and
nothing runs a sensor at its placement, because there is no integration
lifecycle to hang it on. Marked `[UNENFORCED] ci/sensor-placement-honoured` in
`CLAUDE.md`.

**Inferential sensors.** The kind exists and is recorded. There is no distinct
runner and no liveness story for a model-judged check.

**MCP as a wire protocol.** The registry stores and refuses MCP-shaped
definitions. No external MCP server can connect. MCP is the data shape here,
not the transport.

**Taint propagation.** Recorded, not propagated. See the taint entry above.

**`seq` gap reporting.** The schema says a gap in `seq` is the signal that a
harness was switched off mid-run. The verifier does not report gaps.

**Consistency proof verification from the CLI.** `gantry ledger consistency`
produces a proof. Checking one is a library function and a property test; there
is no `verify-consistency` subcommand the way there is for inclusion.

**Retention rules.** `gantry ledger expire` records an expiry you hand it. The
retention rule id is a field the caller writes. There is no scheduler and no
rule engine deciding what expires when.

**Demotion triggers other than a sensor failure.** The trust budget lists
`human.override` and `policy.deny`. Only a `capability.run` recorded by the
orchestrator with a non-clean outcome moves a rung down; a broker denial does
not.

**`gantry scan`, `gantry apply`, `gantry up`.** Named in
`docs/CLAUDE-CODE-INTEGRATION.md` as the onboarding path, and `gantry scan`
is referenced by `CLAUDE.md`. None is a subcommand. `gantry` with no arguments
lists what does exist.

**Two policy version schemes.** The broker pins the computed content version of
`config/policy.json`. The gateway smoke command `gantry run` still pins the
byte hash of `docs/POLICY-SCHEMA.md`, so a `model.call` event from that path
carries a different kind of value in the same field. Noted in
`docs/proof/03.md` and still true.
