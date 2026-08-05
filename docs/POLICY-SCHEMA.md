# Policy schema, slice 00 (evaluator landed in slice 03)

Companion to `docs/EVENT-SCHEMA.md`. The event schema says what happened. This
document says what was allowed to happen, and under whose authority. One
`policy.decision` event is the output of one evaluation of this document.

Since slice 03 the machine form of this document is `config/policy.json`,
loaded and evaluated by `src/policy.rs`. Changes against the slice 00 shape,
each reflected in the computed `policy_version`:

- **`match.path_in` is generalised to `match.target_in`** and is matched
  against the request target whatever its kind: a path for file tools, a
  command line for shell, a host for egress. `path_in` remains accepted as an
  alias.
- **`policy_version` is computed by the loader** over the RFC 8785 form of
  the parsed document with the field itself omitted. A hand-written value
  that does not match the content refuses to load.
- The load-time checks promised below are running: a shadowed rule, a post
  gate without a rollback handle, and a deny or hold rule without a message
  each refuse to load. Host parity runs in `gantry policy check`. The shadow
  check is conservative: it only flags coverage it can prove (an absent
  constraint, or pattern sets where each later pattern is matched by an
  earlier one), so it cannot false-positive.

Primitive 12 is a guide plus a sensor. The guide is this document. The sensor
is the drift check that compares every declared value here against an observed
value taken from the running system. A field in this schema that nothing can
observe is a guide wearing a badge, and it is marked so.

## Design constraints

1. **One call, one evaluation, one event.** Every tool call is evaluated
   exactly once and emits exactly one `policy.decision`. An absent decision is
   a fault, not an implied allow. A harness that can perform a call without
   producing a decision is not carrying primitive 12, whatever the document
   says.
2. **Verdict is derived, not written.** A rule states an action (`allow`,
   `deny`, `hold`). The gate placement comes from the capability's rung and the
   call's effect class. Rules never hardcode "ask a human", because that is the
   trust budget's decision, not the rule author's.
3. **Every declared value names its observation source.** `observed_by` is a
   required field on profile requirements. `observed_by: none` is legal and is
   an admission: that requirement caps its primitive at 3.
4. **Ordered rules, first match wins.** Determinism is what lets an event name
   one rule. A deny rule shadowed by an earlier allow is a lint failure, not a
   subtlety the reader has to notice.
5. **Policy is data, versioned by content.** `policy_version` is the SHA-256 of
   the RFC 8785 canonical form of this document with the `policy_version` field
   itself omitted. Two installations run the same policy or they do not, and
   the answer is a string comparison.
6. **Undeclared is denied.** A tool matching no capability is denied. This is
   the schema registry's stance applied to authority: a tool nobody scoped is
   not a tool the agent may call.

## Document shape

```yaml
v: 1
policy_version: sha256:...      # computed, never hand-written
profile: laptop                  # laptop | team | regulated

profile_requirements:
  isolation:
    declared: oci+seccomp        # none | oci+seccomp | kernel-sandbox | microvm
    observed_by: sandbox.active_backend
    scores: 3                    # primitive 05 ceiling this backend can reach
  egress:
    declared: allowlist
    allow: []                    # empty on laptop, and the empty list is enforced
    observed_by: netns.route_table
  identity:
    declared: local              # oidc | local | none
    fallback_permitted: true     # regulated sets false
    observed_by: gateway.identity_source
  ledger:
    declared: local_file
    anchoring: none              # none | object_store | rfc3161 | notary
    key_custody: software        # software | tpm | hsm
    observed_by: ledger.head
  instruction_pack:
    declared: sha256:...
    observed_by: gateway.instruction_hash
  host_permissions:
    declared: sha256:...         # hash of the host harness settings file
    observed_by: hook.settings_hash
  rung_default: autonomous
  on_unavailable: degrade        # degrade | refuse

capabilities:
  - id: repo.read
    tools: ["Read(**)", "Grep(**)", "Glob(**)"]
    effect: read
    rung: autonomous
    credentials: []
  - id: repo.write
    tools: ["Write(**)", "Edit(**)"]
    effect: write.local
    rung: assisted
    rollback: git.worktree
    sensors: [ci/message-lint]
  - id: vcs.publish
    tools: ["Bash(git push:*)"]
    effect: irreversible
    rung: led
  - id: net.egress
    tools: ["Bash(curl:*)", "Bash(wget:*)", "WebFetch(**)"]
    effect: irreversible
    rung: led
    credentials: []

rules:
  - id: r-credential-file
    match: { capability: repo.read, path_in: ["./.env", "./.env.*", "**/*.pem", "**/id_rsa*", "./secrets/**"] }
    action: deny
    message: "Reading a credential file is denied. Ask the broker for a handle and pass the handle name; the broker substitutes the value at the tool boundary."
  - id: r-egress-laptop
    match: { capability: net.egress }
    when: { profile: laptop }
    action: deny
    message: "Egress is denied on the laptop profile, whose allowlist is empty. Add the host to profile_requirements.egress.allow and re-run, or perform this lookup outside the run and paste the result."
  - id: r-write-docs
    match: { capability: repo.write, path_in: ["docs/**"] }
    action: allow
  - id: r-default
    match: {}
    action: deny
    message: "No capability declares this tool. Add it to a capability in docs/POLICY-SCHEMA.md with an effect class and a rung, then re-run."

trust_budget:
  promotion:
    runs_at_rung: 20
    zero_sensor_failures: true
    approver: any                # any | named
    emits: rung.change
  demotion:
    triggers: [sensor.fail, policy.deny]
    to: one_rung_down
    automatic: true
    approval_required: false
```

Two notes on `profile_requirements`, both since slice 15, when `gantry drift`
started reading these fields instead of describing them. The shape above shows
`egress.observed_by: netns.route_table`; `config/policy.json` names
`sandbox.egress_allow`. Nothing reads either one, and the Drift section below
says why the second is worse than the first. And only one value per field is
compared, the one named `declared`, except for `attestation`, whose `declared`
is the algorithm and whose observable value is the `key_id` beside it. The rows
next to those (`egress.allow`, `ledger.anchoring`, `ledger.key_custody`,
`identity.fallback_permitted`) are read by nothing.

## Effect classes

The class is a property of what the call does to the world, not of how risky it
feels. Four values, and the boundary that matters is the last one.

| Class | Meaning | Rollback |
|---|---|---|
| `read` | Observes state inside the sandbox. | Not applicable. |
| `write.local` | Mutates state the run owns and the sandbox discards. | Automatic. |
| `write.shared` | Mutates state outside the run: a shared branch, a database, a ticket. | Possible, by a compensating action. |
| `irreversible` | Cannot be recalled by any action available to the harness. Egress, publication, deletion, payment, notification of a third party. | None. |

Egress is `irreversible` because a byte that has left cannot be unsent. This is
the single classification most likely to be argued with, and it is the one that
makes the table below safe.

## Gate placement

The verdict is a function of the rule action, the capability's rung, and the
effect class. This table is the trust budget from `docs/CONCEPT.md` made
evaluable.

| Rung | `read` | `write.local` | `write.shared` | `irreversible` |
|---|---|---|---|---|
| `led` | pre | pre | pre | pre |
| `assisted` | none | none | pre | pre |
| `autonomous` | none | post | post | pre |

- **pre** means the call blocks on a human decision and emits `hold`, then an
  `approval` event carrying a verdict, then the call proceeds or does not.
- **post** means the call proceeds and a review record is required afterwards.
  The capability must declare a `rollback` handle, or the policy fails to load.
- **none** means the call proceeds and is recorded, with no review obligation.

**Irreversible is `pre` at every rung, including autonomous.** Autonomous is
post-hoc review with rollback, and there is no rollback for an unrecallable
act. A ladder that promotes its way out of a human gate on irreversible work is
theatre, which is exactly the failure `docs/CONCEPT.md` names when it collapses
the three candidate models into one.

## Evaluation

```
decide(call, identity, profile):
  cap  := first capability whose tools pattern matches call.tool
          if none        -> deny, rule r-default, reason "undeclared capability"
  rule := first rule whose match applies to (call, cap) and whose `when`
          matches the active profile
          if none        -> deny, reason "no rule"          # unreachable when r-default exists
  if rule.action == deny -> deny
  gate := GATE[cap.rung][cap.effect]
  if rule.action == hold -> hold
  if gate == pre         -> hold
  else                   -> allow, with review obligation when gate == post
```

Total, ordered, and side-effect free. It is a pure function of the policy
document, the call, and the identity, which is what makes a decision replayable
by a third party holding only an exported ledger and this document.

Two refinements applied at the broker, both replayable from the ledger:

- The rung that indexes GATE is the earned rung, replayed from the ledger's
  `capability.run` and `rung.change` events starting at the declared rung. A
  gate that would land on `post` for a capability with no rollback handle
  degrades to `pre` instead, keeping post-implies-rollback true at runtime.
- In a delegated run (after a `subagent.spawn` event), a call whose matched
  capability is outside the granted set is denied with the synthesized rule
  id `r-delegation`. Like `r-default`, it is not written in the rules list;
  it names the mechanism so the denial stays explicable.

## Decision object

The output maps one to one onto the `subject` of a `policy.decision` event.

```json
{
  "verdict": "deny",
  "capability": "net.egress",
  "rule": "r-egress-laptop",
  "rung": "led",
  "effect": "irreversible",
  "gate": "pre",
  "obligation": null,
  "request": {
    "tool": "Bash",
    "args_hash": "sha256:b3e46a297ee98853160b908303b1714c6af04336d3f82dbf4d4aeae7dd4f12d8",
    "target": "https://crates.io/api/v1/crates/gantry"
  },
  "identity": { "id": "user:mariano@local", "source": "local" },
  "message": "Egress is denied on the laptop profile, whose allowlist is empty. Add the host to profile_requirements.egress.allow and re-run, or perform this lookup outside the run and paste the result."
}
```

`obligation` is `null`, `"review"` or `"approval"`. A `post` gate sets
`"review"` and the run cannot seal clean until a matching review record exists.
This is what stops post-hoc review from being a promise.

`message` is required on every `deny` and every `hold`, and it must name the
action to take. The reader is an agent. `ci/message-lint` rejects a message
that contains no imperative.

## The three profiles

A profile is a set of declarations that differ per deployment. This table
carries only the rows something runs, and each names what runs it. The rows
that described behaviour nothing implements were deleted rather than left
looking like coverage; what they described is listed under the table as
unbuilt.

| Field | `laptop` | `team` | `regulated` | Enforced by |
|---|---|---|---|---|
| `isolation.declared` | `seatbelt` | `seatbelt` | `seatbelt` | `Sandbox::per_run` (`src/sandbox.rs`) builds the profile and `run.open` records `active_backend` beside the declaration; `tests/sandbox.rs` |
| `egress.allow` | `[]` | explicit list | explicit list | the same generated seatbelt profile: an entry becomes a `remote ip` allow and everything else, loopback included, is denied; `tests/sandbox.rs` |
| `promotion.approver` | `any` | `any` | **`named`** | `TrustBudget::approver_ok` (`src/trust.rs`), consulted by `gantry approve` and by promotion in `Orchestrator::step`; `tests/broker.rs` |
| `on_unavailable` | `degrade` | `degrade` | **`refuse`** | `policy::availability_check` (`src/policy.rs`) at run open; `tests/profiles.rs`, `ci/run.sh` (`ci/profile-unavailable-refuses`) |
| `attestation` key seed | published key permitted | held key only | held key only | `ActorSigner::declared` (`src/runlog.rs`); `tests/broker.rs` |

Every value in the isolation row is `seatbelt` because this build has one
isolation backend. A profile is free to declare another, and the row below
says what happens when it does.

The attestation row is enforced at run open rather than at load, because it
needs the key registry beside the policy: a profile other than `laptop` that
declares an actor key the registry marks `seed_published` refuses to start.
The laptop fixture seed is tracked in the repository, so a signature under it
says which run wrote an event and nothing about who operated it. That is what
a laptop claims and it is not what a `team` or `regulated` attestation is read
as.

`on_unavailable: refuse` is the row that carries the weight, and it is why
`regulated` does not quietly become `laptop` when the HSM is missing.
Availability is checked at run open, before the first event is appended: each
requirement's declared value is compared against what the running system can
provide, and under `refuse` a requirement nothing can provide is a `Fault`
naming the field, the declared value, what this system does provide, and the
action to take. Under `degrade` the run starts and the shortfall is written to
`run.open` as `unavailable`, so the weakening is on the ledger rather than in
nobody's head.

Availability is not divergence, and the two are separate checks on purpose.
Divergence is one declared value against the one value observed now, which is
the Drift section below. Availability asks whether anything on the machine
could meet the declaration at all, which is why `Providable` holds a set per
field: a host that can boot a microvm answers yes for microvm even while a
particular run sits inside seatbelt.

### Declared but not built

This build provides one isolation backend (seatbelt), local process identity,
a local-file ledger with no anchoring, and a software-held actor key. Nothing
here provides `microvm`, `kernel-sandbox`, `oci+seccomp`, `oidc`,
`object_store`, `rfc3161`, `notary`, `hsm` or `tpm`, on any machine. A profile
may still declare them, and the only thing that runs about such a declaration
is the availability check: `refuse` stops the run and names it, `degrade`
records it on `run.open`. Read a declaration in this list as a statement of
intent that the control plane will not let you mistake for a control.

`isolation.scores` and `rung_default` are read by no code at all. They are left
in the shape block above because a policy carrying them still loads, and they
are named here so nobody reads them as a control. `identity.fallback_permitted`
is in the same position: no identity fallback exists to permit or refuse.

The profile name never enters a score. The scorer reads telemetry, never a
profile name or a configuration value, which is what `observed_by` is for and
why it is mandatory.

## Drift

`gantry drift <ledger-dir> <policy.json>` walks `profile_requirements`, reads
each `observed_by` source from the running system, and appends one
`drift.report` per field. Every field reports every run, matches included, so
silence is evidence rather than absence. Running it on a schedule is the
caller's job: `ci/run.sh` runs it on every push, and the weekly cron in
`.github/workflows/ci.yml` runs the same gate. Implemented in `src/drift.rs`
since slice 15; before that this section described a subcommand that did not
exist.

Three outcomes per field:

- **match**: declared equals observed.
- **divergence**: declared differs from observed. The report names both values
  and the fix, and the command exits 1. The run's own events carry the field in
  `authority.diverged`, as `<field>.<compared>`, which is the mechanism
  `docs/EVENT-SCHEMA.md` defines for a declaration that does not match what is
  running. There is no `authority.declared` boolean to set false: the v1 field
  of that name became the `diverged` list in slice 01, and this section went on
  describing the field it replaced.
- **unobservable**: no value was read. `observed_by: none` is one way to get
  here. A source no code reads is another, and so is a readable source with
  nothing to read yet, since an empty ledger has no head and no event to take
  an identity source or a key id off. Reported as a gap, never as a match, and
  it does not fail the command: the tracked policy has gaps by admission, and
  an exit code that hid them would be the same mistake in a different place.

### Which sources are observations and which are admissions

| `observed_by` | Read from | What it is |
|---|---|---|
| `sandbox.active_backend` | whether the seatbelt binary exists, the same expression `Sandbox::per_run` stamps on every `tool.request` | observation |
| `gateway.instruction_hash` | sha256 of the instruction pack the run pins | observation |
| `hook.settings_hash` | sha256 of the host settings file | observation |
| `ledger.head` | whether the ledger has a signed head | observation of the storage shape, and of nothing else in the row |
| `gateway.identity_source` | `actor.identity_source` on the newest event already on the ledger | telemetry, and the producer of that event is this same binary |
| `event.attestation.key_id` | `attestation.key_id` on the newest event; an event with no attestation reads `unsigned`, which diverges from a declared key | observation |
| `sandbox.egress_allow` | nothing | admission: the seatbelt allowlist is generated from this policy's own `egress.allow`, so reading it back would compare the declaration with itself and agree every time |
| `netns.route_table` | nothing | admission: this build reads no network namespace, and the host it runs on has none |
| any other value, or `none` | nothing | admission |

The two named admissions are the point of the table. An egress check that read
the generated allowlist back would report `match` on every run while the host
route table permitted the world, which is a control living in this document
wearing the badge of one that runs. `ci/run.sh` fails if any field whose
`observed_by` is outside the readable list is reported as anything but
`unobservable`, and it fails on a policy that declares a host permission hash
the running system does not have, so both directions are checked on every push.

What still does not run: the rows beside the compared value are read by
nothing, so `egress.allow`, `ledger.anchoring`, `ledger.key_custody` and
`identity.fallback_permitted` are declarations the scan does not touch.
`rung_default` and `on_unavailable` name no source at all and report as gaps,
which is the honest reading of a scalar this document alone carries. Nothing
schedules the walk from inside the binary; CI is the schedule.

## Relationship to the host harness permission list

Gantry is the decision point. The host harness permission list (for Claude
Code, `.claude/settings.json`) is a backstop, not the policy.

This matters because of an observed failure, recorded in `docs/proof/00.md`: a
`deny` entry in the host list short-circuits before the pre-tool hook runs, so
the denial leaves no `policy.decision` and no named rule. The denial is real,
the record is not. A harness in that configuration has enforcement without
evidence, which scores 4 on primitive 05 and 1 on primitive 12.

The rule that follows: rules that must produce evidence live here, and the host
`deny` list is reduced to the cases where an enforcement failure is worse than
an evidence gap (credential files, egress). Those entries are duplicated in
both places deliberately, and the duplication is checked.

- `ci/policy-shadow`: no rule is unreachable behind an earlier broader rule.
  — enforced at load by `Policy::validate` since slice 03
- `ci/policy-host-parity`: every host `deny` entry has a corresponding rule
  here, so a short-circuited denial is at least explicable after the fact.
  — enforced by `gantry policy check` and `tests/broker.rs` since slice 03
- `ci/policy-rollback`: every capability whose rung and effect resolve to a
  `post` gate declares a `rollback` handle. — enforced at load by
  `Policy::validate` since slice 03

## Non-goals for slice 00

No evaluator, no policy language runtime, no host adapter. Slice 00 produces
this document and the trace in `docs/proof/00.md` that exercises it by hand.
The evaluator lands in slice 03 with the tool broker, and it is not permitted
to add a field to this schema without a `policy_version` bump and a note here.
