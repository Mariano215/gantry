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
    zero_human_overrides: true
    approver: any                # any | named
    emits: rung.change
  demotion:
    triggers: [sensor.fail, human.override, policy.deny]
    to: one_rung_down
    automatic: true
    approval_required: false
```

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

One profile sets isolation, gates, anchoring and identity together. Rung
defaults come from the profile and stay overridable per capability.

| Field | `laptop` | `team` | `regulated` |
|---|---|---|---|
| `isolation.declared` | `oci+seccomp` | `kernel-sandbox` | `microvm` |
| `isolation.scores` | 3 | 4 | 4 |
| `egress.allow` | `[]` | explicit list | explicit list |
| `identity.declared` | `local` | `oidc` | `oidc` |
| `identity.fallback_permitted` | true | true | **false** |
| `ledger.anchoring` | `none` | `object_store`, daily | `rfc3161` |
| `ledger.key_custody` | `software` | `software` | `hsm` or `tpm` |
| `rung_default` | `autonomous` | `assisted` | `assisted` |
| `promotion.approver` | `any` | `any` | **`named`** |
| `on_unavailable` | `degrade` | `degrade` | **`refuse`** |

Two rows carry the weight. `on_unavailable: refuse` is why `regulated` does not
quietly become `laptop` when the HSM is missing: the control plane fails to
start and says which requirement was unavailable. And `isolation.scores: 3` on
`laptop` is stated in the policy rather than computed by the scorer's goodwill,
so the default profile caps the overall level at 3 by declaration.

The profile name never enters a score. The scorer reads `observed_by` sources.
A `regulated` policy running on a machine whose `sandbox.active_backend`
reports `oci+seccomp` scores 3 on primitive 05 and emits a `drift.report`
naming the divergence. That is the whole reason `observed_by` is mandatory.

## Drift

`gantry drift` walks `profile_requirements`, reads each `observed_by` source,
and emits one `drift.report` per field on a schedule, not only on change, so
silence is evidence rather than absence.

Three outcomes per field:

- **match**: declared equals observed.
- **divergence**: declared differs from observed. The report names both values
  and the fix. Any run containing a divergent field emits its events with
  `authority.declared: false`, which caps primitive 12 at 2.
- **unobservable**: `observed_by: none`. Reported as a gap in the scan, not as
  a match. This is the field that would otherwise let a policy claim a control
  nothing checks.

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
