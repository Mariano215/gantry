# Gantry

An LLM-agnostic control plane for agentic engineering. Implements the twelve
harness primitives as running services. Ships as a container. Scores itself.

Read `docs/CONCEPT.md` before changing architecture. Read `docs/PLAN.md`
before starting work — the slice order is deliberate and the proof gates are
not optional.

## The rule that governs this file

This project's entire thesis is that a layer carried only by a guide caps at
maturity 3. This file is a guide. Every rule below therefore names what
enforces it. A rule added here without an enforcing check is a defect in this
file, not a standard.

Rules with no enforcement yet are marked `[UNENFORCED]`. That marker is a
work item, and `gantry scan` on this repo is expected to report it.

## Architecture invariants

- **One chokepoint.** Every model call and every tool call passes the gateway
  or the broker. A code path that reaches a provider SDK directly is a bug,
  because it is a hole in primitive 11. — enforced by `tests/invariants.rs`
  (build failure if the HTTP client is referenced outside `src/gateway.rs`);
  `ci/run.sh` (run by `.github/workflows/ci.yml` on every push) is the CI
  form: format, clippy with warnings as errors, the offline suite, policy
  host-parity and template validation, as one gate
- **The ledger is append-only.** No code mutates or deletes a ledger entry.
  Retention is expiry of the payload under a retained hash, never a rewrite.
  — enforced by `ci/ledger-append-only`
- **Secrets never enter a prompt or a tool argument.** Agents hold handles.
  The broker substitutes at the boundary. — enforced since slice 04 by
  `src/secrets.rs`: a value reaches only the sandboxed child's environment,
  never the command string, an event or a Fault; a handle a capability does
  not declare is refused. Exercised by `tests/secrets.rs` and
  `tests/sandbox.rs`. The scanner `ci/secret-in-prompt` named is
  `gantry ledger scan-secrets` since the post-nine gap work: it greps every
  stored byte (events, heads, payloads) for the values of the
  GANTRY_HANDLE_* environment, names the handle and file on a hit and never
  echoes the value. Exercised by `tests/ledger.rs`
  (`a_secret_value_on_the_ledger_is_found_and_never_echoed`)
- **No network in tests.** The full suite runs with an empty network
  namespace. This is what keeps the air-gap claim true. — enforced by
  `ci/offline-suite`. Partially mechanised since slice 04: the broker runs
  every command inside a seatbelt profile that denies all non-allowlisted
  network, and `tests/sandbox.rs` asserts a sandboxed connection to loopback
  fails; the suite itself binds loopback listeners only as unreachable
  targets, never as a real route out.
- **Profiles never lie.** Scores derive from what is running, never from the
  profile name. A scorer that reads configuration instead of telemetry is
  wrong. — enforced since slice 08 by `src/scorer.rs`, whose every predicate
  is a statement about ledger events; it never reads a profile name or a
  config value to score. The self-score (`README.md`, `docs/proof/08.md`)
  lands at overall 2 precisely because telemetry, not prose, decides.
- **Authority is declared, and the declaration is checked.** The running
  permission mode, the policy and the instruction pack each match what is
  tracked in version control. Observed divergence in slice 00: the session ran
  under `bypassPermissions` while `.claude/settings.json` declared allow, ask
  and deny lists, and nothing reported it. See `docs/proof/00.md` finding (a).
  Partially mechanised in slice 02: settings-file drift against HEAD is
  computed per run and recorded in `authority.diverged` on every event
  (`docs/proof/02.md` attack 5). Since the post-nine gap work the running
  permission mode is recorded too: `authority.permission_mode` carries the
  observed mode (from CLAUDE_PERMISSION_MODE, set by the hook or wrapper
  invoking gantry), compared against the tracked
  `permissions.defaultMode`; a mismatch lands in `authority.diverged` as
  `host_permissions.permission_mode`, and no signal is written as
  `unobserved`, never guessed. — enforced by
  `gateway::permission_mode_check` and `tests/gateway.rs`
  (`permission_mode_divergence_is_computed_never_guessed`). Since slice 12
  the variable is set automatically: `.claude/hooks/permission-mode.sh` is a
  PreToolUse hook, wired in `.claude/settings.json`, that reads the real
  `permission_mode` Claude Code puts on its own hook input and injects it as
  `CLAUDE_PERMISSION_MODE` into any Bash command that invokes gantry,
  leaving every other command untouched. Enforced by `ci/run.sh`
  (`ci/permission-mode-hook`, which feeds the hook fixture input and checks
  the rewrite and the propagation) and `docs/proof/12.md`
- **A denial names its rule.** Every denied call resolves to a rule id in
  `docs/POLICY-SCHEMA.md`, so a denial short-circuited by the host permission
  list is still explicable afterwards. — enforced since slice 03 by the
  broker (every decision carries a rule id) and by `gantry policy check`
  plus `tests/broker.rs` (`tracked_policy_has_host_parity`), which replay
  each host deny entry through the policy
- **No rule is unreachable.** A deny rule shadowed by an earlier broader allow
  is a build failure. — enforced since slice 03 by `Policy::validate`, which
  refuses to load such a policy; exercised by `tests/broker.rs` and proof 03
- **Post-hoc review implies rollback.** Any capability whose rung and effect
  resolve to a `post` gate declares a rollback handle, or the policy refuses to
  load. — enforced since slice 03 by `Policy::validate`
- **A skill is resolved or refused, never titled.** A skill package with
  broken metadata, a missing referenced step, or a signature that no
  registered key verifies is refused at resolve time; the resolver never
  falls back to the id or title, and an unverifiable signature is refused
  rather than downgraded to unsigned. — enforced since slice 09 by
  `src/skills.rs` (`SkillManifest::resolve`); exercised by `tests/skills.rs`
  and `docs/proof/09.md`. Delegation can only narrow scope, never widen it.
  The key registry is a managed store since the post-nine gap work:
  `config/skill-keys.json` is the tracked trust root, loaded by
  `KeyRegistry::load` (`src/skills.rs`), which refuses the whole registry on
  a corrupt key or an entry with no owner rather than silently trusting
  fewer keys. `gantry skill resolve` reads it by default; a key passed on
  the command line is added for one resolution, never a replacement. —
  enforced by `src/skills.rs` tests
  (`a_registry_with_a_corrupt_key_or_anonymous_entry_refuses_whole`,
  `a_signed_skill_resolves_against_the_managed_registry`)
- **A rung is derived, never stored.** The rung a capability holds is
  replayed from the ledger's `capability.run` and `rung.change` events, so a
  third party recomputes it from the signed record; promotion needs the
  clean-run threshold and a permitted approver, demotion is automatic on the
  next failure. — enforced since slice 06 by `src/trust.rs`
  (`TrustState::replay`, `Orchestrator::step`); exercised by `tests/trust.rs`
  and `docs/proof/06.md`. Since the post-nine gap work the broker's gate
  consults the derived rung: every `BrokerRun::call` replays trust history
  and gates through `Policy::decide_with_earned`, so a recorded demotion
  tightens the gate on the very next call; an earned promotion whose gate
  would become post without a declared rollback degrades to pre instead. —
  enforced by `tests/broker.rs`
  (`broker_gates_on_the_earned_rung_not_the_declared_one`). A denial costs a
  rung too, so autonomy comes down on bad behaviour and not only on a failed
  sensor: the broker writes a `rung.change` naming the rule that caused it
  whenever a decision denies a call and the trust budget lists `policy.deny`.
  Autonomy that only ever goes up is granted once and defended by nothing.
  `led` is the floor, and a denial naming no capability demotes nothing. The
  trust budget lists only triggers that run: `human.override` was declared
  for nine slices with no command able to produce one and has been removed
  rather than left as a promise, along with `promotion.zero_human_overrides`.
  — enforced by `tests/broker.rs`
  (`a_denial_narrows_the_capabilitys_autonomy`, `demotion_stops_at_the_floor`,
  `the_demotion_follows_the_capability_the_decision_named`,
  `the_rung_a_denial_cost_gates_the_next_call`)
- **A sensor that cannot fail is broken, not clean, and neither is one that
  fires on everything.** Every sensor declares a negative control per branch
  of its check, content it must reject, and may declare positive controls,
  content it must accept; a sensor that passes any negative control or
  rejects any positive one is reported as `broken`, never as a clean pass, so
  a green board of dead sensors is impossible. One control for a check that
  catches four kinds of thing leaves three branches dead while the sensor
  still reports live, which is why `negative_control` takes a list (the
  single-string form still loads). Enforced since slice 05 by `src/sensor.rs`
  (`Sensor::liveness_failure` runs every control before any trusted verdict,
  and `Sensor::validate` refuses a sensor with no negative control);
  exercised by `tests/sensor.rs` and `docs/proof/05.md`. The summary
  `gantry sensor live` prints comes from that same function rather than from
  a fixed string, so a sensor broken by a positive control is not reported as
  having passed a negative one. Liveness is also swept on a schedule since
  the post-nine gap work: `gantry sensor live` runs every tracked sensor's
  controls standalone, `ci/run.sh` runs the sweep on every push, and the
  workflow adds a weekly cron so a sensor that rots between pushes is caught
  by the schedule, not by the next unlucky verdict. The positive controls are
  what keep a widened check honest in the other direction: the
  `no-private-key` sensor's are a real ledger envelope and the tracked policy
  and review records, so a check that fires on this system's own sha256
  output is reported broken rather than shipped and switched off. Enforced by
  `ci/run.sh` and `.github/workflows/ci.yml`. What a sensor's `placement`
  declares is still not honoured: the value is recorded on every verdict and
  nothing dispatches on it, so `pre_integration` and `post_integration` are
  descriptions rather than schedule. `[UNENFORCED]`
  `ci/sensor-placement-honoured`. This marker was carried by
  `docs/proof/05.md` and had gone missing from this file, which is the defect
  this file's own opening paragraph describes
- **An attestation is verified or declared unverified, never assumed.** The
  ledger verifier checks actor attestations against registered keys: an
  attestation under a registered key id is verified (a failure is a fault,
  naming forgery or alteration), one under an unregistered key id is counted
  and reported unverified, never silently passed. The registry is
  `config/actor-keys.json`, same loader and refusal rules as the skill key
  registry. See `docs/proof/01.md` section 6. — enforced since the post-nine
  gap work by `ledger::verify_with_actor_keys`; exercised by
  `tests/ledger.rs` (`attestations_verify_against_a_registered_key_or_are_counted`,
  `a_forged_attestation_under_a_registered_key_is_a_fault`). Since slice 10
  the producer signs: the profile declares its actor key in
  `profile_requirements.attestation` (the key id, and where the seed is read
  from), and `RunCore` signs every event the gateway and the broker append
  over `Envelope::attestation_bytes`. A profile that declares a key it cannot
  load, or a seed that produces a different key id than declared, refuses the
  run rather than appending unsigned; a profile that declares no key appends
  unsigned, which verify reports as a count. The tracked laptop profile
  declares one, so `gantry ledger verify` on a real run reports every event
  verified rather than counted. — enforced by `src/runlog.rs`
  (`ActorSigner::declared`), `tests/broker.rs`
  (`a_real_run_is_signed_and_verifies_against_the_tracked_registry`,
  `altering_a_signed_event_is_reported_as_alteration`,
  `a_profile_declaring_an_unloadable_actor_key_refuses_to_start`) and
  `tests/gateway.rs`
  (`the_gateway_signs_under_the_key_the_pinned_profile_declares`). A published
  seed is refused outside the laptop profile: the laptop fixture key is
  tracked in this repository, so a signature under it proves which run wrote
  an event and never who operated it, which is all a laptop claims and is not
  what a `team` or `regulated` attestation is read as. `ActorSigner::declared`
  reads `seed_published` from the actor key registry beside the policy and
  refuses any non-laptop profile that declares such a key, before the run
  appends anything. — enforced by `src/runlog.rs` and `tests/broker.rs`
  (`a_non_laptop_profile_declaring_a_published_seed_refuses_to_start`). A
  harness generates its own key rather than inheriting one: `gantry template
  init` writes a fresh 32-byte seed at `config/actor-key.seed` (mode 0600),
  registers the public half in a `config/actor-keys.json` the template does
  not carry, with an owner naming the harness and `seed_published` false, and
  declares the key id that seed produces in the destination policy's
  `profile_requirements.attestation`. The template ships no key material, so
  no two installs share a signing identity. Every destination path is checked
  before the first write and the seed is written last, so a refused init
  leaves no half-written harness and no seed for a harness that does not
  exist. — enforced by `src/main.rs` (`generate_actor_key`), `tests/broker.rs`
  (`template_init_generates_a_per_harness_key_and_the_harness_signs`,
  `a_refused_init_leaves_no_seed_and_never_clobbers_one`) and `ci/run.sh`
  (`ci/template-init-signs`), which inits a harness on every push and fails if
  it does not sign, if it signs under a published seed, or if its ledger does
  not verify clean

- **A hold is resolved by an approval on the record, and the decision keeps
  saying hold.** A policy hold is not a failure, it is a call waiting for a
  human. `gantry approve` writes an `approval` naming the call hash, the rule
  and the approver; the broker releases the retry and writes an
  `approval.use`. The `policy.decision` still reads `hold`, because that is
  what the policy computed, and an allow written there would say the policy
  permitted a call it did not. A grant is single use, is bound to the call
  hash rather than the request id (the retry is a new run with a new request
  id), releases only a call whose rule it names, and is re-checked against
  the trust budget at consumption, because a ledger file is writable by more
  than the one command. An approval never reverses a denial: `gantry approve`
  refuses any request that did not resolve to `hold`, and the broker consults
  grants only on the hold branch. A refusal is recorded as
  `verdict: deny`, so "nobody looked" and "somebody said no" are different
  states. — enforced by `src/broker.rs` (`usable_grant`), `src/main.rs`
  (`approve`) and `tests/broker.rs`
  (`an_approval_releases_the_held_call_and_the_decision_still_says_hold`,
  `an_approval_releases_one_call_and_not_the_next`,
  `an_approval_does_not_release_a_different_call`,
  `a_denied_call_cannot_be_approved`,
  `a_grant_from_an_unpermitted_approver_does_not_release_the_call`,
  `a_refusal_is_recorded_and_releases_nothing`)
- **The console renders the API, and that is checked by rendering it.** The
  operator console's six views are asserted against values taken off a fixture
  ledger at check time rather than against API shapes alone, so a field
  renamed in `src/console.rs` fails the gate instead of showing a blank cell.
  The check builds an eleven-event ledger, serves it with the binary and
  renders every view in headless Chrome with `--dump-dom`, under flags that
  leave only loopback resolvable; with no browser present it names the fix and
  exits non-zero rather than skipping, because a render check that passes when
  nothing rendered is a dead sensor reporting green. A verified signature
  under a published seed renders as `verified (fixture)` and not as plain
  `verified`: `docs/CONSOLE-API.md` requires the qualifier, and until the
  render check existed the API returned `_attestation_trust` and nothing read
  it, so a laptop run and an HSM-backed deployment rendered identically. —
  enforced by `ci/console-render.sh`, run by `ci/run.sh` on every push; proved
  able to fail by renaming `fired`, `earned_rung`, `_attestation_state` and
  `_attestation_trust` in turn, and recorded in `docs/proof/11.md`

## Code standards

- Rust for the control plane. One static binary. The UI is static assets that
  binary serves — no second process in the container.
- Errors carry a fix, not just a cause. A sensor verdict or a policy denial is
  read by an agent, so the message must name the action to take. — enforced by
  `ci/message-lint`; since slice 05 a sensor whose `fix` is empty refuses to
  load (`Sensor::validate`), and a policy deny or hold rule with no message
  refuses to load (`Policy::validate`)
- No `unwrap` or `expect` outside tests and `main`. — enforced by clippy
- Public types that appear in the event schema derive canonical JSON
  serialisation; field order and naming are schema-breaking changes.
  — enforced by `ci/schema-compat`
- Dependencies are added by a commit that says why. Anything with a network
  or process capability needs a note in `docs/DEPENDENCIES.md`.
  — enforced by `ci/run.sh`, which fails when a crate in `[dependencies]`
  has no entry in that file

## Working agreement for agents

- One slice at a time. Do not start slice N+1 while slice N has no proof
  document.
- A slice is done when `docs/proof/NN.md` exists, contains the adversarial
  case, the evidence, and the conformance delta — and the proof was produced
  by running the thing, not by reasoning about it.
- Prefer deleting a guide over letting it go stale. A false instruction is
  worse than a missing one; it looks like coverage.
- When something fails twice the same way, the fix is a sensor, not a third
  repair. Repairing the same defect by hand twice is the failure mode this
  project exists to prevent.

## Voice

Direct and technical. Sentence case. No emoji. No exclamation marks. State
what the thing does; do not describe how transformative it is.
