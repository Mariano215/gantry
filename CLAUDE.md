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

A rule with no enforcement yet carries the unenforced marker followed by the
check id that would close it, both on one line. The marker is a work item, and
`gantry scan` on this repo reports every one it finds. This paragraph names no
marker of its own, because a definition that quoted the token would be
indistinguishable from a use and the count would be wrong by one.

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
  descriptions rather than schedule.
  `[UNENFORCED]` `ci/sensor-placement-honoured`. This marker was carried by
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
- **A declared value is observed or the gap is reported, never assumed.**
  `gantry drift` walks `profile_requirements`, reads each `observed_by`
  source from the running system and appends one `drift.report` per field on
  every run, matches included, so a silent scan and a stopped scan are
  different states on the ledger. A source this build cannot read reports
  `unobservable` and never `match`: the seatbelt egress allowlist is
  generated from the policy's own `egress.allow`, so reading it back would
  compare the declaration with itself and agree on every run while the host
  route table permitted the world, and there is no network namespace here to
  read `netns.route_table` out of. Both are reported as gaps, as is a source
  no code reads, which is a gap in one field rather than an aborted walk. A
  divergence names both values and the fix, exits 1, and lands in the run's
  own `authority.diverged`; the `authority.declared: false` the policy schema
  asked for was v1's name for that list and is not reintroduced. The first
  run against the tracked policy found a divergence nothing had reported:
  `config/policy.json` declared a host permission hash `.claude/settings.json`
  had stopped having, and the declared value simply had no reader. It was
  corrected at merge, and the check now requires the tracked policy to come
  back clean rather than tolerating a divergence, because a drift check that
  passes on the state it exists to catch is a dead sensor. Enforced since
  slice 15 by `src/drift.rs` (`walk`, `read`) and `ci/run.sh`
  (`ci/drift-honest`), which fails if a field whose source nothing reads is
  reported as anything but a gap and if the tracked policy declares a value
  the running system does not have; exercised by `tests/drift.rs`
  (`a_source_this_build_cannot_read_is_unobservable_never_a_match`,
  `the_generated_allowlist_is_not_an_observation_of_itself`,
  `an_unreadable_source_does_not_stop_the_walk`,
  `every_field_reports_every_run_and_the_ledger_verifies`,
  `a_divergent_field_lands_in_authority_diverged_and_the_exit_status_is_one`)
  and proved able to fail in `docs/proof/15.md`. Four of the nine profile
  requirements are still carried by the document alone, and the report says
  which four rather than passing them quietly.
  `[UNENFORCED]` `ci/egress-allowlist-observed`
- **A profile declares what the machine must provide, and a machine that
  cannot provide it says so.** Every `profile_requirements` field with an
  availability question (isolation backend, identity source, ledger anchoring,
  key custody) is checked at run open against what the running system can
  provide. Under `on_unavailable: refuse` an unavailable requirement refuses
  the run before a single event is appended, with a fault naming the field, the
  declared value, what this system provides instead and the action to take, so
  a `regulated` profile cannot quietly become a `laptop` on a machine with no
  HSM. Under `degrade` (the laptop default) the run starts and the shortfall is
  written to `run.open` as `unavailable`, never swallowed. A stance that is
  neither refuses on every run, because a typo falling through to degrade is
  the silent degradation this field exists to rule out. Availability is not
  divergence: `availability_check` takes the observed values as arguments and
  reads no system state, so it cannot become a second observer, and a host that
  can provide microvm answers yes for microvm even while a run sits inside
  seatbelt. Enforced by `src/policy.rs` (`availability_check`), its callers
  in `BrokerRun::open` and `GatewayRun::open`, `tests/profiles.rs`
  (`a_regulated_profile_refuses_to_start_and_names_the_unavailable_requirements`,
  `the_same_profile_under_degrade_starts_and_records_the_shortfall`,
  `the_gateway_refuses_the_same_profile`,
  `an_unrecognised_stance_refuses_rather_than_degrading`) and `ci/run.sh`
  (`ci/profile-unavailable-refuses`), which builds a regulated harness on every
  push and fails if it starts; recorded in `docs/proof/17.md`
- **A score names a path, or it names the paths it looked in.** `gantry scan
  <repo-dir>` reads a repository's harness surface and scores the twelve
  primitives from what is on disk. Every number carries evidence: the artifact
  found and the check file that names it, or an explicit list of every path
  looked in that came back empty. A number with no path is an opinion, which is
  what `docs/PRIMITIVES.md` refuses. The scan writes nothing to the repository
  it reads, and that is structural rather than intended: every filesystem call
  in `src/scan.rs` goes through `RepoRead`, which has no write, create, rename
  or remove, and it appends no ledger event. A static read caps at 3, absent
  (0), an artifact nothing enforces (2), an artifact a check file names (3),
  because a file says a check is wired and only a run says it fired and could
  have failed; 4 and above needs telemetry, which is what `src/scorer.rs` reads
  off a ledger. On this repository the scan lands at or below the telemetry
  score on all twelve primitives, overall 0 against telemetry's 3, and it
  reports the unenforced markers this file carries, which is what the
  paragraph at the top of this file promises and what nothing did for sixteen
  slices. Enforced by `ci/run.sh` (`ci/scan-evidence`, which fails on a score
  with no evidence behind it, a score outside 0 to 3, a primitive count other
  than twelve, a static overall above the ceiling, or a scan that cannot run)
  and `tests/scan.rs`
  (`an_empty_repository_scores_zero_and_says_where_it_looked`,
  `a_scan_never_writes_to_the_target`,
  `the_scanner_holds_no_write_capable_filesystem_call`,
  `an_artifact_scores_two_and_a_check_naming_it_scores_three`,
  `scanning_this_repository_stays_under_its_own_ceiling_and_reports_its_markers`);
  recorded in `docs/proof/16.md`
- **A hole in the record is reported, and a rewrite is caught by a copy or not
  at all.** `gantry ledger verify` reports every gap in a run's `seq`, naming
  the run, the last seq before the hole, the next one after it and how many are
  missing. A gap is a finding and never a fault: a removed entry already faults
  on the chain or a signed head, so a hole in `seq` is an event that was never
  appended, and the log cannot tell a harness killed mid-run from a producer
  that numbered an event it failed to write. Calling that an alteration would
  assert a distinction the record cannot make. Since slice 18 a consistency
  proof is also checkable by whoever is handed one: `gantry ledger consistency`
  emits both signed heads with the proof between them, because a bare hash
  array is not checkable by anybody, and `gantry ledger verify-consistency
  <bundle.json> <pubkey-file>` checks it offline the way `verify-inclusion`
  does, refusing an old head no key signed before any Merkle arithmetic.
  Neither closes the hole a transparency log has with no head gossip, which is
  why `gantry ledger anchor` writes the current signed head outside the ledger
  directory and records a `ledger.anchor` naming the destination, the tree
  size, the head and the time, with `proves` and `does_not_prove` in the
  payload; the destination is refused inside the ledger and refused when a file
  already sits there, because overwriting the older copy destroys the only
  thing an anchor is. `gantry ledger verify-anchor` folds the anchored root
  through a fresh consistency proof, so a writer who drops its own tail and
  re-signs is caught by a log that still verifies clean, and only by a party
  holding the copy. Enforced by `src/ledger.rs` (`seq_gaps`, `Ledger::anchor`,
  `verify_consistency_bundle`), `tests/ledger.rs`
  (`a_seq_gap_is_reported_per_run_and_is_not_a_fault`,
  `a_consistency_bundle_verifies_offline_and_a_rewrite_is_rejected`,
  `an_anchored_head_detects_a_rewrite_verification_alone_misses`,
  `anchoring_refuses_a_destination_inside_the_ledger_and_refuses_to_overwrite`)
  and `ci/run.sh` (`ci/ledger-seq-gap`, `ci/ledger-verify-consistency`,
  `ci/ledger-anchor`), proved able to fail by widening the gap test and by
  folding the log's own head instead of the anchored one, which prints
  `anchor verified` on a rewritten log. Recorded in `docs/proof/18.md`.
  Nothing dispatches on the profile's declared anchoring kind and nothing
  schedules an anchor. `[UNENFORCED]` `ci/anchor-schedule`
- **A scoring level credits a control running, never what it found.** A
  primitive reaches a level because the control carrying it ran, so a ledger
  where the check passed and a ledger where it failed score the same, and a
  ledger where it never ran scores lower. The alternative is the defect proof
  13 records: a rule keyed on a sensor's failure message scored a broken
  repository above a working one, so the way to raise the number was to break
  the check. Since slice 19 primitive 07 reaches 4 from a `policy.decision`
  reading `hold` plus an `approval` carrying a `call_hash`, approve and deny
  alike because a refusal is the gate working, and primitive 12 from a
  `drift.report` plus a `run.open` carrying `unavailable`, match and
  divergence alike. The approval predicate matches on `call_hash` because
  `src/trust.rs` writes the same event kind for a rung promotion, which every
  ledger at level 3 already has, so the kind alone handed level 4 to level 3's
  own evidence. A control the ledger cannot see is credited nowhere rather
  than approximately: attestation, because the record carries no evidence of
  whose key signed it and a published fixture seed would score as an HSM, and
  `ledger.anchor`, because a copy the writer controls is not independent of
  the writer. Enforced by `ci/run.sh` (`ci/scoring-outcome-neutral`, which
  builds six ledgers with the binary and fails if an outcome moves a level,
  proved able to fail by inverting each rule in turn) and `tests/scoring.rs`
  (`the_human_gate_scores_the_same_whether_the_human_said_yes_or_no`,
  `the_drift_walk_scores_the_same_whether_it_matched_or_diverged`,
  `the_tracked_rules_and_the_template_copy_are_the_same_file`). A rule the
  self-audit never exercises is inert, so `docs/proof/08-run.sh` holds a
  `vcs.publish` call, approves it and walks the requirements; recorded in
  `docs/proof/19.md`
- **A held call is visible, and the console still writes nothing.** Every call
  whose `policy.decision` resolved to `hold` appears in the operator console's
  inbox with the rule that held it, the message it carries, the capability, the
  call, when it was last held, who has answered and the exact `gantry approve`
  command that resolves it. A hold nobody can see makes the approval path
  complete and useless, which is what `docs/proof/14.md` recorded as its first
  remaining guide. The row's state is the broker's own predicate re-derived,
  not the presence of an event: an approve grant, under an approver the trust
  budget permits, that no `approval.use` has spent, so a grant the broker would
  ignore never renders as one that releases the call, and "nobody looked" and
  "somebody said no" are different rows with different words. The console
  prints the command and never runs it: `gantry approve` records a named human,
  and a button on a loopback port with no identity story would put that name on
  the ledger because a socket was reachable. Where the profile permits any
  approver the command carries a placeholder rather than a name the console
  guessed. Enforced by `src/console.rs` (`approvals`), `tests/console.rs`
  (`the_inbox_names_every_held_call_and_what_the_record_says_about_it`,
  `a_ledger_with_no_hold_has_an_empty_inbox_rather_than_no_route`) and
  `ci/console-render.sh`, which builds three held calls in three states and
  asserts each state, the approver and the whole approve command in the
  rendered DOM; proved able to fail by renaming `state`, `approve_command`,
  `grants` and `releases_next_call` in turn, and recorded in `docs/proof/20.md`
- **A page never shows part of a record as the whole of it.** `/api/events`
  returns at most 1000 rows and reports how many matched; the Run view prints
  both numbers and, when they differ, names how many events are not drawn and
  where to page the rest. A complete-looking rendering of an incomplete read is
  a worse failure on this product than a page that refuses to draw. The same
  read is the oldest matching events and not the newest, because limit and
  offset run over the log in append order, and the overview said "most recent"
  for nine slices. The render check reaches the expanded row and the
  verification takeover without a browser driver: a row opened by its own route
  is not an interaction, and the takeover is what the router does before any
  view mounts, so a second console over an altered copy of the ledger reaches
  it. Enforced by `ci/console-render.sh`, which renders eleven pages and
  refutes the healthy scorecard behind the takeover; proved able to fail by
  renaming `total`, `index`, `faults` and `ok` in turn. Whether an expanded row
  survives the five second poll is proved in `docs/proof/20.md` against
  `dev/serve.py grow` and is not in the gate, because against the real binary
  the same question is a race with the browser's virtual clock and a flaky gate
  is one people learn to skip.
  `[UNENFORCED]` `ci/console-open-row-survives-poll`
- **The page that makes the claim does not break it.** The site published to
  GitHub Pages prints "no hosted control plane, no licence check, no CDN font"
  and, as exported by the design tool, fetched React from unpkg and three
  families from Google Fonts while printing it. `dev/build-site.py` vendors
  React out of the build machine's own node_modules and drops the font import
  and the design-system bundle, which is also where every link to an unrelated
  project came from. The check has to render, not read: a page whose runtime
  never loaded still answers 200 with a body, so `ci/site-offline.sh` serves
  `site/` with every name but 127.0.0.1 mapped to NOTFOUND and asserts that
  text carried only by the logic script reaches the DOM. The first marker
  chosen was rejected by the check itself for also sitting in the static
  template, and the first render assertion passed with React deleted, because
  `--dump-dom` returns script elements with their text; the dump is stripped of
  them before the grep. — enforced by `ci/site-offline.sh`, run by `ci/run.sh`
  on every push, proved able to fail by adding an absolute script src, putting
  the font import back, and deleting each vendored React build in turn
- **Authority is built from what the caller observed, never from what the
  process is running under.** `Pinning` carries the observed permission mode
  and `GatewayRun::open` records that, rather than reading
  `CLAUDE_PERMISSION_MODE` itself; one function, `observed_permission_mode`,
  reads the variable and every other path takes it as an argument. This is the
  seam `policy::availability_check` already draws, and the gateway was the
  exception: because it read process-global state, the suite passed or failed
  according to the permission mode of the shell that launched it, and
  `cargo test` from inside a session whose mode diverges from
  `.claude/settings.json` failed on an assertion about divergence. A gate that
  fails for reasons invisible in the diff is one people learn to run somewhere
  else. Enforced by `tests/gateway.rs`
  (`the_observed_mode_reaches_the_event_from_the_pinning_and_not_the_environment`,
  which drives a diverging mode, a matching mode and no observation at all
  through a real run and reads the authority block off the event)
- **An arrow asserts a handoff, and an event records one end of it.** The trace
  view draws an edge only where a producer recorded a peer, in the one place a
  peer is read (`PEER_FIELD` in `assets/trace.js`), and holds no table mapping
  an event kind to a source and a destination lane. Every other event is a
  marker on a single lane, and the legend prints `inferred: 0` beside the
  observed count, because a diagram people trust has to say what it refused to
  draw. The picture is sparse, and the sparseness names the handoffs this
  system does not observe; the fix for a missing arrow is a producer recording
  a peer, never a renderer inferring one. Two things the same view must not do:
  paint one mark over another, since marks sharing a position are drawn as one
  carrying its count and the legend states marks against events on every
  render, and report a browser-side filter count as a statement about the log.
  Since slice 21 a decision names its own call: `policy.decision` carries
  `request_id` and `call_hash`, so a hold and the approval that answered it
  join on the record rather than on position in the log. Both readers were
  wrong before: the console reported the hold against the wrong call, and
  `gantry approve` refused the call the record held while writing a grant bound
  to a call nothing held, which the broker would then have released. A hole in
  a run's seq also reaches an operator surface for the first time, drawn apart
  from a fault because the record cannot tell a killed harness from an event a
  producer numbered and never wrote. Enforced by `tests/invariants.rs`
  (`the_trace_view_derives_no_edge_from_an_event_kind_alone`), `tests/broker.rs`
  (`a_decision_names_the_call_it_decided_rather_than_relying_on_adjacency`,
  `approve_binds_the_grant_to_the_call_the_decision_named`),
  `tests/console.rs`
  (`a_hold_is_correlated_by_the_recorded_call_and_not_by_position`,
  `verify_reports_a_seq_gap_and_the_ledger_still_reads_ok`) and
  `ci/console-render.sh`, whose every trace assertion was proved able to fail
  by breaking the thing it names; four of them did not, and `docs/proof/21.md`
  records what they were and what replaced them

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
