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
  `ci/no-direct-sdk` is the CI form of the same check once CI exists
- **The ledger is append-only.** No code mutates or deletes a ledger entry.
  Retention is expiry of the payload under a retained hash, never a rewrite.
  — enforced by `ci/ledger-append-only`
- **Secrets never enter a prompt or a tool argument.** Agents hold handles.
  The broker substitutes at the boundary. — enforced since slice 04 by
  `src/secrets.rs`: a value reaches only the sandboxed child's environment,
  never the command string, an event or a Fault; a handle a capability does
  not declare is refused. Exercised by `tests/secrets.rs` and
  `tests/sandbox.rs`. The remaining gap is a scanner that greps every
  subject for a known secret value; `ci/secret-in-prompt` names it
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
  (`docs/proof/02.md` attack 5). The permission mode itself is still
  unobserved. — `[UNENFORCED]` `ci/permission-mode-drift`
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
- **A rung is derived, never stored.** The rung a capability holds is
  replayed from the ledger's `capability.run` and `rung.change` events, so a
  third party recomputes it from the signed record; promotion needs the
  clean-run threshold and a permitted approver, demotion is automatic on the
  next failure. — enforced since slice 06 by `src/trust.rs`
  (`TrustState::replay`, `Orchestrator::step`); exercised by `tests/trust.rs`
  and `docs/proof/06.md`. The gap: the derived rung is not yet consulted by
  the broker's gate, which still reads the static capability rung from the
  policy. — `[UNENFORCED]` `ci/gate-uses-earned-rung`
- **A sensor that cannot fail is broken, not clean.** Every sensor declares a
  negative control it must reject; a sensor that passes its own negative
  control is reported as `broken`, never as a clean pass, so a green board of
  dead sensors is impossible. — enforced since slice 05 by `src/sensor.rs`
  (`Sensor::is_live` runs before any trusted verdict); exercised by
  `tests/sensor.rs` and `docs/proof/05.md`. The gap: liveness is checked at
  evaluation time, not continuously, so a sensor that rots between runs is
  caught on next use, not immediately. — `[UNENFORCED]` `ci/sensor-liveness-schedule`
- **An attestation is verified or declared unverified, never assumed.** The
  ledger verifier checks actor attestations against a registered key once a
  key registry exists; until then it counts them and says so in every report.
  See `docs/proof/01.md` section 6. — `[UNENFORCED]` `ci/attestation-verify`

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
  — `[UNENFORCED]`

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
