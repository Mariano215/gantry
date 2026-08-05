#!/bin/zsh
# The CI gate, runnable locally and by .github/workflows/ci.yml. Every check
# here is one a CLAUDE.md rule names; a rule whose check lives only in prose
# caps at maturity 3, which is this project's whole thesis. Run from the
# repository root. Requires the stable Rust toolchain and macOS (the sandbox
# tests exercise seatbelt).
set -e

echo "== format =="
cargo fmt --check

echo "== clippy, warnings are errors (carries the no-unwrap rule) =="
cargo clippy --all-targets -- -D warnings

echo "== offline suite (ci/offline-suite, ci/no-direct-sdk, ci/ledger-append-only via tests/invariants.rs and tests/ledger.rs) =="
cargo test

echo "== tracked policy parses, validates, and matches host deny entries (ci/policy-host-parity) =="
cargo run --quiet -- policy check config/policy.json .claude/settings.json

echo "== tracked template validates whole (a broken bundle refuses) =="
cargo run --quiet -- template validate templates/laptop

echo "== a regulated profile refuses to start on a machine that cannot provide what it declares (ci/profile-unavailable-refuses) =="
cargo build --quiet
reg_root=$(mktemp -d)
mkdir -p "$reg_root/config" "$reg_root/instructions"
printf 'you are an audit agent\n' > "$reg_root/instructions/pack.md"
# The tracked laptop policy with the regulated profile's declarations. None of
# microvm, oidc, rfc3161 or an hsm exists in this build, so this policy must
# not start here. The attestation block goes because the tracked seed is
# published, which a non-laptop profile refuses on its own; this check is
# about availability, not about the fixture key.
jq '.profile = "regulated"
  | .profile_requirements.isolation.declared = "microvm"
  | .profile_requirements.identity.declared = "oidc"
  | .profile_requirements.ledger.anchoring = "rfc3161"
  | .profile_requirements.ledger.key_custody = "hsm"
  | .profile_requirements.on_unavailable = "refuse"
  | del(.profile_requirements.attestation)' config/policy.json > "$reg_root/config/policy.json"
reg_bin="$PWD/target/debug/gantry"
if reg_out=$(cd "$reg_root" && "$reg_bin" broker call .ledger Read instructions/pack.md 2>&1); then
  reg_status=0
else
  reg_status=$?
fi
reg_events="$reg_root/.ledger/events.jsonl"
reg_appended=0
[ -s "$reg_events" ] && reg_appended=1
rm -rf "$reg_root"
# The exit status decides, not the text: a run that printed a refusal and then
# exited zero has started, and reading only the output would pass it.
if [ "$reg_status" = 0 ]; then
  echo "a regulated profile started on a machine with no microvm, no oidc, no rfc3161 and no hsm: $reg_out. Fix: profile_requirements.on_unavailable refuse must stop run open; see availability_check in src/policy.rs and its caller in BrokerRun::open"
  exit 1
fi
case "$reg_out" in
  *microvm*hsm*|*hsm*microvm*)
    ;;
  *)
    echo "the refusal did not name the unavailable requirements: $reg_out. Fix: the fault from availability_check must name every declared value this system cannot provide, so a human at 3am knows which requirement to fix"
    exit 1
    ;;
esac
if [ "$reg_appended" != 0 ]; then
  echo "the refused regulated run appended events. Fix: the availability check must run before the first append in BrokerRun::open"
  exit 1
fi
echo "the regulated profile refused to start (exit $reg_status) and named its unavailable requirements"

echo "== template init generates a per-install actor key and the harness it produces signs (ci/template-init-signs) =="
cargo build --quiet
gantry_bin="$PWD/target/debug/gantry"
init_root=$(mktemp -d)
cargo run --quiet -- template init templates/laptop "$init_root/harness" >/dev/null
if init_verify=$(cd "$init_root/harness" && "$gantry_bin" broker call .ledger Read instructions/pack.md >/dev/null && "$gantry_bin" ledger verify .ledger); then
  init_status=0
else
  init_status=$?
fi
rm -rf "$init_root"
# The exit status is checked before the output is, because verify prints its
# verified count and then exits non-zero on a fault. Reading only the text
# would pass a harness whose ledger does not check out.
if [ "$init_status" != 0 ]; then
  echo "the harness template init produced did not run and verify clean (exit $init_status): $init_verify. Fix: run gantry template init by hand into an empty directory and work through the first failing command"
  exit 1
fi
case "$init_verify" in
  *"attestations verified against config/actor-keys.json"*)
    ;;
  *)
    echo "the harness template init produced does not sign: $init_verify. Fix: gantry template init must generate an actor key, register it in config/actor-keys.json and declare it in profile_requirements.attestation; see generate_actor_key in src/main.rs"
    exit 1
    ;;
esac
case "$init_verify" in
  *"seed is published"*)
    echo "the generated harness signs under a published seed, so its attestations attribute nothing: $init_verify. Fix: init must generate a fresh seed per install and register it without seed_published, never ship the repository fixture key in templates/"
    exit 1
    ;;
esac
echo "the generated harness signs under a key only it holds: ${init_verify//$'\n'/; }"

echo "== sensor liveness sweep (ci/sensor-liveness-schedule): every tracked sensor rejects every negative control it declares and accepts every positive one =="
cargo run --quiet -- sensor live templates/laptop/config/sensors/*.json docs/proof/fixtures/no-private-key.json

echo "== permission-mode hook injects the observed mode into gantry commands, leaves everything else alone (ci/permission-mode-hook) =="
HOOK=.claude/hooks/permission-mode.sh
untouched=$(echo '{"tool_input":{"command":"echo hello"},"permission_mode":"acceptEdits"}' | $HOOK)
if [ "$untouched" != "{}" ]; then
  echo "hook rewrote a command with no gantry in it: $untouched. Fix: the case match in .claude/hooks/permission-mode.sh must only touch commands containing \"gantry\""
  exit 1
fi
no_mode=$(echo '{"tool_input":{"command":"echo gantry-hook-check"}}' | $HOOK)
if [ "$no_mode" != "{}" ]; then
  echo "hook rewrote a gantry command with no permission_mode observed: $no_mode. Fix: an absent signal must pass through untouched, never guessed"
  exit 1
fi
rewritten=$(echo '{"tool_input":{"command":"echo gantry-hook-check"},"permission_mode":"bypassPermissions"}' | $HOOK | jq -r '.hookSpecificOutput.updatedInput.command')
case "$rewritten" in
  "export CLAUDE_PERMISSION_MODE="*"bypassPermissions"*"echo gantry-hook-check")
    ;;
  *)
    echo "hook did not inject CLAUDE_PERMISSION_MODE into a gantry command: $rewritten. Fix: check the jq program in .claude/hooks/permission-mode.sh"
    exit 1
    ;;
esac
granted=$(echo '{"tool_input":{"command":"echo gantry-hook-check"},"permission_mode":"bypassPermissions"}' | $HOOK | jq -r '.hookSpecificOutput.permissionDecision // "none"')
if [ "$granted" != "none" ]; then
  echo "the permission-mode hook returned permissionDecision=$granted. Fix: remove it from .claude/hooks/permission-mode.sh; a hook that grants permission to every command containing \"gantry\" widens the session's authority past what .claude/settings.json declares, which is the drift this hook exists to measure"
  exit 1
fi
propagated=$(sh -c "$rewritten; printf '%s' \"\$CLAUDE_PERMISSION_MODE\"")
case "$propagated" in
  *bypassPermissions)
    ;;
  *)
    echo "the exported env var did not reach the rewritten command: $propagated. Fix: the injected prefix must be \"export VAR=val; \" so it survives the whole sh -c invocation"
    exit 1
    ;;
esac
echo "hook injects the observed mode, leaves unrelated and unobserved commands untouched, and the export propagates through the rewritten command"

echo "== the console renders ledger values, not just HTTP 200 (ci/console-render) =="
if ! zsh ci/console-render.sh; then
  echo "the operator console did not render values that came off the ledger. Fix: read the line above, which names the view and the missing value; the front end in assets/ and the route in src/console.rs have to move together, and docs/CONSOLE-API.md is the contract between them"
  exit 1
fi

echo "== every dependency has a note in docs/DEPENDENCIES.md =="
deps=$(sed -n '/^\[dependencies\]/,/^\[/p' Cargo.toml | grep -E '^[a-z0-9_-]+ *=' | cut -d= -f1 | tr -d ' ')
for dep in ${(f)deps}; do
  # Whole-word match: "sha" must not pass because "sha2" is documented.
  if ! grep -qE "(^|[^a-zA-Z0-9_-])${dep}([^a-zA-Z0-9_-]|$)" docs/DEPENDENCIES.md; then
    echo "dependency $dep has no entry in docs/DEPENDENCIES.md. Fix: add a row naming why it is here and its network/process capability"
    exit 1
  fi
done
echo "all $(echo $deps | wc -w | tr -d ' ') dependencies documented"

echo "== unenforced-rule census: CLAUDE.md markers are work items, not failures =="
count=$(grep -c 'UNENFORCED' CLAUDE.md || true)
echo "CLAUDE.md carries $count [UNENFORCED] marker line(s); gantry scan is expected to report them"

echo "ci gate passed"
