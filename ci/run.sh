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

echo "== drift walks profile_requirements against the running system, and a source it cannot read is a gap not a match (ci/drift-honest) =="
drift_root=$(mktemp -d)
# The sources src/drift.rs actually reads. Anything else must report
# unobservable, whatever the two values happen to be.
drift_readable="sandbox.active_backend gateway.instruction_hash hook.settings_hash ledger.head gateway.identity_source event.attestation.key_id"
if drift_out=$(cargo run --quiet -- drift "$drift_root/tracked" config/policy.json); then
  drift_status=0
else
  drift_status=$?
fi
# Exit status first, then the text. A command that prints a report and then
# dies would otherwise pass a check that reads only what it printed. 1 is the
# documented status for "a field diverged"; anything above it is a failure to
# run at all.
if [ "$drift_status" -gt 1 ]; then
  echo "gantry drift did not run against the tracked policy (exit $drift_status): $drift_out. Fix: run cargo run -- drift /tmp/drift-led config/policy.json by hand and work through the first failure it names"
  exit 1
fi
for field in ${(f)"$(jq -r '.profile_requirements | keys[]' config/policy.json)"}; do
  line=$(print -r -- "$drift_out" | grep "^$field: " || true)
  if [ -z "$line" ]; then
    echo "gantry drift reported nothing for profile_requirements.$field. Fix: every field reports every run, matches included; see walk in src/drift.rs"
    exit 1
  fi
  # A bare scalar requirement (rung_default) names no source at all, which is
  # the "none" case and must report as a gap like any other unread source.
  source=$(jq -r --arg f "$field" '.profile_requirements[$f] | if type == "object" then (.observed_by // "none") else "none" end' config/policy.json)
  case " $drift_readable " in
    *" $source "*) ;;
    *)
      case "$line" in
        "$field: unobservable"*) ;;
        *)
          echo "profile_requirements.$field names the source $source, which no code in src/drift.rs reads, and drift reported: $line. Fix: a source nothing reads reports unobservable, never a match; add a real observation to read in src/drift.rs or leave the field a declared gap"
          exit 1
          ;;
      esac
      ;;
  esac
done
# Both controls run on every push, because a check never seen red is a dead
# sensor reporting green.
cp -R config "$drift_root/config"
jq '.profile_requirements.isolation.observed_by = "netns.route_table"' config/policy.json > "$drift_root/config/policy.json"
blind=$(cargo run --quiet -- drift "$drift_root/blind" "$drift_root/config/policy.json" | grep "^isolation: " || true)
case "$blind" in
  "isolation: unobservable"*)
    ;;
  *)
    echo "isolation declared a value and named a source with no reader, and drift said: $blind. Fix: read in src/drift.rs must return Unreadable for netns.route_table; a match here means the check agrees with itself instead of observing anything"
    exit 1
    ;;
esac
jq '.profile_requirements.host_permissions.declared = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' config/policy.json > "$drift_root/config/policy.json"
if red=$(cargo run --quiet -- drift "$drift_root/red" "$drift_root/config/policy.json"); then
  red_status=0
else
  red_status=$?
fi
if [ "$red_status" != 1 ]; then
  echo "a policy declaring a host permission hash the running system does not have exited $red_status, not 1: $red. Fix: gantry drift exits 1 when any field diverges; see drift_scan in src/main.rs"
  exit 1
fi
case "$red" in
  *"host_permissions: divergence"*)
    ;;
  *)
    echo "a real divergence went unreported: $red. Fix: read in src/drift.rs must compare the declared host permission hash against hook.settings_hash"
    exit 1
    ;;
esac
settings_hash="sha256:$(shasum -a 256 .claude/settings.json | cut -d' ' -f1)"
jq --arg h "$settings_hash" '.profile_requirements.host_permissions.declared = $h' config/policy.json > "$drift_root/config/policy.json"
if clean=$(cargo run --quiet -- drift "$drift_root/clean" "$drift_root/config/policy.json"); then
  clean_status=0
else
  clean_status=$?
fi
rm -rf "$drift_root"
if [ "$clean_status" != 0 ]; then
  echo "a policy whose declared values match the running system still reported drift (exit $clean_status): $clean. Fix: the divergence line above names the field, both values and the change to make; config/policy.json declares something the running system no longer has"
  exit 1
fi
echo "drift walked $(jq -r '.profile_requirements | keys | length' config/policy.json) field(s), reported every unreadable source as a gap, and both controls fired: ${drift_out##*$'\n'}"

echo "== tracked template validates whole (a broken bundle refuses) =="
cargo run --quiet -- template validate templates/laptop

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
