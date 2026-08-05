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

echo "== gantry scan runs on this repo and every score names a path (ci/scan-evidence) =="
# The census CLAUDE.md asks for is now the scan's own output rather than a
# grep, and the check is that no number arrives bare: a score with nothing
# behind it is the exact failure this command exists to refuse.
# stderr is folded in so a fault arrives with its fix attached; only lines
# starting "primitive " are read as scores, so nothing else can pass for one.
if ! scan_out=$(cargo run --quiet -- scan . 2>&1); then
  echo "gantry scan failed on this repository: $scan_out. Fix: run cargo run -- scan . and read the fault; the scan only reads, so a failure here is a bug in src/scan.rs rather than repository state to clean up"
  exit 1
fi
scored=0
for line in ${(f)scan_out}; do
  case "$line" in
    "primitive "*)
      scored=$((scored + 1))
      fields=(${(s:|:)line})
      score=${fields[2]// /}
      evidence=${${fields[3]}//[[:space:]]/}
      if [ -z "$evidence" ]; then
        echo "gantry scan reported a score with nothing behind it: $line. Fix: every branch in src/scan.rs builds an evidence string naming either the artifact found or every path looked in; a number with no path is an opinion, which is what docs/PRIMITIVES.md refuses"
        exit 1
      fi
      case "$score" in
        [0-3]) ;;
        *)
          echo "gantry scan reported score '$score' for: $line. Fix: a static read resolves absent (0), an artifact (2) and an artifact a check names (3); 4 and above is a claim about a control running and only gantry score over a ledger can make it"
          exit 1
          ;;
      esac
      ;;
  esac
done
if [ "$scored" != 12 ]; then
  echo "gantry scan reported $scored primitive lines, expected 12. Fix: PROBES in src/scan.rs carries one entry per primitive in docs/PRIMITIVES.md, and the report prints all of them, scored or not"
  exit 1
fi
overall=$(echo "$scan_out" | sed -n 's/^overall \([0-9]*\) |.*/\1/p')
if [ "$overall" -gt 3 ]; then
  echo "the static scan of this repository scored overall $overall, above the ceiling a static read is allowed. Fix: a file shows a control is present, never that it ran; the telemetry score from zsh docs/proof/08-run.sh is the only number that can go higher, and a static scan that outranks it is measuring prose"
  exit 1
fi
echo "12 primitive scores, each with a path behind it, static overall $overall (telemetry, from gantry score over a real ledger, is the number that can exceed 3)"
echo "$scan_out" | sed -n '/UNENFORCED/,$p'

echo "ci gate passed"
