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

echo "== the verifier reports seq gaps, a consistency proof checks from the CLI, and an anchored head catches the rewrite verification alone misses (ci/ledger-seq-gap, ci/ledger-verify-consistency, ci/ledger-anchor) =="
cargo build --quiet
led_bin="$PWD/target/debug/gantry"
led_root=$(mktemp -d)
led="$led_root/led"
mkdir -p "$led_root/keep"
"$led_bin" ledger init "$led" >/dev/null
led_append() { # seq, run id: one tool.request, appended through the binary
  printf '{"id":"ev-%s-%s","run_id":"%s","parent_id":null,"seq":%s,"ts":"2026-08-05T09:00:0%s.000Z","kind":"tool.request","actor":{"type":"agent","id":"agent:ci","identity_source":"none","rung":null},"authority":{"profile":"laptop","policy_version":"sha256:aa","instruction_version":"sha256:bb","settings_hash":"sha256:cc","permission_mode":"default","diverged":[]},"subject":{"tool_id":"Read","n":%s},"redacted":[],"attestation":null}' \
    "$2" "$1" "$2" "$1" "$1" "$1" | "$led_bin" ledger append "$led" >/dev/null
}
# run-01 writes 0,1,2, dies, comes back at 5. run-02 is contiguous, so a check
# that fires on every run fails here rather than in production.
for s in 0 1 2 5 6; do led_append $s run-01; done
for s in 0 1 2; do led_append $s run-02; done
# The status is read before the text: a gap is a finding and must not change
# the exit code, because the chain and the heads are what say the log was
# altered, and they verify.
if gap_out=$("$led_bin" ledger verify "$led"); then gap_status=0; else gap_status=$?; fi
if [ "$gap_status" != 0 ]; then
  echo "a seq gap changed the exit status of ledger verify (exit $gap_status): $gap_out. Fix: a gap is reported and counted, never a fault; VerifyReport::ok in src/ledger.rs is a statement about the record's integrity and a never-written event did not alter anything"
  exit 1
fi
case "$gap_out" in
  *"seq gap in run run-01: last seq before the gap 2, next seq after it 5, 2 event(s) missing"*)
    ;;
  *)
    echo "ledger verify did not report the gap punched in run-01: $gap_out. Fix: seq_gaps in src/ledger.rs computes the holes and src/main.rs prints them; docs/EVENT-SCHEMA.md says a gap is the signal a harness was switched off mid-run, so nothing may carry that claim except this check"
    exit 1
    ;;
esac
case "$gap_out" in
  *run-02*)
    echo "ledger verify reported a gap in run-02, which has none: $gap_out. Fix: a check that fires on everything is as broken as one that never fires; seq_gaps reports interior holes only"
    exit 1
    ;;
esac
"$led_bin" ledger consistency "$led" 4 > "$led_root/bundle.json"
if ! cons_out=$("$led_bin" ledger verify-consistency "$led_root/bundle.json" "$led/keys/ledger.pub"); then
  echo "a consistency proof the ledger produced did not check out: $cons_out. Fix: gantry ledger consistency and gantry ledger verify-consistency must agree; both go through merkle::verify_consistency"
  exit 1
fi
sed 's/"proof":\["sha256:[0-9a-f]*"/"proof":["sha256:abababababababababababababababababababababababababababababababab"/' \
  "$led_root/bundle.json" > "$led_root/bundle.tampered.json"
if bad_out=$("$led_bin" ledger verify-consistency "$led_root/bundle.tampered.json" "$led/keys/ledger.pub"); then
  echo "a consistency proof with a hash the log never produced was accepted: $bad_out. Fix: verify_consistency_bundle in src/ledger.rs must reject it; a checker that only ever passes proves nothing"
  exit 1
fi
"$led_bin" ledger anchor "$led" "$led_root/keep/head.json" >/dev/null
if inside_out=$("$led_bin" ledger anchor "$led" "$led/head.json" 2>&1); then
  echo "anchoring into the ledger directory was permitted: $inside_out. Fix: Ledger::anchor refuses a destination under the ledger; a copy whoever rewrites the log also rewrites detects nothing"
  exit 1
fi
for s in 7 8 9; do led_append $s run-03; done
if ! anchor_out=$("$led_bin" ledger verify-anchor "$led" "$led_root/keep/head.json"); then
  echo "honest appends stopped agreeing with the anchored head: $anchor_out. Fix: an anchor must accept every log the anchored head is a prefix of, or it is noise"
  exit 1
fi
# The rewrite an anchor exists for: the writer drops its own tail and re-signs.
# Verification alone cannot see it, which is why the exit status of both
# commands is checked here and not just the second one.
head -5 "$led/events.jsonl" > "$led/events.new" && mv "$led/events.new" "$led/events.jsonl"
head -5 "$led/heads.jsonl" > "$led/heads.new" && mv "$led/heads.new" "$led/heads.jsonl"
for s in 5 6 7 8; do led_append $s run-09; done
if ! rewritten_out=$("$led_bin" ledger verify "$led"); then
  echo "the rewritten log failed verification, so this check no longer exercises what an anchor is for: $rewritten_out. Fix: rebuild the rewrite so the log stays internally consistent, then assert the anchor catches it"
  exit 1
fi
if caught=$("$led_bin" ledger verify-anchor "$led" "$led_root/keep/head.json"); then
  echo "a rewritten history still agreed with the anchored head: $caught. Fix: verify-anchor must fold the anchored root through the consistency proof; without that the ledger.anchor event is decoration"
  exit 1
fi
case "$caught" in
  *"consistency fails"*)
    ;;
  *)
    echo "verify-anchor rejected the rewrite without naming it: $caught. Fix: the message must name the rewrite and the restore, since an agent reads it"
    exit 1
    ;;
esac
rm -rf "$led_root"
echo "a punched seq gap is reported and stays a finding, a tampered consistency proof is refused, and an anchored head catches a rewrite the log verifies clean"

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
# dies would otherwise pass a check that reads only what it printed. The
# tracked policy has to come back clean, not merely run: this block first
# tolerated a divergence (exit 1) and proved the clean path against a corrected
# scratch copy instead, which left the gate green while config/policy.json
# declared a host permission hash .claude/settings.json had stopped having.
# A drift check that passes on the state it exists to catch is a dead sensor.
if [ "$drift_status" != 0 ]; then
  echo "gantry drift found the tracked policy out of step with this machine (exit $drift_status): $drift_out. Fix: the divergence line above names the field, both values and the change to make; correct config/policy.json or put the running system back"
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
# The clean path is the tracked run above and not a scratch copy. A control
# that rewrote the declared hash from the running system before comparing them
# would agree with itself on every push, which is the same mistake the egress
# row is reported unobservable for.
rm -rf "$drift_root"
echo "drift walked $(jq -r '.profile_requirements | keys | length' config/policy.json) field(s), reported every unreadable source as a gap, and both controls fired: ${drift_out##*$'\n'}"

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

echo "== the published page fetches nothing from any host (ci/site-offline) =="
if ! zsh ci/site-offline.sh; then
  echo "the page published to GitHub Pages reaches a host, or did not render without one. Fix: read the line above; site/ is built by python3 dev/build-site.py and is committed built, so a hand edit under site/ is lost on the next build"
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

echo "== a scoring level credits a control running, never what it found (ci/scoring-outcome-neutral) =="
# Proof 13's first scoring rule credited the instruction-lifecycle sensor's
# failure message: a repository whose control passed scored 3, one whose
# control was broken scored 4, and the way to raise the number was to break the
# check. This asserts the property that would have caught it, against the
# tracked rules and the real binary rather than against hand-written events.
# For each level that credits a control, two ledgers differing only in what the
# control found must score the same, and a ledger where it never ran must score
# lower. Statuses are read, not output text: the approve path must release the
# call and the deny path must not, and the divergent walk must exit non-zero,
# or the two ledgers being compared did not actually differ and the equality is
# worth nothing.
sc_bin="$PWD/target/debug/gantry"
sc_work=$(mktemp -d)
sc_publish='git push gantry-ci-no-such-remote HEAD'
echo "clean finding" > "$sc_work/art.md"
sc_score() { # ledger, primitive line prefix -> that primitive's score
  "$sc_bin" score "$1" config/scoring.json 2>/dev/null \
    | awk -F'|' -v p="$2" 'index($2, p) {gsub(/ /,"",$3); print $3}'
}
sc_hold() { # ledger -> the request id of a call the policy holds
  if "$sc_bin" broker call "$1" Bash "$sc_publish" >/dev/null 2>&1; then
    echo "the policy did not hold an irreversible call, so nothing here tests a human gate. Fix: vcs.publish is irreversible at rung led and gate() in src/policy.rs turns that into a pre gate; check config/policy.json still declares it"
    exit 1
  fi
  local h=$(jq -rs '[.[] | select(.kind=="tool.request")] | last | .subject_hash' \
    "$1/events.jsonl" | sed 's/^sha256://')
  jq -r '.request_id' "$1/payloads/$h.json"
}
# One base ledger carrying levels 2 and 3 of both primitives (capability runs,
# a promotion under a named approver, a named denial), copied per variant so
# the promotion is paid for once.
sc_base="$sc_work/base"
sc_i=1
sc_threshold=$(jq -r '.trust_budget.promotion.runs_at_rung' config/policy.json)
while [ $sc_i -le $sc_threshold ]; do
  "$sc_bin" orchestrate step "$sc_base" repo.write docs/proof/fixtures/no-private-key.json \
    "$sc_work/art.md" user:ci@local >/dev/null
  sc_i=$((sc_i + 1))
done
"$sc_bin" broker call "$sc_base" Bash "rm -rf /" >/dev/null 2>&1 || true

cp -R "$sc_base" "$sc_work/approved"
sc_req=$(sc_hold "$sc_work/approved")
if ! "$sc_bin" approve "$sc_work/approved" "$sc_req" user:ci@local >/dev/null; then
  echo "gantry approve refused to record an approval for a held call. Fix: run the command by hand and read the fault; approve() in src/main.rs pairs each tool.request with the decision that answers it"
  exit 1
fi
if ! "$sc_bin" broker call "$sc_work/approved" Bash "$sc_publish" >/dev/null 2>&1; then
  echo "an approved call was not released on retry, so this check is not comparing an approval with a refusal. Fix: usable_grant in src/broker.rs binds a grant to the call hash; see docs/proof/14.md"
  exit 1
fi
cp -R "$sc_base" "$sc_work/refused"
sc_req=$(sc_hold "$sc_work/refused")
"$sc_bin" approve "$sc_work/refused" "$sc_req" user:ci@local deny >/dev/null
if "$sc_bin" broker call "$sc_work/refused" Bash "$sc_publish" >/dev/null 2>&1; then
  echo "a recorded refusal released the call it refused. Fix: the broker consults grants only on the hold branch and a deny verdict releases nothing; see src/broker.rs"
  exit 1
fi
cp -R "$sc_base" "$sc_work/unanswered"
sc_hold "$sc_work/unanswered" >/dev/null
sc_yes=$(sc_score "$sc_work/approved" '07 Orchestration')
sc_no=$(sc_score "$sc_work/refused" '07 Orchestration')
sc_none=$(sc_score "$sc_work/unanswered" '07 Orchestration')
if [ "$sc_yes" != "$sc_no" ]; then
  echo "an approved call scored $sc_yes for primitive 07 and a refused one scored $sc_no. Fix: the level must name the gate having run, never the answer; a refusal is the gate working, and paying more for a yes rewards approving everything"
  exit 1
fi
if [ "$sc_none" -ge "$sc_yes" ]; then
  echo "a held call nobody answered scored $sc_none for primitive 07, against $sc_yes for one a human answered. Fix: the level credits nothing as written; note that a rung promotion writes its own approval event, so the predicate has to match on call_hash"
  exit 1
fi

cp -R config "$sc_work/config-diverged"
jq '.profile_requirements.instruction_pack.declared = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' \
  config/policy.json > "$sc_work/config-diverged/policy.json"
cp -R "$sc_base" "$sc_work/drift-clean"
if ! "$sc_bin" drift "$sc_work/drift-clean" config/policy.json >/dev/null; then
  echo "the drift walk over the tracked policy exited non-zero here, so the clean and divergent ledgers below are not distinguishable. Fix: ci/drift-honest above requires the tracked policy to come back clean; fix that first"
  exit 1
fi
cp -R "$sc_base" "$sc_work/drift-diverged"
if "$sc_bin" drift "$sc_work/drift-diverged" "$sc_work/config-diverged/policy.json" >/dev/null; then
  echo "a policy declaring an instruction pack hash the running system does not have walked clean. Fix: src/drift.rs must report a divergence and exit 1; a check comparing two clean walks proves nothing"
  exit 1
fi
cp -R "$sc_base" "$sc_work/no-drift"
sc_match=$(sc_score "$sc_work/drift-clean" '12 Governance')
sc_diverged=$(sc_score "$sc_work/drift-diverged" '12 Governance')
sc_unwalked=$(sc_score "$sc_work/no-drift" '12 Governance')
if [ "$sc_match" != "$sc_diverged" ]; then
  echo "a clean drift walk scored $sc_match for primitive 12 and a divergent one scored $sc_diverged. Fix: the level must name the walk having run, never its verdict; a ledger of matches and a ledger of divergences are the same control working"
  exit 1
fi
if [ "$sc_unwalked" -ge "$sc_match" ]; then
  echo "a ledger with no drift walk scored $sc_unwalked for primitive 12, against $sc_match for one with a walk. Fix: the level credits nothing as written"
  exit 1
fi
echo "primitive 07: approve and deny both score $sc_yes, an unanswered hold scores $sc_none. Primitive 12: match and divergence both score $sc_match, an unwalked ledger scores $sc_unwalked"

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
