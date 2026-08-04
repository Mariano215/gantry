#!/bin/zsh
# Proof 01 run script. Re-runnable: builds a throwaway ledger in a temp dir
# and attacks it. Run from anywhere; needs target/debug/gantry built first.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
G="$REPO/target/debug/gantry"
S="$(mktemp -d /tmp/gantry-proof01.XXXXXX)"
LED="$S/ledger"
OFF="$S/offline"
mkdir -p "$OFF" "$S/out"
echo "workdir: $S"

step() { echo "\n=== $1 ==="; }

auth='{"profile":"laptop","policy_version":"sha256:8f6ad5254987f97af4022c9291da4ac4a99df013d939d33b09019a4380619d63","instruction_version":"sha256:03f6dcd3bbd8b6035c1eba6e2d47a44e70bfef19c7c1b30a2b2ff9a09f04adaf","settings_hash":"sha256:8f6ad5254987f97af4022c9291da4ac4a99df013d939d33b09019a4380619d63","diverged":["host_permissions.permission_mode"]}'
actor_agent='{"type":"agent","id":"agent:claude-code","identity_source":"none","rung":null}'
actor_sys='{"type":"system","id":"system:gantry-ledger","identity_source":"none","rung":null}'
actor_human='{"type":"human","id":"user:mariano@local","identity_source":"local","rung":null}'

ev() { # id seq ts kind actor subject
  echo "{\"id\":\"$1\",\"run_id\":\"slice-01-proof\",\"parent_id\":null,\"seq\":$2,\"ts\":\"$3\",\"kind\":\"$4\",\"actor\":$5,\"authority\":$auth,\"subject\":$6,\"redacted\":[],\"attestation\":null}"
}

# flip one byte inside line $2 (0-based) of file $1, at the byte just after
# marker $3 within that line; fails loudly if the marker is absent
flip() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
path, line_no, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
data = open(path, 'rb').read()
lines = data.split(b'\n')
i = lines[line_no].find(marker)
if i < 0:
    sys.exit(f"marker {marker!r} not in line {line_no}")
off = sum(len(l) + 1 for l in lines[:line_no]) + i + len(marker)
orig = data[off:off+1]
new = b'X' if orig != b'X' else b'Y'
open(path, 'wb').write(data[:off] + new + data[off+1:])
print(f"flipped 1 byte, file offset {off}: {orig.decode()!r} -> {new.decode()!r}")
PY
}

step "init"
"$G" ledger init "$LED"

step "append 8 events"
ev p01-open   1 "2026-08-04T20:01:00.000Z" run.open      "$actor_human" '{"workload":"gantry/slice-01","harness":"claude-code","model":"claude-fable-5","instruction_pack":["CLAUDE.md"],"permission_mode_running":"bypassPermissions","restored_checkpoint":null}' | "$G" ledger append "$LED" > "$S/out/a1.json"
ev p01-req-1  2 "2026-08-04T20:01:05.000Z" tool.request  "$actor_agent" '{"tool_id":"Bash","schema_version":null,"args":{"command":"cargo test"},"capability":"repo.exec","sandbox_kind":"none","egress_allowlist_hash":null,"credential_handles":[]}' | "$G" ledger append "$LED" > "$S/out/a2.json"
ev p01-res-1  3 "2026-08-04T20:01:44.000Z" tool.result   "$actor_agent" '{"request_id":"p01-req-1","outcome":"ok","result_hash":"sha256:1f2a4b6c1f2a4b6c1f2a4b6c1f2a4b6c1f2a4b6c1f2a4b6c1f2a4b6c1f2a4b6c","taint":false,"duration_ms":39000}' | "$G" ledger append "$LED" > "$S/out/a3.json"
ev p01-dec-1  4 "2026-08-04T20:02:00.000Z" policy.decision "$actor_sys" '{"verdict":"deny","capability":"net.egress","rule":"deny[6]:Bash(curl:*)","request":{"tool":"Bash","target":"https://crates.io/api/v1/crates/gantry"},"identity":{"id":"user:mariano@local","source":"local"},"message":"denied by rule deny[6]; perform the lookup outside the run and paste the result"}' | "$G" ledger append "$LED" > "$S/out/a4.json"
ev p01-sen-1  5 "2026-08-04T20:02:20.000Z" sensor.verdict "$actor_sys" '{"sensor_id":"ghost/precheck","kind":"computational","placement":"pre-integration","verdict":"fail","blocked":true,"findings":[{"line":1,"col":16,"rule":"dashes"}],"message":"remove the em dash and rewrite the line"}' | "$G" ledger append "$LED" > "$S/out/a5.json"
ev p01-app-1  6 "2026-08-04T20:03:00.000Z" approval      "$actor_human" '{"approver":{"id":"user:mariano@local","source":"local","named":false},"verdict":"approve","decided":"schema v2 migration applied before ledger code","required_by":null,"elapsed_seconds":40}' | "$G" ledger append "$LED" > "$S/out/a6.json"
ev p01-drift  7 "2026-08-04T20:03:30.000Z" drift.report  "$actor_human" '{"field":"host_permissions.permission_mode","declared":"allow/ask/deny lists, .claude/settings.json","running":"bypassPermissions","observed_by":"none","detected_by":"operator statement in session","outcome":"divergence","message":"set the session permission mode to normal so the tracked ask entries take effect"}' | "$G" ledger append "$LED" > "$S/out/a7.json"
ev p01-seal   8 "2026-08-04T20:04:00.000Z" run.seal      "$actor_sys" '{"outcome":"complete","event_count":8,"events_omitted":0,"cost":null}' | "$G" ledger append "$LED" > "$S/out/a8.json"
echo "appended: $(wc -l < "$LED/events.jsonl" | tr -d ' ') events"
cp "$LED/events.jsonl" "$S/out/events.pristine"

step "verify clean"
"$G" ledger verify "$LED"; echo "exit=$?"

step "bundle for entry 4 (sensor.verdict), taken before any attack"
"$G" ledger prove "$LED" 4 > "$OFF/bundle.json"
cp "$LED/keys/ledger.pub" "$OFF/ledger.pub"

step "ATTACK 1: flip one byte of historical entry 3 (its ts, inside the envelope)"
flip "$LED/events.jsonl" 3 '"ts":"2026-08-04T20:02:0'
"$G" ledger verify "$LED"; echo "exit=$?"
cp "$S/out/events.pristine" "$LED/events.jsonl"

step "ATTACK 2: flip one byte of the newest entry (chain cannot see it, heads do)"
flip "$LED/events.jsonl" 7 '"kind":"run.sea'
"$G" ledger verify "$LED"; echo "exit=$?"
cp "$S/out/events.pristine" "$LED/events.jsonl"

step "ATTACK 3: truncate the log to 5 entries"
head -5 "$LED/events.jsonl" > "$LED/events.jsonl.tmp" && mv "$LED/events.jsonl.tmp" "$LED/events.jsonl"
"$G" ledger verify "$LED"; echo "exit=$?"
cp "$S/out/events.pristine" "$LED/events.jsonl"

step "ATTACK 4: tamper the newest entry AND delete the head that covers it"
cp "$LED/heads.jsonl" "$S/out/heads.pristine"
flip "$LED/events.jsonl" 7 '"kind":"run.sea'
head -7 "$LED/heads.jsonl" > "$LED/heads.jsonl.tmp" && mv "$LED/heads.jsonl.tmp" "$LED/heads.jsonl"
"$G" ledger verify "$LED"; echo "exit=$?"
cp "$S/out/events.pristine" "$LED/events.jsonl"
cp "$S/out/heads.pristine" "$LED/heads.jsonl"

step "ATTACK 5: silent payload deletion, no retention.expire on record"
target=$(python3 -c "
import json
line = open('$LED/events.jsonl').read().splitlines()[2]
print(json.loads(line)['subject_hash'])")
cp "$LED/payloads/${target#sha256:}.json" "$S/out/payload.bak"
rm "$LED/payloads/${target#sha256:}.json"
"$G" ledger verify "$LED"; echo "exit=$?"
cp "$S/out/payload.bak" "$LED/payloads/${target#sha256:}.json"

step "the lawful path: expire the same payload as a retention.expire event"
ev p01-exp 9 "2026-08-04T20:05:00.000Z" retention.expire "$actor_sys" "{\"expired\":\"$target\",\"rule\":\"retention/laptop-30d\",\"actor\":\"system:retention\"}" | "$G" ledger expire "$LED" "$target" > "$S/out/a9.json"
"$G" ledger verify "$LED"; echo "exit=$?"

step "OFFLINE: verify inclusion of entry 4 from bundle + pubkey only, network denied by sandbox"
cd "$OFF"
sandbox-exec -p '(version 1)(allow default)(deny network*)' "$G" ledger verify-inclusion bundle.json ledger.pub; echo "exit=$?"

step "OFFLINE: a tampered bundle must fail"
python3 - "$OFF/bundle.json" <<'PY'
import json, sys
p = sys.argv[1]
b = json.load(open(p))
b['envelope']['seq'] = 99
json.dump(b, open(p.replace('.json', '.tampered.json'), 'w'), separators=(',', ':'))
PY
sandbox-exec -p '(version 1)(allow default)(deny network*)' "$G" ledger verify-inclusion bundle.tampered.json ledger.pub; echo "exit=$?"

step "consistency: the size-4 head is a prefix of the size-9 tree"
old_head=$(sed -n '4p' "$LED/heads.jsonl")
echo "old head: $old_head"
"$G" ledger consistency "$LED" 4

echo "\nDONE"
