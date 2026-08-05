#!/bin/zsh
# Proof 08: score the platform with itself. Build one ledger that exercises
# the layers, then run gantry score over it. The numbers come from telemetry,
# not from the profile name, so low numbers cannot be dressed up. Run from the
# repository root after cargo build. The one model call uses the local ollama
# endpoint; if it is down, primitives 2 and 3 score N/A, which is the honest
# result and the proof still runs.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof08.XXXXXX)
L=$WORK/ledger
echo "workdir: $WORK"

echo "== build one self-audit ledger across the layers =="

# Gateway: one real model call (primitives 2, 3, 11). Tolerated if offline.
$BIN run config/providers.json local $L 2>/dev/null && echo "gateway leg: ok" \
  || echo "gateway leg: skipped (no local model); primitives 2 and 3 will score N/A"

# Broker: a denial (12), a registration rejection (4), an allowed tainted call (4, 5, 11).
$BIN broker call $L Bash "rm -rf /" 2>/dev/null || true
cat > $WORK/loose.json <<'EOF'
{ "name": "shell.any", "description": "Run any shell command.", "inputSchema": { "type": "object" } }
EOF
$BIN broker register $L $WORK/loose.json 2>/dev/null || true
$BIN broker call $L Read docs/PLAN.md >/dev/null 2>&1 || true

# Sensor: a passing verdict and a broken sensor (10).
echo "clean finding" > $WORK/art.md
$BIN sensor gate $L docs/proof/fixtures/no-private-key.json $WORK/art.md >/dev/null 2>&1 || true
$BIN sensor gate $L docs/proof/fixtures/broken-sensor.json $WORK/art.md >/dev/null 2>&1 || true
# Instruction lifecycle (1): gate the real pack against the review record. A
# self-audit that never checks its own instructions has no lifecycle
# telemetry, and primitive 1 stays at 3 by the same rule that governs the
# rest: the score follows what ran.
$BIN sensor gate $L templates/laptop/config/sensors/instruction-lifecycle.json instructions/pack.md >/dev/null 2>&1 || true

# Orchestrator: enough clean runs to earn a promotion under a named approver (7).
THRESHOLD=$(jq -r '.trust_budget.promotion.runs_at_rung' config/policy.json)
i=1; while [ $i -le $THRESHOLD ]; do
  $BIN orchestrate step $L repo.write docs/proof/fixtures/no-private-key.json $WORK/art.md user:mariano@local >/dev/null
  i=$((i + 1))
done

# Skill: resolve against the managed key registry, then execute the steps
# as a delegated sub-agent run (8, 9).
$BIN skill run $L docs/proof/fixtures/skill-repo-audit repo.read,repo.write >/dev/null

# Graph: a ledgered retrieval, so context management is telemetry (3).
$BIN graph build $WORK/graph.json docs/CONCEPT.md docs/PLAN.md >/dev/null
$BIN graph query $L $WORK/graph.json harness >/dev/null

# Durable: a kill and a resume, so the seam is on the ledger (6).
for n in 1 2 3; do echo "step $n" > $WORK/s$n.md; done
set +e; $BIN durable run $L selfaudit 1 $WORK/s1.md $WORK/s2.md $WORK/s3.md >/dev/null 2>&1; set -e
$BIN durable resume $L selfaudit $WORK/s1.md $WORK/s2.md $WORK/s3.md >/dev/null

echo "== score the platform with itself =="
$BIN score $L config/scoring.json $WORK/console.html

echo "== the score.snapshot is itself on the ledger =="
jq -rs '[.[] | select(.kind=="score.snapshot")] | last | .subject_hash' $L/events.jsonl | sed 's/^sha256://' \
  | xargs -I{} cat $L/payloads/{}.json | jq -c '{overall, rules_version, events_scored}'

echo "== the ledger the score was read from still verifies =="
$BIN ledger verify $L | tail -1

echo "console at $WORK/console.html"
echo "proof 08 run complete, workdir: $WORK"
