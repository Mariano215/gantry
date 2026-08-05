#!/bin/zsh
# Proof 06: a capability earns its way from assisted to autonomous on real
# sensor history, promoted by a named approver, then is demoted automatically
# by the next failure. The whole arc reads back out of the ledger as a story.
# Run from the repository root after cargo build. No network needed; the
# sensor is computational.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof06.XXXXXX)
L=$WORK/ledger
CAP=repo.write
SENSOR=docs/proof/fixtures/no-private-key.json
echo "workdir: $WORK"

# The tracked policy promotes after runs_at_rung clean runs at a rung.
THRESHOLD=$(jq -r '.trust_budget.promotion.runs_at_rung' config/policy.json)
APPROVER=user:mariano@local
echo "promotion threshold from config/policy.json: $THRESHOLD clean runs"

echo "== $THRESHOLD clean runs at assisted, promotion expected on the last =="
CLEAN=$WORK/clean-finding.md
echo "Finding: parser.py has no license header. No secrets present." > $CLEAN
i=1
while [ $i -le $THRESHOLD ]; do
  OUT=$($BIN orchestrate step $L $CAP $SENSOR $CLEAN $APPROVER | tail -1)
  if [ $i -eq 1 ] || [ $i -eq $THRESHOLD ] || [ $((i % 5)) -eq 0 ]; then
    echo "run $i: $OUT"
  fi
  i=$((i + 1))
done

echo "== the next run trips the sensor: automatic demotion =="
DIRTY=$WORK/leaky-finding.md
cat > $DIRTY <<'EOF'
Finding: a private key is committed.
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEF
-----END PRIVATE KEY-----
EOF
$BIN orchestrate step $L $CAP $SENSOR $DIRTY $APPROVER | tail -1

echo "== read the arc back out of the ledger =="
$BIN trust history $L $CAP

echo "== the approval that authorised the promotion =="
jq -rs '[.[] | select(.kind=="approval")] | last | .subject_hash' $L/events.jsonl | sed 's/^sha256://' \
  | xargs -I{} cat $L/payloads/{}.json | jq -c '{approver: .approver.id, verdict, decided}'

echo "== the rung.change events, verbatim =="
for h in $(jq -rs '[.[] | select(.kind=="rung.change")][].subject_hash' $L/events.jsonl | sed 's/^sha256://'); do
  jq -c '{from, to, trigger, approver}' $L/payloads/$h.json
done

echo "== the whole ledger verifies =="
$BIN ledger verify $L

echo "proof 06 run complete, workdir: $WORK"
