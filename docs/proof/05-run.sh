#!/bin/zsh
# Proof 05: a failing sensor blocks a result; the agent reads the fix message
# and corrects the artifact on rerun with no human in the loop; both attempts
# are recorded. Then a sensor that cannot fail is reported broken, not clean.
# Run from the repository root after cargo build. The repair turn needs a
# model; it uses the local ollama endpoint in config/providers.json.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof05.XXXXXX)
echo "workdir: $WORK"

last_subject() {
  local L=$1 kind=$2
  H=$(jq -rs "[.[] | select(.kind==\"$kind\")] | last | .subject_hash" $L/events.jsonl | sed 's/^sha256://')
  cat $L/payloads/$H.json
}

echo "== attack 1: a findings document with an embedded private key =="
ART=$WORK/findings.md
cat > $ART <<'EOF'
# Audit findings for awesome-parser

Finding 1 (high): a private key is committed in the repository.

-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC
-----END PRIVATE KEY-----

Finding 2 (low): no license header on parser.py.
EOF
echo "-- the artifact before the gate --"
sed -n '3,9p' $ART

L=$WORK/ledger-repair
echo "-- the sensor gate with autonomous repair --"
if $BIN sensor repair $L docs/proof/fixtures/no-private-key.json $ART config/providers.json local; then
  echo "gate passed after repair, exit=0"
else
  echo "gate did not reach a pass, exit=$?"
fi
echo "-- the artifact after repair --"
grep -q 'BEGIN PRIVATE KEY' $ART && { echo "KEY STILL PRESENT"; } || echo "the private key block is gone from the repaired artifact"

echo "-- both verdicts on the ledger --"
jq -rs '[.[] | select(.kind=="sensor.verdict")] | length' $L/events.jsonl | xargs -I{} echo "sensor.verdict events: {}"
for h in $(jq -rs '[.[] | select(.kind=="sensor.verdict")][].subject_hash' $L/events.jsonl | sed 's/^sha256://'); do
  jq -c '{sensor, verdict, blocked}' $L/payloads/$h.json
done
last_subject $L run.seal | jq -c '{outcome, blocked_any, broken_any}'
$BIN ledger verify $L

echo "== attack 2: a sensor that cannot fail =="
L2=$WORK/ledger-broken
echo "harmless" > $WORK/clean.md
if $BIN sensor gate $L2 docs/proof/fixtures/broken-sensor.json $WORK/clean.md; then
  echo "gate returned pass"
else
  echo "gate returned non-pass, exit=$?"
fi
last_subject $L2 sensor.verdict | jq -e '.verdict == "broken"' >/dev/null \
  && echo "the always-green sensor is reported broken, not clean"
last_subject $L2 run.seal | jq -c '{outcome, broken_any}'
$BIN ledger verify $L2

echo "proof 05 run complete, workdir: $WORK"
