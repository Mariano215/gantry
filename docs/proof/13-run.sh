#!/bin/zsh
# Proof 13: instruction lifecycle telemetry. Primitive 1 was capped at 3
# because instructions/pack.md was pinned by hash on every run.open but
# nothing recorded whether a change to it had been reviewed. The
# instruction-lifecycle sensor (templates/laptop/config/sensors) compares an
# artifact's hash against config/instruction-reviews.jsonl and fails when the
# hash is not there; config/scoring.json now credits level 4 from that fail
# verdict. This proves the score moves when the pack changes without review,
# and does not move when an unrelated file changes instead. Run from the
# repository root after cargo build. No network needed; the one model call
# in `gantry run` is tolerated offline exactly as in proof 08.
set -e
BIN=./target/debug/gantry
SENSOR=templates/laptop/config/sensors/instruction-lifecycle.json
WORK=$(mktemp -d /tmp/gantry-proof13.XXXXXX)
echo "workdir: $WORK"

score_primitive1() {
  $BIN score $1 config/scoring.json 2>/dev/null | awk -F'|' '/01 Instruction/ {gsub(/ /,"",$3); print $3}'
}

echo "== baseline: a working copy of the real instruction pack, matching its recorded review =="
cp instructions/pack.md $WORK/pack.md
L1=$WORK/ledger-baseline
$BIN sensor gate $L1 $SENSOR $WORK/pack.md
$BIN run config/providers.json local $L1 >/dev/null 2>&1 || true
echo "primitive 1 score: $(score_primitive1 $L1) (expected 3: version-pinned, no unreviewed change caught)"

echo ""
echo "== attack: change the pack, do not update the review record =="
printf '\nAn unreviewed line, added straight to the working copy.\n' >> $WORK/pack.md
L2=$WORK/ledger-changed
if $BIN sensor gate $L2 $SENSOR $WORK/pack.md; then
  echo "gate passed, which should not happen for an unreviewed change"
else
  echo "gate did not pass, exit=$?"
fi
$BIN run config/providers.json local $L2 >/dev/null 2>&1 || true
echo "primitive 1 score: $(score_primitive1 $L2) (expected 4: the sensor caught it)"

echo ""
echo "== control: edit prose that talks about the sensor, not the pack itself =="
cp instructions/pack.md $WORK/pack-untouched.md
echo "(a scratch note about this proof, not part of the instruction pack)" > $WORK/scratch-prose.md
L3=$WORK/ledger-prose
$BIN sensor gate $L3 $SENSOR $WORK/pack-untouched.md
$BIN run config/providers.json local $L3 >/dev/null 2>&1 || true
echo "primitive 1 score: $(score_primitive1 $L3) (expected 3: the pack itself never changed, so the sensor never fires)"

echo ""
echo "== both verdicts, verbatim =="
last_subject() {
  local L=$1 kind=$2
  H=$(jq -rs "[.[] | select(.kind==\"$kind\")] | last | .subject_hash" $L/events.jsonl | sed 's/^sha256://')
  cat $L/payloads/$H.json
}
echo "-- baseline verdict --"
last_subject $L1 sensor.verdict | jq -c '{sensor, verdict, message}'
echo "-- changed-pack verdict --"
last_subject $L2 sensor.verdict | jq -c '{sensor, verdict, message}'

echo ""
echo "== the sensor rejects its own negative control (it is not a sensor that cannot fail) =="
$BIN sensor live $SENSOR

echo ""
echo "== the ledgers score was read from still verify =="
$BIN ledger verify $L1 | tail -1
$BIN ledger verify $L2 | tail -1

echo ""
echo "proof 13 run complete, workdir: $WORK"
