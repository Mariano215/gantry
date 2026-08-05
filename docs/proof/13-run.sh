#!/bin/zsh
# Proof 13: instruction lifecycle telemetry. Primitive 1 was capped at 3
# because instructions/pack.md was pinned by hash on every run.open but
# nothing recorded whether a change to it had been reviewed. The
# instruction-lifecycle sensor (templates/laptop/config/sensors) compares an
# artifact's hash against config/instruction-reviews.jsonl and fails when the
# hash is not there.
#
# What earns level 4 is that the control ran, never that it failed. An
# earlier version of this rule credited 4 from the sensor's failure message,
# which meant a repository with a properly reviewed pack scored 3 and one
# with an unreviewed change scored 4. That is backwards and gameable: the way
# to raise the number would have been to break the review. The rule now names
# the sensor and not its outcome.
#
# So this script proves three things: a passing gate earns the level, a
# failing gate earns the same level and additionally blocks, and a ledger
# where the sensor never ran does not earn it at all. Run from the repository
# root after cargo build. No network needed; the one model call in
# `gantry run` is tolerated offline exactly as in proof 08.
set -e
BIN=./target/debug/gantry
SENSOR=templates/laptop/config/sensors/instruction-lifecycle.json
WORK=$(mktemp -d /tmp/gantry-proof13.XXXXXX)
echo "workdir: $WORK"

score_primitive1() {
  $BIN score $1 config/scoring.json 2>/dev/null | awk -F'|' '/01 Instruction/ {gsub(/ /,"",$3); print $3}'
}

echo "== the negative control for the scoring rule: a run that never gates its pack =="
L0=$WORK/ledger-ungated
$BIN run config/providers.json local $L0 >/dev/null 2>&1 || true
$BIN broker call $L0 Read docs/PLAN.md >/dev/null 2>&1 || true
echo "primitive 1 score: $(score_primitive1 $L0) (expected 3: pinned by hash, but no lifecycle control ran)"

echo ""
echo "== the pack matches its recorded review: the gate passes and the level is earned =="
cp instructions/pack.md $WORK/pack.md
L1=$WORK/ledger-baseline
$BIN sensor gate $L1 $SENSOR $WORK/pack.md
$BIN run config/providers.json local $L1 >/dev/null 2>&1 || true
echo "primitive 1 score: $(score_primitive1 $L1) (expected 4: the lifecycle control ran and passed)"

echo ""
echo "== attack: change the pack, do not update the review record =="
printf '\nAn unreviewed line, added straight to the working copy.\n' >> $WORK/pack.md
L2=$WORK/ledger-changed
if $BIN sensor gate $L2 $SENSOR $WORK/pack.md; then
  echo "gate passed, which should not happen for an unreviewed change"
  exit 1
else
  echo "gate blocked the unreviewed change, exit=$?"
fi
$BIN run config/providers.json local $L2 >/dev/null 2>&1 || true
echo "primitive 1 score: $(score_primitive1 $L2) (expected 4: the same level, because the level tracks the control running, not the outcome)"

echo ""
echo "== the score cannot be raised by breaking the review =="
if [ "$(score_primitive1 $L1)" != "$(score_primitive1 $L2)" ]; then
  echo "FAIL: a failing gate scored differently from a passing one, so the rule rewards breakage"
  exit 1
fi
echo "a passing gate and a failing gate score the same: $(score_primitive1 $L1). Only the ungated run scores lower."

echo ""
echo "== both verdicts, verbatim =="
last_subject() {
  local L=$1 kind=$2
  H=$(jq -rs "[.[] | select(.kind==\"$kind\")] | last | .subject_hash" $L/events.jsonl | sed 's/^sha256://')
  cat $L/payloads/$H.json
}
echo "-- passing verdict --"
last_subject $L1 sensor.verdict | jq -c '{sensor, verdict, message}'
echo "-- changed-pack verdict --"
last_subject $L2 sensor.verdict | jq -c '{sensor, verdict, message}'

echo ""
echo "== the sensor rejects its own negative control (it is not a sensor that cannot fail) =="
$BIN sensor live $SENSOR

echo ""
echo "== the ledgers score was read from still verify =="
$BIN ledger verify $L1 | head -2
$BIN ledger verify $L2 | head -2

echo ""
echo "proof 13 run complete, workdir: $WORK"
