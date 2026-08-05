#!/bin/zsh
# Proof 07: kill a durable run mid-task, resume it, lose nothing, and read the
# seam off the ledger. Separately: the corpus graph versus a flat scan, token
# and accuracy delta, including the case where the stale graph loses. Run from
# the repository root after cargo build. No network needed.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof07.XXXXXX)
echo "workdir: $WORK"

echo "== part A: kill mid-run, resume, lose nothing =="
FILES=()
for n in 1 2 3 4 5; do
  f=$WORK/finding-$n.md
  echo "Finding $n: line $(seq -s' ' 1 $((n*3)))" > $f
  FILES+=($f)
done
L=$WORK/ledger

echo "-- run the 5-file audit, killed after 2 files --"
set +e
$BIN durable run $L audit 2 $FILES
echo "run exit=$? (137 = killed, run left unsealed)"
set -e

echo "-- resume from the ledger --"
$BIN durable resume $L audit $FILES

echo "-- the seam, read off the ledger --"
$BIN durable show $L audit

echo "-- nothing lost: the seal covers all 5 steps, 2 from before the kill --"
H=$(jq -rs '[.[] | select(.kind=="run.seal")] | last | .subject_hash' $L/events.jsonl | sed 's/^sha256://')
jq -c '{outcome, steps_completed, restored_from}' $L/payloads/$H.json
$BIN ledger verify $L

echo "-- offline inclusion of one pre-kill checkpoint --"
# The first checkpoint (index 1: run.open=0, checkpoint step0=1) predates the kill.
$BIN ledger prove $L 1 > $WORK/ckpt-bundle.json
cp $L/keys/ledger.pub $WORK/
(cd $WORK && sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  $OLDPWD/$BIN ledger verify-inclusion ckpt-bundle.json ledger.pub)

echo "== part B: corpus graph versus flat retrieval =="
CORPUS=$WORK/corpus
mkdir -p $CORPUS
for n in $(seq 1 12); do
  yes "boilerplate line $n describing an unrelated module for bulk " | head -80 > $CORPUS/mod-$n.txt
done
# One file defines the symbol we will query.
echo "pub fn reconcile_ledger() { /* the real definition */ }" >> $CORPUS/mod-7.txt
G=$WORK/corpus-graph.json
$BIN graph build $G $CORPUS/*.txt

echo "-- fresh: graph agrees with flat and reads far less --"
$BIN graph compare $G reconcile_ledger $CORPUS/*.txt

echo "-- the honest loss: a symbol added after indexing --"
echo "pub fn hotpatched_symbol_9x() {}" >> $CORPUS/mod-3.txt
$BIN graph compare $G hotpatched_symbol_9x $CORPUS/*.txt

echo "proof 07 run complete, workdir: $WORK"
