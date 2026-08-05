#!/bin/zsh
# Proof 19: two scoring levels that credit a control running, never what it
# found.
#
#   primitive 07 level 4: the policy held a call at an irreversible step and a
#                         human answered it on the record.
#   primitive 12 level 4: gantry drift walked the profile requirements and
#                         reported every field, and run open recorded what this
#                         machine could not provide.
#
# Proof 13 records what happens when a level is keyed on an outcome instead:
# the first instruction-lifecycle rule credited the sensor's failure message,
# so a repository whose control passed scored 3 and one whose control was
# broken scored 4, and the way to raise the number was to break the check.
# This script asserts the property that would have caught it. For each level,
# two ledgers that differ only in what the control found must score the same,
# and a ledger where the control never ran must score lower.
#
# Run from the repository root after cargo build. Fully offline: no model call,
# and the released publish command names a remote that does not exist, so it
# fails locally and reaches no network.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof19.XXXXXX)
PUBLISH='git push gantry-proof19-no-such-remote HEAD'
THRESHOLD=$(jq -r '.trust_budget.promotion.runs_at_rung' config/policy.json)
echo "clean finding" > $WORK/art.md
echo "workdir: $WORK"

score_of() { # ledger, primitive line prefix
  $BIN score $1 config/scoring.json 2>/dev/null \
    | awk -F'|' -v p="$2" 'index($2, p) {gsub(/ /,"",$3); print $3}'
}

# Levels 2 and 3 of primitive 07 first: capability runs, then a promotion under
# a named approver. Without them the climb stops below 4 and all three ledgers
# score alike, which would prove nothing.
promote() {
  local i=1
  while [ $i -le $THRESHOLD ]; do
    $BIN orchestrate step $1 repo.write docs/proof/fixtures/no-private-key.json \
      $WORK/art.md user:mariano@local >/dev/null
    i=$((i + 1))
  done
}

hold_a_call() { # ledger -> the request id of the held call
  $BIN broker call $1 Bash "$PUBLISH" >/dev/null 2>&1 || true
  local h=$(jq -rs '[.[] | select(.kind=="tool.request")] | last | .subject_hash' \
    $1/events.jsonl | sed 's/^sha256://')
  jq -r '.request_id' $1/payloads/$h.json
}

echo ""
echo "== primitive 07: the human gate =="

LA=$WORK/led-approved
promote $LA
REQ=$(hold_a_call $LA)
$BIN approve $LA $REQ user:mariano@local | head -1
$BIN broker call $LA Bash "$PUBLISH" >/dev/null 2>&1 || true
echo "approved:    primitive 7 score $(score_of $LA '07 Orchestration')"

LB=$WORK/led-refused
promote $LB
REQ=$(hold_a_call $LB)
$BIN approve $LB $REQ user:mariano@local deny | head -1
$BIN broker call $LB Bash "$PUBLISH" >/dev/null 2>&1 || true
echo "refused:     primitive 7 score $(score_of $LB '07 Orchestration')"

LC=$WORK/led-unanswered
promote $LC
hold_a_call $LC >/dev/null
echo "nobody looked: primitive 7 score $(score_of $LC '07 Orchestration')"

if [ "$(score_of $LA '07 Orchestration')" != "$(score_of $LB '07 Orchestration')" ]; then
  echo "FAIL: an approved call and a refused one scored differently, so the level pays for the answer"
  exit 1
fi
if [ "$(score_of $LC '07 Orchestration')" -ge "$(score_of $LA '07 Orchestration')" ]; then
  echo "FAIL: a held call nobody answered scored as high as one a human answered, so the level credits nothing"
  exit 1
fi
echo "approve and deny score the same ($(score_of $LA '07 Orchestration')); the unanswered hold scores $(score_of $LC '07 Orchestration')"

echo ""
echo "== the three ledgers, verbatim =="
for L in $LA $LB $LC; do
  echo "-- ${L:t} --"
  for H in $(jq -rs '[.[] | select(.kind=="approval")] | .[].subject_hash' $L/events.jsonl | sed 's/^sha256://'); do
    jq -c '{verdict, approver, call_hash: (.call_hash // null), decided: (.decided // null)}' $L/payloads/$H.json
  done
done

echo ""
echo "== primitive 12: the drift walk =="
# A denial first, so levels 2 and 3 are satisfied in all three ledgers.
cp -R config $WORK/config-diverged
jq '.profile_requirements.instruction_pack.declared = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' \
  config/policy.json > $WORK/config-diverged/policy.json

LD=$WORK/led-drift-clean
$BIN broker call $LD Bash "rm -rf /" >/dev/null 2>&1 || true
$BIN drift $LD config/policy.json | tail -1
echo "walk found no divergence: primitive 12 score $(score_of $LD '12 Governance')"

LE=$WORK/led-drift-diverged
$BIN broker call $LE Bash "rm -rf /" >/dev/null 2>&1 || true
$BIN drift $LE $WORK/config-diverged/policy.json | tail -1 || true
echo "walk found a divergence: primitive 12 score $(score_of $LE '12 Governance')"

LF=$WORK/led-no-drift
$BIN broker call $LF Bash "rm -rf /" >/dev/null 2>&1 || true
echo "walk never ran: primitive 12 score $(score_of $LF '12 Governance')"

if [ "$(score_of $LD '12 Governance')" != "$(score_of $LE '12 Governance')" ]; then
  echo "FAIL: a clean walk and a divergent one scored differently, so the level pays for the verdict"
  exit 1
fi
if [ "$(score_of $LF '12 Governance')" -ge "$(score_of $LD '12 Governance')" ]; then
  echo "FAIL: a ledger with no drift walk scored as high as one with a walk, so the level credits nothing"
  exit 1
fi
echo "match and divergence score the same ($(score_of $LD '12 Governance')); the unwalked ledger scores $(score_of $LF '12 Governance')"

echo ""
echo "== the availability half of primitive 12, verbatim =="
H=$(jq -rs '[.[] | select(.kind=="run.open")] | last | .subject_hash' $LD/events.jsonl | sed 's/^sha256://')
jq -c '{profile, unavailable}' $LD/payloads/$H.json

echo ""
echo "== the ledgers the scores were read from still verify =="
for L in $LA $LB $LC $LD $LE $LF; do
  echo "${L:t}: $($BIN ledger verify $L | head -1)"
done

echo ""
echo "proof 19 run complete, workdir: $WORK"
