#!/bin/zsh
# ci/console-render: the console renders values that came off the ledger.
#
# Every other console check stops at the API boundary. tests/console.rs asserts
# the eight routes answer with the right shapes, and nothing asserts the front
# end reads them. A field renamed in src/console.rs would leave a blank cell on
# screen while every existing test still passed, which is the failure this
# check exists to catch.
#
# So: build a small ledger, serve it with the real binary, render each of the
# eight views in a headless browser, and assert that values taken from that
# ledger appear in the rendered DOM. The values are read out of the ledger
# files at check time, never hardcoded, so the check cannot drift into
# asserting a constant.
#
# Two things --dump-dom cannot do are covered by routing rather than by
# clicking. A row that expands on click is unreachable without a driver, but
# both the ledger view and the inbox open a row named in the URL, so
# #/ledger/<event id> and #/inbox/<call hash> render the expanded detail, and
# with it /api/events/:id. The verification takeover is covered by serving a
# second, altered ledger and rendering the same view against it: the takeover
# is what the router does before any view mounts, so no interaction is
# involved. What is still uncovered is anything that needs a real click, which
# is named at the end of docs/proof/20.md.
#
# Run from the repository root, after cargo build.
set -e

CHROME=${GANTRY_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}
BIN=target/debug/gantry

# A check that skips when the browser is missing is a dead sensor reporting
# green, which is the specific failure this project exists to prevent.
if [ ! -x "$CHROME" ]; then
  echo "no headless browser at \"$CHROME\". Fix: install Google Chrome, or set GANTRY_CHROME to a Chromium binary that supports --headless --dump-dom. This check does not skip: a console render check that passes when the browser is absent reports green for a page nobody rendered"
  exit 1
fi
if [ ! -x "$BIN" ]; then
  echo "no gantry binary at $BIN. Fix: run cargo build before ci/console-render.sh"
  exit 1
fi

WORK=$(mktemp -d /tmp/gantry-console-render.XXXXXX)
L=$WORK/ledger
TAMPERED=$WORK/tampered
SERVER=
BROKEN_SERVER=
typeset -A PIDS
# A failed assertion exits mid-loop, so the browsers still running are cleaned
# up here rather than at the end of the happy path. A check that leaves
# processes behind when it fails is a check people learn to skip.
cleanup() {
  local p
  for p in ${(v)PIDS}; do kill $p 2>/dev/null || true; done
  [ -n "$SERVER" ] && kill $SERVER 2>/dev/null
  [ -n "$BROKEN_SERVER" ] && kill $BROKEN_SERVER 2>/dev/null
  rm -rf $WORK
}
trap cleanup EXIT

# -- the fixture ledger ------------------------------------------------------
#
# A handful of commands over one ledger. Enough for every view to have
# something real to render: a denial with a named rule, a sensor verdict and a
# capability run under a replayed rung, and three held calls in three
# different states, because "nobody looked" and "somebody said no" are the
# distinction the inbox exists to draw. docs/proof/08-run.sh builds a
# 137-event ledger and takes far longer; this runs on every push, and the
# values under test are the same shapes.
#
# Nothing here executes a held call. A hold is refused until a grant releases
# it, and the one grant written below is never spent, so no git push runs and
# the check stays offline.
echo "clean finding" > $WORK/art.md
$BIN broker call $L Bash "rm -rf /" >/dev/null 2>&1 || true
$BIN orchestrate step $L repo.write docs/proof/fixtures/no-private-key.json $WORK/art.md user:mariano@local >/dev/null
$BIN broker call $L Bash "git push origin main" >/dev/null 2>&1 || true
$BIN broker call $L Bash "git push origin release" >/dev/null 2>&1 || true
$BIN broker call $L Bash "git push origin docs" >/dev/null 2>&1 || true

# Every payload of one kind, so a value can be selected by what it says rather
# than by its position in the file.
payloads() {
  jq -rs "[.[] | select(.kind==\"$1\") | .subject_hash] | .[]" $L/events.jsonl \
    | sed 's|^sha256:||' | xargs -I{} cat $L/payloads/{}.json
}
# The rule a decision with this verdict resolved to.
decision_rule() { payloads policy.decision | jq -rs "[.[] | select(.verdict==\"$1\") | .rule] | .[0]"; }
# The request id, and the call hash, of the Bash call with this command.
request_field() { payloads tool.request | jq -rs "[.[] | select(.args.command==\"$1\") | .$2] | .[0]"; }

REQ_REFUSED=$(request_field "git push origin release" request_id)
REQ_RELEASED=$(request_field "git push origin docs" request_id)
# One refusal and one grant, both on the record. The refusal releases nothing,
# which is why it is a state of its own on screen and not an absence.
$BIN approve $L $REQ_REFUSED user:mariano@local deny >/dev/null
$BIN approve $L $REQ_RELEASED user:mariano@local >/dev/null

# The expected values, read off the ledger rather than written down here.
ROOT=$(tail -1 $L/heads.jsonl | jq -r .root_hash)
KEY=$(tail -1 $L/heads.jsonl | jq -r .key_id)
SIZE=$(tail -1 $L/heads.jsonl | jq -r .size)
RUN=$(jq -rs '[.[] | select(.kind=="run.open")] | last | .run_id' $L/events.jsonl)
# Every event carrying that run id. The run view prints this as "N of N" from
# the total /api/events reports, so a run truncated at the page limit says so
# instead of looking whole.
RUN_EVENTS=$(jq -rs --arg r "$RUN" '[.[] | select(.run_id==$r)] | length' $L/events.jsonl)
RULE=$(decision_rule deny)
HOLD_RULE=$(decision_rule hold)
REQ_WAITING=$(request_field "git push origin main" request_id)
CALL_WAITING=$(request_field "git push origin main" call_hash)
# The event id of the last policy.decision, for the deep link that opens a row
# without a click.
EVENT_ID=$(jq -rs '[.[] | select(.kind=="policy.decision")] | last | .id' $L/events.jsonl)
EVENT_INDEX=$(jq -rs --arg id "$EVENT_ID" '[.[] | .id] | index($id)' $L/events.jsonl)
# The path the API prints in the approve command is the resolved one, and on a
# mac /tmp resolves through a symlink.
LEDGER_REAL=$(cd $L && pwd -P)
# The policy view joins the rules against the ledger and counts firings, so the
# count of rules that never fired is a number only that join can produce.
FIRED=$(payloads policy.decision | jq -rs '[.[] | .rule] | unique | length')
NEVER=$(( $(jq '.rules | length' config/policy.json) - FIRED ))

for v in ROOT KEY SIZE RUN RULE HOLD_RULE REQ_WAITING CALL_WAITING EVENT_ID; do
  if [ -z "${(P)v}" ] || [ "${(P)v}" = "null" ]; then
    echo "the fixture ledger produced no $v, so the assertions below would test nothing. Fix: run the broker and approve commands at the top of ci/console-render.sh by hand against a fresh ledger and read the failure"
    exit 1
  fi
done

# -- the same ledger, with one event altered ---------------------------------
#
# The console's strongest claim is negative: it cannot render a broken ledger
# as a healthy one. That claim is checked by breaking one, which is a copy
# with one actor id rewritten in place. The edit is inside a string, so the
# envelope still parses and only the hashes give it away, and the check
# refuses to continue if the file did not actually change.
cp -R $L $TAMPERED
sed '3s|"id":"|"id":"tampered-|' $L/events.jsonl > $TAMPERED/events.jsonl
if cmp -s $L/events.jsonl $TAMPERED/events.jsonl; then
  echo "the tampered ledger is identical to the clean one, so the takeover assertions would pass against a sound ledger. Fix: the sed above no longer matches the envelope shape; alter one stored event by hand and re-run"
  exit 1
fi
BROKEN_ID=$(sed -n 3p $L/events.jsonl | jq -r .id)

# -- the server --------------------------------------------------------------

origin_of() {
  local log=$1 i origin=
  for i in $(seq 1 50); do
    origin=$(sed -n 's|^console at \(http://[0-9.:]*\)/.*|\1|p' $log)
    [ -n "$origin" ] && break
    sleep 0.1
  done
  if [ -z "$origin" ]; then
    echo "the console server printed no address in 5s: $(cat $log). Fix: run \"$BIN console \$LEDGER 127.0.0.1:0\" by hand and read the failure"
    exit 1
  fi
  echo $origin
}

$BIN console $L 127.0.0.1:0 > $WORK/server.log 2>&1 &
SERVER=$!
ORIGIN=$(origin_of $WORK/server.log)

# The second server, over the altered copy. Same binary, same routes; the only
# difference is a record that does not check out.
$BIN console $TAMPERED 127.0.0.1:0 > $WORK/broken.log 2>&1 &
BROKEN_SERVER=$!
BROKEN_ORIGIN=$(origin_of $WORK/broken.log)

# -- rendering ---------------------------------------------------------------
#
# Flags, and why each one is here. The air-gap claim is the reason this list is
# long: a browser that phones home during a check that asserts the console
# never leaves the origin would make the check a liar.
#
#   --headless=new --dump-dom     render without a display, print the DOM after
#                                 scripts have run, which is the whole point:
#                                 the shell alone is 2.4kB of static HTML and
#                                 carries none of the values asserted below
#   --virtual-time-budget         run the page clock forward fast so the fetch
#                                 chain completes before the dump, without
#                                 sleeping for real seconds. Under the five
#                                 second mark on purpose, so the ledger view's
#                                 live poll never fires mid-dump
#   --user-data-dir               a throwaway profile under $WORK, so no state
#                                 from a developer's browser reaches the check
#                                 and none is left behind
#   --host-resolver-rules         every host but loopback fails to resolve. If
#                                 an asset ever grows an external reference,
#                                 this is what turns it into a visible failure
#                                 rather than a silent fetch
#   --disable-background-networking, --disable-component-update,
#   --disable-sync, --disable-domain-reliability, --no-pings,
#   --safebrowsing-disable-auto-update, --disable-client-side-phishing-detection,
#   --metrics-recording-only, --disable-breakpad, --disable-crash-reporter
#                                 the background traffic a browser makes on its
#                                 own: update checks, sync, metrics, crash
#                                 upload. Observed on the first run of this
#                                 check: without these, Chrome started
#                                 GoogleUpdater and a GCM registration
#   --no-first-run, --no-default-browser-check, --disable-default-apps
#                                 first-run work that would otherwise fetch and
#                                 would also hold the process open
#   --password-store=basic, --use-mock-keychain
#                                 keep a fresh profile off the macOS keychain,
#                                 which can block on a prompt no CI runner can
#                                 answer
#
# --dump-dom does not exit the browser on its own here, so the dump is read as
# soon as it is complete (it ends with </html>) and the process is killed.
#
# The renders run several at a time, each with its own profile directory,
# because browser startup dominates and eleven startups in series cost more
# than the rest of the gate. The console server answers one connection at a
# time, which is fine: the virtual clock pauses while a fetch is outstanding,
# so queueing costs wall-clock time and never a truncated page. The wave size
# is a real limit rather than a tidy-up: eleven browsers at once starved each
# other on this machine and one of them produced no DOM at all inside a
# minute, which the check reported as a failure, correctly.
# start_render <name> [route] [origin]. The name is the file the DOM lands in
# and the default route; a route with a slash in it (a deep link that opens a
# row) needs the two to differ.
start_render() {
  local view=$1 route=${2:-$1} origin=${3:-$ORIGIN} out=$WORK/dom-$view.html
  "$CHROME" \
    --headless=new \
    --disable-gpu \
    --user-data-dir=$WORK/chrome-profile-$view \
    --no-first-run \
    --no-default-browser-check \
    --disable-default-apps \
    --disable-background-networking \
    --disable-component-update \
    --disable-client-side-phishing-detection \
    --disable-sync \
    --disable-domain-reliability \
    --safebrowsing-disable-auto-update \
    --metrics-recording-only \
    --disable-breakpad \
    --disable-crash-reporter \
    --no-pings \
    --password-store=basic \
    --use-mock-keychain \
    --host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" \
    --virtual-time-budget=4000 \
    --dump-dom "$origin/#/$route" > $out 2>$WORK/chrome-$view.log &
  # Through a local first: zsh stores the literal "$!" when it is assigned
  # straight into an associative array element.
  local pid=$!
  PIDS[$view]=$pid
}

collect_render() {
  local view=$1 out=$WORK/dom-$view.html i
  for i in $(seq 1 600); do
    grep -q '</html>' $out 2>/dev/null && break
    sleep 0.1
  done
  kill $PIDS[$view] 2>/dev/null || true
  wait $PIDS[$view] 2>/dev/null || true
  if ! grep -q '</html>' $out 2>/dev/null; then
    echo "the $view view produced no DOM in 60s. Fix: run the render command in ci/console-render.sh by hand against a served ledger and read $WORK/chrome-$view.log"
    exit 1
  fi
}

# A value the API returned had to travel through fetch, through the view that
# builds the row, and into the document for this to match.
expect() {
  local view=$1 needle=$2 why=$3
  if ! grep -qF -- "$needle" $WORK/dom-$view.html; then
    echo "the $view view rendered without \"$needle\" ($why). Fix: the front end reads a field the API no longer returns under that name. Compare the route in src/console.rs against docs/CONSOLE-API.md and assets/views.js; a rename on either side is a schema change and both sides move together"
    exit 1
  fi
}

# The other half of the same rule: a reshape that leaves a hole often renders
# the hole rather than nothing at all. The optional third argument is for a
# needle that is not a placeholder but a state the page must not have reached,
# an empty table that has rows on this ledger being the case that caught a
# field nothing else could see.
refute() {
  local view=$1 needle=$2
  local why=${3:-"a value that failed to resolve, not data. Fix: find the field in assets/views.js that produced it and reconcile it with the route in src/console.rs"}
  if grep -qF -- "$needle" $WORK/dom-$view.html; then
    echo "the $view view rendered \"$needle\", which is $why"
    exit 1
  fi
}

typeset -A ROUTE ORIGIN_OF
VIEWS=(overview ledger run trace policy trust inbox verify)
for view in $VIEWS; do ROUTE[$view]=$view; ORIGIN_OF[$view]=$ORIGIN; done
# The four routes that reach what a plain view does not: a run's own waterfall,
# a ledger row opened by its event id, a hold opened by its call hash, and the
# takeover the router renders instead of a view when the served ledger does
# not check out.
ROUTE[rundetail]="run/$RUN"; ORIGIN_OF[rundetail]=$ORIGIN
ROUTE[eventrow]="ledger/$EVENT_ID"; ORIGIN_OF[eventrow]=$ORIGIN
ROUTE[holdrow]="inbox/$CALL_WAITING"; ORIGIN_OF[holdrow]=$ORIGIN
ROUTE[takeover]="overview"; ORIGIN_OF[takeover]=$BROKEN_ORIGIN

ALL=($VIEWS rundetail eventrow holdrow takeover)
WAVE=4
i=1
while (( i <= $#ALL )); do
  batch=(${ALL[i,i+WAVE-1]})
  for view in $batch; do start_render $view ${ROUTE[$view]} ${ORIGIN_OF[$view]}; done
  for view in $batch; do
    collect_render $view
    refute $view '[object Object]'
    refute $view '>undefined<'
    refute $view '>NaN<'
  done
  (( i += WAVE ))
done

# Overview: /api/head and /api/score, rendered.
expect overview "$ROOT" "the signed tree head panel prints the root hash /api/head returned"
expect overview "$KEY" "the head chip and the tree head panel name the signing key"
expect overview "class=\"stat-v\">$SIZE<" "the ledger size stat carries the head size, as a number and not a dash"
expect overview "policy.decision" "the kind breakdown counts events off /api/events"

# Ledger: /api/events with its inlined subject and derived attestation state.
expect ledger "$RUN" "each row links to the run its event carries"
expect ledger "$RULE" "the subject summary names the rule the denial resolved to, so _subject reached the row"
expect ledger "att-verified" "the four attestation states render distinctly, and this ledger is signed"
# This fixture ledger is signed under the tracked laptop key, whose seed is
# published, so /api/events returns _attestation_trust of "fixture" on every
# row. The console has to qualify the badge with it. A laptop run and an
# HSM-backed deployment rendering identically is the exact claim the ledger
# exists to rule out, and until this line existed the field was returned by
# the API and read by nothing.
expect ledger "verified (fixture)" "a verified signature under a published seed is qualified on screen, so _attestation_trust reached the row"

# Run: /api/runs.
expect run "$RUN" "the run list is built from run.open and run.seal"
expect run "derived from run.open and run.seal" "the run view mounted rather than faulting"

# Run detail: the waterfall, and the count that says whether it is the whole
# run. /api/events answers at most 1000 rows and reports how many matched, so
# a run longer than that is drawn in part; the view prints both numbers, and
# this fixture's run is short enough that they are equal. A run that showed a
# thousand rows and said nothing would be a complete-looking rendering of an
# incomplete read, which on this product is the worse failure.
expect rundetail "$RUN_EVENTS of $RUN_EVENTS" "the waterfall names how many of the run's events it drew, so truncation at the page limit cannot be silent"
expect rundetail "so this waterfall is the whole run" "the untruncated case says so rather than leaving the reader to assume it"

# Trace: one lane per actor that wrote an event. The labels are read off the
# fixture ledger at check time, so this cannot drift into asserting a
# constant, and a lane the view invented would not be in this list.
for actor in ${(f)"$(jq -rs '[.[].actor.id] | unique | .[]' $L/events.jsonl)"}; do
  expect trace "$actor" "a lane is an actor that wrote an event on the fixture ledger"
done
expect trace "lanes," "the trace panel names how many lanes it drew and how many events of the total"
expect trace "$HOLD_RULE" "a mark carries its subject summary, so the held decision names its rule on the lane"
expect trace "edges observed" "the legend states how many edges the record carried"
expect trace "inferred: 0" "the legend states what the picture refused to draw, not only what it drew"
# The fixture runs Bash calls, so a tool lane exists and an edge reaches it.
expect trace "tool:Bash" "a peer lane created from the tool a tool.request recorded"
refute trace "0 edges observed" "an edge count of zero on a ledger whose tool.request events name a tool, so the peer never resolved"

# Policy: /api/policy, including the firing count joined off the ledger.
expect policy "$RULE" "the rule table lists the rule that denied the call"
expect policy "repo.write" "the capability table lists the declared capabilities"
expect policy "$NEVER never fired" "the firing counts the policy route joins off the ledger reached the screen"

# Trust: /api/trust, the rung replayed rather than read from config.
expect trust "repo.write" "the trust table lists the capability the orchestrator stepped"
expect trust "assisted" "the declared and earned rungs both render"
# This fixture makes a denied call, and a denial costs the capability a rung,
# so declared and earned differ here. That is the stronger assertion: the page
# can only say this if both fields arrived and were compared.
expect trust "the broker gates on the earned rung" "declared and earned are compared on screen, and the denial in this fixture moved one of them"

# Verify: /api/verify, and the offline command the console must print verbatim.
expect verify "gantry ledger verify" "the reproduce command is printed verbatim, not paraphrased"
expect verify "class=\"stat-v\">$SIZE<" "the entry count the server checked is on screen as a number"
expect verify "$ROOT" "the head the verification ran against is printed in full"

# Inbox: /api/approvals, the held calls and what the record says about each.
expect inbox "$HOLD_RULE" "the rule that held the call names itself on screen"
expect inbox "vcs.publish" "the capability the hold gated is on the row"
expect inbox "git push origin main" "the call itself is on the row, so an approver reads what they are answering"
expect inbox "user:mariano@local" "the approver of the recorded answers is named"
# The three states the fixture builds. A held call nobody answered and a held
# call somebody refused are different rows with different words, because
# "nobody looked" and "somebody said no" are different states and a console
# that merged them would lose the distinction the approval path is built on.
expect inbox ">waiting<" "a hold with no approval event naming it says nobody has answered"
expect inbox ">refused<" "a recorded deny is a state on screen and not an absence"
expect inbox ">released<" "a usable grant on the ledger reads as released, waiting for the retry"
expect inbox "nobody has looked" "the count of unanswered holds is derived and shown"
# Which table a hold lands in is decided by releases_next_call, and a hold in
# the wrong table still reads correctly in its own row, so the split is
# asserted through the empty state of a table that has rows on this ledger.
# Nothing else here could see that field move.
refute inbox "no grant on this ledger releases a call right now" \
  "the empty state of a table this ledger has a row for. Fix: compare releases_next_call in the /api/approvals route in src/console.rs against the partition in assets/views.js"
refute inbox "no held call on this ledger is waiting" \
  "the empty state of a table this ledger has two rows for. Fix: compare releases_next_call in the /api/approvals route in src/console.rs against the partition in assets/views.js"
# Read-only, and it says so. The console prints the command; a human runs it.
expect inbox "Why there is no approve button here" "the view states the reason it writes nothing, rather than merely not doing it"

# The hold opened by its call hash: the detail behind a click, reached by
# route instead. This is the copyable command, which is the whole point of an
# inbox: without it an operator greps a ledger to find out a run is blocked.
expect holdrow "gantry approve $LEDGER_REAL $REQ_WAITING" "the exact command that resolves the hold is rendered whole, naming the ledger being served and the request this one recorded, so it is runnable as printed"
expect holdrow "$CALL_WAITING" "the call hash a grant binds to is on the detail, because the request id is not what a grant names"

# The ledger row opened by its event id: the expanded detail, and with it
# /api/events/:id, which nothing rendered until this route existed.
expect eventrow "position" "the expanded row asks /api/events/:id where the event sits"
expect eventrow "$EVENT_INDEX of $SIZE" "the position came from /api/events/:id and not from the row's own index"
expect eventrow "$HOLD_RULE" "the expanded subject is the stored payload, pretty-printed"
expect eventrow "ed25519" "the attestation block renders the algorithm and key id off the envelope"

# The takeover: the same binary over a ledger with one altered event. This is
# the console's strongest claim and it is negative, so it is checked by
# breaking a ledger rather than by reading the code that would refuse one.
expect takeover "This ledger failed verification" "a ledger the server reported ok:false takes the interface over"
expect takeover "$BROKEN_ID" "the fault table names the altered event, off the verification report"
expect takeover "gantry ledger verify" "the takeover prints the offline command that reaches the same verdict without the server"
expect takeover "It cannot be dismissed" "the banner that survives the dismissal is stated on the takeover itself"
# The load-bearing half: the scorecard must not be behind it.
refute takeover 'The twelve primitives'
refute takeover 'Attestation coverage'

echo "eight views, two deep-linked rows and the takeover rendered against a $SIZE-event ledger; head, score, events, events/:id, runs, policy, trust, approvals and verify all reached the screen"
