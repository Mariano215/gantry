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
# six views in a headless browser, and assert that values taken from that
# ledger appear in the rendered DOM. The values are read out of the ledger
# files at check time, never hardcoded, so the check cannot drift into
# asserting a constant.
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
SERVER=
typeset -A PIDS
# A failed assertion exits mid-loop, so the browsers still running are cleaned
# up here rather than at the end of the happy path. A check that leaves
# processes behind when it fails is a check people learn to skip.
cleanup() {
  local p
  for p in ${(v)PIDS}; do kill $p 2>/dev/null || true; done
  [ -n "$SERVER" ] && kill $SERVER 2>/dev/null
  rm -rf $WORK
}
trap cleanup EXIT

# -- the fixture ledger ------------------------------------------------------
#
# Two commands, two runs, eleven events. Enough for every view to have
# something real to render: a denial with a named rule, a sensor verdict and a
# capability run under a replayed rung. docs/proof/08-run.sh builds a
# 137-event ledger and takes far longer; this runs on every push, and the
# values under test are the same shapes.
echo "clean finding" > $WORK/art.md
$BIN broker call $L Bash "rm -rf /" >/dev/null 2>&1 || true
$BIN orchestrate step $L repo.write docs/proof/fixtures/no-private-key.json $WORK/art.md user:mariano@local >/dev/null

# The expected values, read off the ledger rather than written down here.
ROOT=$(tail -1 $L/heads.jsonl | jq -r .root_hash)
KEY=$(tail -1 $L/heads.jsonl | jq -r .key_id)
SIZE=$(tail -1 $L/heads.jsonl | jq -r .size)
RUN=$(jq -rs '[.[] | select(.kind=="run.open")] | last | .run_id' $L/events.jsonl)
RULE=$(jq -rs '[.[] | select(.kind=="policy.decision")] | last | .subject_hash' $L/events.jsonl \
  | sed 's/^sha256://' | xargs -I{} jq -r '.rule' $L/payloads/{}.json)
# The policy view joins the rules against the ledger and counts firings, so the
# count of rules that never fired is a number only that join can produce.
FIRED=$(jq -rs '[.[] | select(.kind=="policy.decision") | .subject_hash] | unique | .[]' $L/events.jsonl \
  | sed 's/^sha256://' | xargs -I{} jq -r '.rule' $L/payloads/{}.json | sort -u | wc -l | tr -d ' ')
NEVER=$(( $(jq '.rules | length' config/policy.json) - FIRED ))

# -- the server --------------------------------------------------------------

$BIN console $L 127.0.0.1:0 > $WORK/server.log 2>&1 &
SERVER=$!
ORIGIN=
for i in $(seq 1 50); do
  ORIGIN=$(sed -n 's|^console at \(http://[0-9.:]*\)/.*|\1|p' $WORK/server.log)
  [ -n "$ORIGIN" ] && break
  sleep 0.1
done
if [ -z "$ORIGIN" ]; then
  echo "the console server printed no address in 5s: $(cat $WORK/server.log). Fix: run \"$BIN console \$LEDGER 127.0.0.1:0\" by hand and read the failure"
  exit 1
fi

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
# The six renders run at once, each with its own profile directory, because
# browser startup dominates and six startups in series cost more than the rest
# of the gate. The console server answers one connection at a time, which is
# fine: the virtual clock pauses while a fetch is outstanding, so queueing
# costs wall-clock time and never a truncated page.
start_render() {
  local view=$1 out=$WORK/dom-$view.html
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
    --dump-dom "$ORIGIN/#/$view" > $out 2>$WORK/chrome-$view.log &
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
# the hole rather than nothing at all.
refute() {
  local view=$1 needle=$2
  if grep -qF -- "$needle" $WORK/dom-$view.html; then
    echo "the $view view rendered \"$needle\", which is a value that failed to resolve, not data. Fix: find the field in assets/views.js that produced it and reconcile it with the route in src/console.rs"
    exit 1
  fi
}

VIEWS=(overview ledger run policy trust verify)
for view in $VIEWS; do start_render $view; done
for view in $VIEWS; do
  collect_render $view
  refute $view '[object Object]'
  refute $view '>undefined<'
  refute $view '>NaN<'
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

echo "six views rendered against a $SIZE-event ledger; head, score, events, runs, policy, trust and verify all reached the screen"
