#!/bin/zsh
# ci/site-offline: the published page fetches nothing from any host.
#
# The page prints "no hosted control plane, no licence check, no CDN font" and
# is the first thing anyone sees. As exported by the design tool it reached
# unpkg for React and fonts.googleapis.com for three families, which made that
# sentence false on the page carrying it. dev/build-site.py removes both. This
# is what keeps them removed.
#
# Two halves, because either alone reports green on a page that is broken.
#
#   Static: every script, stylesheet and image the page references is a
#   relative path, and the stylesheet has no @import and no off-origin url().
#   This catches the regression by reading, before anything is served.
#
#   Rendered: serve site/ on loopback and render it with a resolver that maps
#   every name but 127.0.0.1 to NOTFOUND, then assert text that exists only
#   inside the logic script appears in the DOM. A page whose React never
#   loaded still returns HTTP 200 and still has a <body>, so asserting on the
#   response would pass for a blank screen. Asserting on rendered text from
#   the script block is asserting that the runtime ran with no host reachable.
#
# The check does not skip when the browser is missing, for the same reason
# ci/console-render.sh does not: a render check that passes when nothing
# rendered is a dead sensor reporting green.
#
# Run from the repository root.
set -e

CHROME=${GANTRY_CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}
PORT=${GANTRY_SITE_PORT:-8742}
SITE=site

if [ ! -f $SITE/index.html ]; then
  echo "no built site at $SITE/index.html. Fix: run python3 dev/build-site.py"
  exit 1
fi
if [ ! -x "$CHROME" ]; then
  echo "no headless browser at \"$CHROME\". Fix: install Google Chrome, or set GANTRY_CHROME to a Chromium binary that supports --headless --dump-dom. This check does not skip: a page nobody rendered is not a page that renders offline"
  exit 1
fi

WORK=$(mktemp -d)
cleanup() {
  [ -n "$SERVER_PID" ] && kill $SERVER_PID 2>/dev/null
  rm -rf $WORK
}
trap cleanup EXIT

# ---- static: nothing the page loads is an absolute URL --------------------
# href on an <a> is a navigation the reader chooses, so only the tags a
# browser fetches on its own are checked.
absolute=$(grep -oE '<(script|link|img)[^>]*(src|href)="[a-z]+:?//[^"]*"' $SITE/index.html || true)
if [ -n "$absolute" ]; then
  echo "$SITE/index.html loads something off-origin:"
  echo "$absolute"
  echo "Fix: vendor it under $SITE/ and reference it by relative path; see dev/build-site.py"
  exit 1
fi
# Comments are stripped first: this file's own header says the word @import
# while describing the one it removed, and a check that cannot tell a comment
# from a statement fails on the sentence explaining it.
offsite_css=$(python3 - "$SITE/styles.css" <<'PY'
import re, sys
css = re.sub(r"/\*.*?\*/", "", open(sys.argv[1], encoding="utf-8").read(), flags=re.S)
for hit in re.findall(r"@import[^;]*;|url\(\s*['\"]?[a-z]+:?//[^)]*\)", css):
    print(hit.strip())
PY
)
if [ -n "$offsite_css" ]; then
  echo "$SITE/styles.css reaches off-origin: $offsite_css"
  echo "Fix: the Google Fonts @import is what this check was written for; dev/build-site.py removes it and the font stacks fall back to the platform's own"
  exit 1
fi
echo "static: every script, stylesheet and image is a relative path"

# ---- rendered: with nothing but loopback resolvable -----------------------
# The marker is read out of the logic script rather than hardcoded, and the
# check first proves it is not already in the served HTML outside that script.
# Otherwise a page that never mounted would still satisfy the assertion.
# The first marker tried was r-destructive-shell, and the check rejected it:
# the rule id also sits in the static template, so finding it in the DOM would
# have proved nothing. This one the policy simulator holds and nothing else.
marker="no approval on this ledger releases it"
in_script=$(python3 - "$SITE/index.html" "$marker" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
script = re.search(r'<script type="text/x-dc".*?</script>', html, re.S)
if not script:
    sys.exit("no <script type=\"text/x-dc\"> block in the page")
outside = html.replace(script.group(0), "").count(sys.argv[2])
print(f"{script.group(0).count(sys.argv[2])} {outside}")
PY
)
set -- ${(z)in_script}
if [ "$1" -lt 1 ]; then
  echo "the marker $marker is not in the page's logic script. Fix: pick a string from site/index.html's <script type=\"text/x-dc\"> block and set marker in ci/site-offline.sh; a marker the script does not carry proves nothing about the runtime"
  exit 1
fi
if [ "$2" -ne 0 ]; then
  echo "the marker $marker appears $2 times outside the logic script, so finding it in the DOM would not prove React mounted. Fix: pick a marker that only the script carries"
  exit 1
fi

python3 -m http.server $PORT --bind 127.0.0.1 --directory $SITE > $WORK/access.log 2>&1 &
SERVER_PID=$!
for i in $(seq 1 40); do
  curl -sf -o /dev/null http://127.0.0.1:$PORT/ && break
  sleep 0.25
done
if ! curl -sf -o /dev/null http://127.0.0.1:$PORT/; then
  echo "nothing answered on 127.0.0.1:$PORT in 10s. Fix: the port may be taken; set GANTRY_SITE_PORT"
  exit 1
fi

# --host-resolver-rules is the whole check: every name but loopback fails to
# resolve, so a page that needs a CDN cannot get one. The rest of the flags
# are the background traffic a browser makes on its own, the same set
# ci/console-render.sh documents.
"$CHROME" \
  --headless=new \
  --disable-gpu \
  --user-data-dir=$WORK/profile \
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
  --dump-dom "http://127.0.0.1:$PORT/" > $WORK/dom.html 2>$WORK/chrome.log &
CHROME_PID=$!

# --dump-dom does not exit on its own against a page with a running
# animation, so the dump is read as soon as it is complete.
for i in $(seq 1 120); do
  grep -q '</html>' $WORK/dom.html 2>/dev/null && break
  sleep 0.5
done
kill $CHROME_PID 2>/dev/null || true
wait $CHROME_PID 2>/dev/null || true

if ! grep -q '</html>' $WORK/dom.html; then
  echo "the page produced no DOM in 60s. Fix: run the render command in ci/site-offline.sh by hand against a served site/ and read $WORK/chrome.log"
  exit 1
fi
# The script elements come out of --dump-dom with their text, and the marker
# lives in one of them, so grepping the dump as it stands matches whether the
# runtime mounted or not. Proved by deleting site/vendor/react.production.min.js:
# the page rendered nothing and the assertion still passed.
python3 - "$WORK/dom.html" > $WORK/rendered.html <<'PY'
import re, sys
print(re.sub(r"<script\b.*?</script>", "", open(sys.argv[1], encoding="utf-8").read(),
             flags=re.S | re.I))
PY
if ! grep -q "$marker" $WORK/rendered.html; then
  echo "the page rendered with no host reachable but $marker never reached the DOM, so the runtime did not mount. Fix: site/vendor holds the React build site/support.js names; run python3 dev/build-site.py and read its output"
  exit 1
fi

# Every request the browser made reached this server, and this server only
# serves site/. A request that went anywhere else is absent here and would
# have had to fail, which is the point of the resolver rule above.
served=$(grep -c '" 200 -' $WORK/access.log || true)
echo "rendered: $served files served from loopback, DOM carries $marker, no name but 127.0.0.1 resolvable"
