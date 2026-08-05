#!/usr/bin/env python3
"""Serve assets/ over a fixture set, so the console can be driven before the
real API exists.

    python3 dev/serve.py                 # healthy fixtures on 8787
    python3 dev/serve.py tampered        # a ledger whose /api/verify says ok: false
    python3 dev/serve.py healthy 9000
    python3 dev/serve.py healthy grow    # a ledger that grows on every read,
                                         # so the live poll always repaints

This is developer tooling. It is never embedded in the binary and the Rust
build does not read it. It exists because two things in the console cannot be
exercised any other way before slice 10 lands: the four _attestation_state
values, and the takeover a ledger that fails verification triggers. Both are
rules the UI must never break, so both need a way to fail on demand.

Routing matches docs/CONSOLE-API.md: /api/* answers from the fixture set,
an unknown /api/* path is a 404 with a Fault body, and any other path serves
the console shell so the front end owns its own routing.
"""

import json
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, "assets")

ROUTES = {"score", "head", "events", "runs", "policy", "trust", "approvals", "verify"}

# Two console states need a click to reach, which a headless screenshot cannot
# do: the failure banner that follows dismissing the takeover, and the light
# theme. ?drive= injects one of these fixed snippets so both can be captured.
# The set is closed on purpose, since a dev server that evaluates arbitrary
# query text is a hole even in dev tooling.
DRIVE = {
    "proceed": "document.querySelectorAll('.takeover-actions .btn')[1].click();",
    "light": "localStorage.setItem('gantry-theme','light');document.documentElement.setAttribute('data-theme','light');",
    "dark": "localStorage.setItem('gantry-theme','dark');document.documentElement.setAttribute('data-theme','dark');",
    # j j j Enter: three moves down the selection, then expand. Proves the
    # keyboard path without a human at the keyboard.
    "keys": ("const k=(key)=>document.dispatchEvent(new KeyboardEvent('keydown',{key,bubbles:true}));"
             "k('j');k('j');k('j');k('Enter');"),
}


def fault(cause, fix):
    return {"cause": cause, "fix": fix}


class Handler(SimpleHTTPRequestHandler):
    fixtures = os.path.join(HERE, "fixtures", "healthy")
    # A third thing a headless dump cannot reach: what the live poll does to a
    # row the reader has open. The poll only repaints when the event set has
    # changed, and timing a real append against a page running on a virtual
    # clock is a race. Under `grow`, every /api/events answer carries one more
    # synthetic event than the last, so the first poll always repaints and the
    # question becomes deterministic.
    grow = False
    growth = 0

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ASSETS, **kw)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def load(self, name):
        with open(os.path.join(self.fixtures, name + ".json")) as f:
            return json.load(f)

    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path.startswith("/api/"):
            return self.api(url)
        # Unknown non-API paths serve the shell, same as the contract requires.
        if url.path != "/" and not os.path.isfile(os.path.join(ASSETS, url.path.lstrip("/"))):
            self.path = "/index.html"
        drive = parse_qs(url.query).get("drive", [None])[0]
        if drive in DRIVE:
            return self.shell_with(DRIVE[drive])
        return super().do_GET()

    def shell_with(self, snippet):
        with open(os.path.join(ASSETS, "index.html")) as f:
            html = f.read()
        html = html.replace(
            "</body>",
            f"<script type='module'>await new Promise(r=>setTimeout(r,700));{snippet}</script></body>",
        )
        body = html.encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api(self, url):
        parts = [p for p in url.path.split("/") if p][1:]  # strip "api"
        if not parts or parts[0] not in ROUTES:
            return self.send_json(
                fault(f"no such API route {url.path}",
                      "read docs/CONSOLE-API.md for the routes this console serves"),
                404,
            )
        name = parts[0]
        if name == "events" and len(parts) == 2:
            return self.one_event(parts[1])
        if name == "events":
            return self.events(parse_qs(url.query))
        return self.send_json(self.load(name))

    def one_event(self, ev_id):
        evs = self.load("events")["events"]
        for i, e in enumerate(evs):
            if e["id"] == ev_id:
                return self.send_json({"event": e, "index": i, "tree_size": len(evs)})
        return self.send_json(
            fault(f"no event with id {ev_id} is on this ledger",
                  "check the id against /api/events, or the ledger directory the server was pointed at"),
            404,
        )

    def grown(self, evs):
        """One more event than the previous answer, so a poll sees a change."""
        Handler.growth += 1
        last = evs[-1]
        for n in range(Handler.growth):
            e = json.loads(json.dumps(last))
            e["id"] = f"{last['id']}-grown-{n}"
            e["seq"] = last["seq"] + 1 + n
            evs = evs + [e]
        return evs

    def events(self, q):
        evs = self.load("events")["events"]
        if Handler.grow:
            evs = self.grown(evs)
        kinds = q.get("kind")
        if kinds:
            evs = [e for e in evs if e["kind"] in kinds]
        if q.get("run"):
            evs = [e for e in evs if e.get("run_id") == q["run"][0]]
        if q.get("actor"):
            needle = q["actor"][0]
            evs = [e for e in evs if needle in json.dumps(e.get("actor"))]
        if q.get("since"):
            evs = [e for e in evs if e["ts"] >= q["since"][0]]
        total = len(evs)
        try:
            offset = max(0, int(q.get("offset", ["0"])[0]))
            limit = min(1000, max(1, int(q.get("limit", ["200"])[0])))
        except ValueError:
            return self.send_json(
                fault("limit and offset must be integers",
                      "drop the parameter or pass a whole number"),
                400,
            )
        page = evs[offset:offset + limit]
        self.send_json({"events": page, "total": total, "returned": len(page), "offset": offset})


def main():
    args = [a for a in sys.argv[1:]]
    Handler.grow = "grow" in args
    args = [a for a in args if a != "grow"]
    which = args[0] if args and not args[0].isdigit() else "healthy"
    port = int(args[-1]) if args and args[-1].isdigit() else 8787
    Handler.fixtures = os.path.join(HERE, "fixtures", which)
    if not os.path.isdir(Handler.fixtures):
        sys.exit(f"no fixture set at {Handler.fixtures}; the sets are healthy and tampered")
    print(f"console: http://127.0.0.1:{port}/  fixtures: {which}")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
