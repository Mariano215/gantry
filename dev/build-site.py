#!/usr/bin/env python3
"""Build site/ from the design export in dev/site-src, fetching nothing.

    python3 dev/build-site.py

The export is a Design Component page: a <x-dc> template, a logic class in a
<script type="text/x-dc"> block, and a runtime (support.js) that mounts the
two with React. Shipped as exported it reaches three hosts at view time, which
is a problem specific to this page rather than a general one: it renders the
sentence "no hosted control plane, no licence check, no CDN font" while
fetching a font from a CDN.

So three changes, and only three:

  1. React and ReactDOM load from site/vendor instead of unpkg. support.js
     calls loadReactUmd(), which returns early when both globals already
     exist, so the CDN constants it carries are never reached. Babel was never
     reached to begin with: ensureBabel() is called only from the x-import
     path, and this page has no x-import.
  2. The Google Fonts @import goes, and the three families fall back to the
     platform's own. Self-hosting the real ones would also have worked and
     would have cost 150KB of woff2 for a closer match; the system stacks cost
     nothing and the page is mostly monospace anyway.
  3. The design system's marketing and ui-kit stylesheets and its 288KB
     component bundle are dropped. The page uses no class from any of them,
     and the bundle is where every link to an unrelated project came from.

ci/site-offline.sh is what holds all of that: it serves the built directory
and renders it with every name but loopback unresolvable.
"""

import json
import os
import re
import shutil
import sys

SRC = "dev/site-src"
OUT = "site"
ASSETS = ("logo.png", "console-overview.png", "console-ledger.png",
          "console-tampered.png")
# Where React comes from is a build-time question, so this is a path on the
# machine doing the build and never a URL the page knows about.
VENDOR = (
    ("react.production.min.js", "react/umd/react.production.min.js"),
    ("react-dom.production.min.js", "react-dom/umd/react-dom.production.min.js"),
)

FONT_STACKS = {
    '--font-display:   "Plus Jakarta Sans", system-ui, sans-serif;':
        "--font-display:   system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif;",
    '--font-body:      "Manrope", system-ui, sans-serif;':
        "--font-body:      system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif;",
    '--font-mono:      "JetBrains Mono", ui-monospace, Menlo, monospace;':
        "--font-mono:      ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;",
}

CSS_HEADER = """/* =========================================================================
   Gantry site foundations, built by dev/build-site.py from
   dev/site-src/colors_and_type.css. Do not edit here.

   Two changes from the export: no Google Fonts @import, and the three
   families fall back to the platform's own.
   ========================================================================= */
"""


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_css():
    css = read(f"{SRC}/colors_and_type.css")
    at = css.index("@import")
    css = CSS_HEADER + css[css.index("\n", at) + 1:]
    for old, new in FONT_STACKS.items():
        if old not in css:
            sys.exit(f"{SRC}/colors_and_type.css: no font stack matching\n  {old}\n"
                     f"Fix: the export changed its type block; update FONT_STACKS "
                     f"in dev/build-site.py to the line it now carries")
        css = css.replace(old, new)
    write(f"{OUT}/styles.css", css)
    return css


def build_html():
    html = read(f"{SRC}/gantry.dc.html")

    boot = '<script src="./support.js"></script>'
    if boot not in html:
        sys.exit(f"{SRC}/gantry.dc.html: no support.js tag to load React ahead of. "
                 f"Fix: the export changed how it boots; read dev/build-site.py")
    html = html.replace(boot, "\n".join(
        f'<script src="./vendor/{name}"></script>' for name, _ in VENDOR) + "\n" + boot)

    dropped = len(re.findall(r"_ds/", html))
    html = re.sub(r"\s*<(?:link|script)[^>]*_ds/[^>]*>(?:</script>)?", "", html)
    html = html.replace("<helmet>", '<helmet>\n<link rel="stylesheet" href="styles.css">', 1)
    html = html.replace(
        '<meta charset="utf-8">',
        '<meta charset="utf-8">\n<title>Gantry</title>\n'
        '<link rel="icon" href="assets/logo.png">')
    return ("<!-- Built by dev/build-site.py from dev/site-src/gantry.dc.html.\n"
            "     Edit the source, not this file: the next build overwrites it. -->\n"
            + html), dropped


def vendor_react():
    """Copy the UMD builds the runtime expects, from this machine's node_modules."""
    roots = os.environ.get("GANTRY_NODE_MODULES", "").split(os.pathsep)
    roots = [r for r in roots if r]
    support = read(f"{SRC}/support.js")
    for name, relative in VENDOR:
        package = relative.split("/")[0]
        # The version the runtime names is the version the page gets. A
        # support.js that starts asking for React 19 must not be served an 18.
        want = re.search(rf"{package}@([0-9.]+)", support)
        if not want:
            sys.exit(f"{SRC}/support.js names no {package} version. "
                     f"Fix: read its REACT_URL constants and update dev/build-site.py")
        found = None
        for root in roots:
            candidate = os.path.join(root, relative)
            manifest = os.path.join(root, package, "package.json")
            if not (os.path.exists(candidate) and os.path.exists(manifest)):
                continue
            if json.loads(read(manifest)).get("version") == want.group(1):
                found = candidate
                break
        if not found:
            sys.exit(
                f"no {package} {want.group(1)} UMD build on this machine. Fix: set "
                f"GANTRY_NODE_MODULES to a colon-separated list of node_modules "
                f"directories holding it, for example a project that depends on "
                f"react@{want.group(1)}; this script fetches nothing")
        shutil.copyfile(found, f"{OUT}/vendor/{name}")
    return want.group(1)


def main():
    if not os.path.isdir(SRC):
        sys.exit(f"run from the repository root: {SRC} is not there")
    os.makedirs(f"{OUT}/vendor", exist_ok=True)
    os.makedirs(f"{OUT}/assets", exist_ok=True)

    html, dropped = build_html()
    build_css()
    shutil.copyfile(f"{SRC}/support.js", f"{OUT}/support.js")
    for name in ASSETS:
        shutil.copyfile(f"docs/assets/{name}", f"{OUT}/assets/{name}")
    version = vendor_react()

    for host in ("unpkg.com", "googleapis", "_ds/"):
        if host in html:
            sys.exit(f"{OUT}/index.html still references {host}. "
                     f"Fix: read dev/build-site.py; this is the thing it exists to remove")
    write(f"{OUT}/index.html", html)
    print(f"built {OUT}/ from {SRC}: dropped {dropped} design-system references, "
          f"vendored react {version}, copied {len(ASSETS)} assets")


if __name__ == "__main__":
    main()
