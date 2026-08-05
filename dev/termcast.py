#!/usr/bin/env python3
"""Render a terminal cast to an animated SVG, from output the binary produced.

The tape holds commands, never their output. Every frame in the SVG is
captured by running the command, so a cast cannot show a line gantry did not
print. Regenerate after any change to the output it shows:

    python3 dev/termcast.py dev/readme-cast.tape docs/assets/first-hour.svg

Standard library only, no recording tool, and the SVG references no host: it
animates with CSS keyframes, which is what survives GitHub serving it as an
image. Nothing here runs in CI, because a real run stamps run ids and hashes
that differ every time, so a regenerate-and-diff gate would fail on a clean
tree. The cast going stale is caught by reading it, which is the honest
statement of what this check is.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape

COLS = 92
FONT = 13
CHARW = FONT * 0.6
LH = 19
PAD = 16
CHROME = 30

BG = "#080d16"
SURFACE = "#101a2b"
LINE = "#1b2841"
FG = "#e3e9f4"
DIM = "#64748f"
ACCENT = "#3b90ff"
DENY = "#ff5f5a"
FAULT = "#ff3b40"

TYPE = 0.035        # seconds per typed character
AFTER_TYPE = 0.35   # beat between the command and its first output line
STAGGER = 0.05      # between output lines
AFTER_OUT = 1.4     # beat before the next command
AFTER_NOTE = 0.8    # beat after an on-screen comment
HOLD = 3.0          # tail before the loop restarts


def wrap(text, cols):
    """Wrap like a terminal: break on width, keep whole words when they fit."""
    out = []
    for raw in text.split("\n"):
        if not raw:
            out.append("")
            continue
        line = ""
        for word in raw.split(" "):
            while len(word) > cols:
                if line:
                    out.append(line)
                    line = ""
                out.append(word[:cols])
                word = word[cols:]
            if not line:
                line = word
            elif len(line) + 1 + len(word) <= cols:
                line += " " + word
            else:
                out.append(line)
                line = word
        out.append(line)
    return out


def run_tape(tape_path, binary):
    """Run the tape and return the screen: (kind, text) in the order shown."""
    repo = os.path.dirname(os.path.abspath(os.path.dirname(tape_path)))
    bindir = tempfile.mkdtemp(prefix="gantry-cast-bin-")
    os.symlink(os.path.abspath(binary), os.path.join(bindir, "gantry"))
    env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
    # A cast that inherits the launching shell's mode would print a different
    # authority block depending on who ran it. Observe nothing instead.
    env.pop("CLAUDE_PERMISSION_MODE", None)

    # shell=True is the point: a tape line is a shell command, shown on screen
    # exactly as it runs, quoting included. The tape is a tracked file in this
    # repository and never anything a user supplies, so there is no untrusted
    # string reaching this call. Anyone who can edit the tape can already run
    # the build.
    screen = []
    try:
        for raw in open(tape_path, encoding="utf-8"):
            raw = raw.rstrip("\n")
            if not raw.strip() or raw.startswith("#"):
                continue
            kind, _, body = raw.partition(" ")
            if kind == "!":
                done = subprocess.run(body, shell=True, cwd=repo, env=env,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True)
                if done.returncode:
                    # A setup step that fails quietly stages the wrong screen:
                    # a cast whose tamper never happened prints a clean verify
                    # and reads as the log missing an alteration.
                    sys.exit(f"{tape_path}: setup failed ({done.returncode}): "
                             f"{body}\n{done.stdout.strip()}")
            elif kind == ">":
                screen.append(("note", body))
            elif kind == "$":
                screen.append(("cmd", body))
                # Merged, so the screen shows the order a terminal would.
                done = subprocess.run(body, shell=True, cwd=repo, env=env,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True)
                output = done.stdout.rstrip("\n")
                for line in wrap(output, COLS):
                    screen.append(("out", line))
            else:
                sys.exit(f"{tape_path}: unknown tape line: {raw}")
    finally:
        shutil.rmtree(bindir, ignore_errors=True)
    return screen


def schedule(screen):
    """Assign each row the second it appears, and return (rows, total)."""
    rows, t, previous = [], 0.0, None
    for kind, text in screen:
        if previous == "out" and kind != "out":
            t += AFTER_OUT   # let the reader finish the block before the next
        if kind == "cmd":
            span = max(len(text) * TYPE, 0.3)
            rows.append((kind, text, t, span))
            t += span + AFTER_TYPE
        elif kind == "note":
            rows.append((kind, text, t, 0.0))
            t += AFTER_NOTE
        else:
            rows.append((kind, text, t, 0.0))
            t += STAGGER
        previous = kind
    total = t + AFTER_OUT + HOLD
    return rows, total


def colour(text):
    if text.startswith("policy denied") or text.startswith("policy held"):
        return DENY
    if re.match(r"^entry \d+ ", text) or text.lstrip().startswith("Fix:"):
        return FAULT
    return FG


def render(rows, total, cols=COLS):
    width = int(cols * CHARW) + PAD * 2
    height = CHROME + PAD + len(rows) * LH + PAD
    css, body = [], []

    def pct(seconds):
        return round(max(0.0, min(100.0, seconds / total * 100)), 3)

    for i, (kind, text, at, span) in enumerate(rows):
        y = CHROME + PAD + i * LH + FONT
        on = pct(at)
        css.append(
            f".r{i}{{animation:a{i} {total:.2f}s infinite}}"
            f"@keyframes a{i}{{0%,{on}%{{opacity:0}}{min(on + 0.01, 100)}%,100%{{opacity:1}}}}"
        )
        if kind == "cmd":
            shown = escape(text)
            w = len(text) * CHARW
            end = pct(at + span)
            css.append(
                f"#w{i} rect{{animation:t{i} {total:.2f}s infinite linear}}"
                f"@keyframes t{i}{{0%,{on}%{{transform:scaleX(0)}}"
                f"{end}%,100%{{transform:scaleX(1)}}}}"
            )
            body.append(
                f'<clipPath id="w{i}" clipPathUnits="userSpaceOnUse">'
                f'<rect x="{PAD + CHARW * 2:.1f}" y="{y - FONT}" '
                f'width="{w:.1f}" height="{LH}" '
                f'style="transform-origin:{PAD + CHARW * 2:.1f}px 0px"/></clipPath>'
                f'<text class="r{i}" x="{PAD}" y="{y}" fill="{ACCENT}">$</text>'
                f'<g clip-path="url(#w{i})">'
                f'<text class="r{i}" x="{PAD + CHARW * 2:.1f}" y="{y}" fill="{FG}" '
                f'textLength="{w:.1f}" lengthAdjust="spacingAndGlyphs">{shown}</text>'
                f"</g>"
            )
        elif kind == "note":
            shown = escape("# " + text)
            body.append(
                f'<text class="r{i}" x="{PAD}" y="{y}" fill="{DIM}" '
                f'textLength="{len(shown) * CHARW:.1f}" '
                f'lengthAdjust="spacingAndGlyphs">{shown}</text>'
            )
        elif text:
            shown = escape(text)
            body.append(
                f'<text class="r{i}" x="{PAD}" y="{y}" fill="{colour(text)}" '
                f'textLength="{len(text) * CHARW:.1f}" '
                f'lengthAdjust="spacingAndGlyphs">{shown}</text>'
            )

    dots = "".join(
        f'<circle cx="{PAD + 8 + n * 16}" cy="{CHROME // 2}" r="5" fill="{c}"/>'
        for n, c in enumerate(("#3b4763", "#3b4763", "#3b4763"))
    )
    # opacity:1 as a presentation attribute, so a renderer that ignores the
    # stylesheet shows the whole transcript rather than an empty terminal.
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" '
        f'font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" '
        f'font-size="{FONT}" role="img" '
        f'aria-label="A terminal session: gantry refuses a destructive tool call, '
        f'then detects one altered event on the ledger">'
        f"<style>text{{white-space:pre}}</style>"
        f'<rect width="{width}" height="{height}" rx="8" fill="{BG}"/>'
        f'<path d="M0 8a8 8 0 0 1 8-8h{width - 16}a8 8 0 0 1 8 8v{CHROME - 8}H0z" '
        f'fill="{SURFACE}"/>'
        f'<line x1="0" y1="{CHROME}" x2="{width}" y2="{CHROME}" stroke="{LINE}"/>'
        f"{dots}"
        f'<text x="{width / 2:.0f}" y="{CHROME / 2 + 4:.0f}" fill="{DIM}" '
        f'font-size="11" text-anchor="middle">gantry</text>'
        f"<style>{''.join(css)}</style>"
        f'<g opacity="1">{"".join(body)}</g>'
        f"</svg>\n"
    )


def tamper(ledger):
    """Alter one character of one timestamp, in place. Used by the tape."""
    path = os.path.join(ledger, "events.jsonl")
    with open(path, encoding="utf-8") as handle:
        lines = handle.readlines()
    target = min(4, len(lines) - 1)
    hit = re.search(r'"ts":"[^"]*?(\d)[^"\d]*"', lines[target])
    if not hit:
        sys.exit(f"{path}: entry {target} carries no timestamp to alter. "
                 f"Fix: the envelope's ts field was renamed; update this regex")
    digit = hit.group(1)
    at = hit.start(1)
    lines[target] = (
        lines[target][:at] + ("0" if digit != "0" else "1") + lines[target][at + 1:]
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def selftest():
    assert wrap("a bb ccc", 6) == ["a bb", "ccc"], wrap("a bb ccc", 6)
    assert wrap("abcdefgh", 3) == ["abc", "def", "gh"], wrap("abcdefgh", 3)
    assert wrap("", 5) == [""]
    rows, total = schedule([("cmd", "ab"), ("out", "x")])
    assert rows[0][2] == 0.0 and rows[1][2] > rows[0][2], rows
    assert total > rows[-1][2] + HOLD
    # A command that follows output waits for the block to be read.
    paced, _ = schedule([("cmd", "a"), ("out", "x"), ("cmd", "b")])
    assert paced[2][2] - paced[1][2] >= AFTER_OUT, paced
    svg = render(*schedule([("cmd", "gantry"), ("out", "ok")]))
    assert svg.startswith("<svg") and "@keyframes" in svg and "<script" not in svg
    assert "&amp;" not in svg
    print("termcast selftest ok")


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--tamper"]:
        tamper(args[1])
    elif args[:1] == ["--selftest"]:
        selftest()
    elif len(args) == 2:
        binary = os.environ.get("GANTRY_BIN", "target/debug/gantry")
        if not os.path.exists(binary):
            sys.exit(f"{binary} not built. Fix: run cargo build, or set GANTRY_BIN")
        screen = run_tape(args[0], binary)
        with open(args[1], "w", encoding="utf-8") as handle:
            handle.write(render(*schedule(screen)))
        print(f"wrote {args[1]} from {sum(1 for k, _ in screen if k == 'cmd')} commands")
    else:
        sys.exit(__doc__)
