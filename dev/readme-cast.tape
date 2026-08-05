# The cast rendered into docs/assets/first-hour.svg by dev/termcast.py.
#
# Lines beginning "$ " are typed on screen and run for real; whatever the
# binary prints is what the frame shows. A line beginning "! " is setup: it
# runs and its output is discarded, so the cast can stage a tampered copy
# without showing the plumbing. "# " is a comment, and "> " is a comment
# drawn on screen between commands.
#
# gantry on PATH is a link to target/debug/gantry, so the command shown is
# the command that ran.

! rm -rf /tmp/gantry-cast
$ gantry ledger init /tmp/gantry-cast/ledger

> ask the broker to run something destructive
$ gantry broker call /tmp/gantry-cast/ledger Bash "rm -rf /"

> the record is checkable without trusting the binary that wrote it
$ gantry ledger verify /tmp/gantry-cast/ledger

> now copy the ledger and alter one character of one event
! cp -r /tmp/gantry-cast/ledger /tmp/gantry-cast/tampered
! python3 dev/termcast.py --tamper /tmp/gantry-cast/tampered
$ gantry ledger verify /tmp/gantry-cast/tampered
