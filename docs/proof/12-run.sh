#!/bin/zsh
# Proof 12: the permission-mode hook. Before this slice, authority.permission_mode
# recorded "unobserved" on every event because nothing set
# CLAUDE_PERMISSION_MODE automatically; a session running under a mode that
# diverges from the tracked declaration produced no signal at all. This
# proves the hook (.claude/hooks/permission-mode.sh, wired in
# .claude/settings.json) injects the real mode into any command that
# invokes gantry, and that a divergent mode lands in authority.diverged as
# host_permissions.permission_mode. Run from the repository root after
# cargo build. No network needed.
set -e
BIN=./target/debug/gantry
HOOK=.claude/hooks/permission-mode.sh
WORK=$(mktemp -d /tmp/gantry-proof12.XXXXXX)
L=$WORK/ledger
echo "workdir: $WORK"

last_authority() {
  jq -rs '[.[] | select(.kind=="run.open")] | last | .authority' $L/events.jsonl
}

echo "== the tracked declaration =="
echo ".claude/settings.json declares no permissions.defaultMode, so the tracked value is the implicit \"default\" (src/gateway.rs permission_mode_check)."

echo ""
echo "== attack 1: no hook, no wrapper -- the pre-existing gap =="
echo "with CLAUDE_PERMISSION_MODE unset, the observed mode is unobserved and never counted as divergence:"
CLAUDE_PERMISSION_MODE= $BIN run config/providers.json local $L >/dev/null 2>&1 || true
last_authority | jq -c '{permission_mode, diverged}'

echo ""
echo "== the hook, exercised directly as Claude Code would invoke it =="
echo "-- a command with no gantry in it: left untouched --"
echo '{"tool_input":{"command":"echo hello"},"permission_mode":"bypassPermissions"}' | $HOOK

echo "-- a gantry command, observed mode bypassPermissions: rewritten to export it --"
HOOK_OUT=$(echo '{"tool_input":{"command":"'"$BIN"' run config/providers.json local '"$L"'"},"permission_mode":"bypassPermissions"}' | $HOOK)
echo $HOOK_OUT | jq -c '.hookSpecificOutput.updatedInput.command'
REWRITTEN=$(echo $HOOK_OUT | jq -r '.hookSpecificOutput.updatedInput.command')

echo ""
echo "== attack 2: the rewritten command actually runs, under a mode (bypassPermissions) that diverges from the tracked declaration (default) =="
L2=$WORK/ledger-diverged
REWRITTEN2=$(echo $REWRITTEN | sed "s#$L#$L2#")
sh -c "$REWRITTEN2" >/dev/null 2>&1 || true
jq -rs '[.[] | select(.kind=="run.open")] | last | .authority' $L2/events.jsonl | jq -c '{permission_mode, diverged}'
jq -rs '[.[] | select(.kind=="run.open")] | last | .authority.diverged' $L2/events.jsonl | jq -e 'index("host_permissions.permission_mode")' >/dev/null \
  && echo "host_permissions.permission_mode is in authority.diverged: the hook-observed mode disagreed with the tracked declaration, and the event says so"

echo ""
echo "== attack 3: the same hook, a mode that matches the tracked declaration (default): no divergence =="
L3=$WORK/ledger-matched
CLAUDE_PERMISSION_MODE=default $BIN run config/providers.json local $L3 >/dev/null 2>&1 || true
jq -rs '[.[] | select(.kind=="run.open")] | last | .authority' $L3/events.jsonl | jq -c '{permission_mode, diverged}'

echo ""
echo "== the ledger the divergence was read from still verifies =="
$BIN ledger verify $L2 | tail -1

echo ""
echo "proof 12 run complete, workdir: $WORK"
