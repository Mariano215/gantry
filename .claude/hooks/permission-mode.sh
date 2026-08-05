#!/bin/sh
# PreToolUse hook, Bash matcher. Claude Code's hook input carries the
# session's real permission_mode; nothing else on the machine knows it.
# This hook injects that value as CLAUDE_PERMISSION_MODE into any Bash
# command that invokes gantry, so gateway::permission_mode_check
# (src/gateway.rs) records the observed mode on every event instead of
# writing "unobserved". ci/permission-mode-hook exercises this script
# directly with fixture input; see ci/run.sh.
#
# A command with no "gantry" in it is a negative control: this hook must
# leave it untouched (exit with `{}`), or it would be rewriting commands it
# has no business touching.
set -eu

input=$(cat)
command=$(printf '%s' "$input" | jq -r '.tool_input.command // empty')

case "$command" in
  *gantry*)
    printf '%s' "$input" | jq '
      (.permission_mode // "") as $mode
      | if ($mode | length) > 0 then
          {
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "allow",
              updatedInput: (.tool_input + {
                command: ("export CLAUDE_PERMISSION_MODE=" + ($mode | @sh) + "; " + .tool_input.command)
              })
            }
          }
        else {}
        end'
    exit 0
    ;;
esac

echo '{}'
