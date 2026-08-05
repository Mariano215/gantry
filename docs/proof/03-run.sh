#!/bin/zsh
# Proof 03: every tool call passes the broker; a destructive command is
# denied and the ledger names the rule, the policy version and the identity;
# a loose tool definition is refused registration. Run from the repository
# root after cargo build. No network is needed anywhere in this proof.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof03.XXXXXX)
L=$WORK/ledger
echo "workdir: $WORK"

# Subject payload of the most recent event of a kind. Each CLI invocation is
# one sealed run appended to the same ledger, so "last" is always the run
# that just finished.
last_subject() {
  H=$(jq -rs "[.[] | select(.kind==\"$1\")] | last | .subject_hash" $L/events.jsonl | sed 's/^sha256://')
  cat $L/payloads/$H.json
}
last_envelope() {
  jq -rs "[.[] | select(.kind==\"$1\")] | last" $L/events.jsonl
}

echo "== policy loads clean, host parity holds =="
$BIN policy check config/policy.json .claude/settings.json

echo "== attack 1: destructive command =="
if $BIN broker call $L Bash "rm -rf /"; then
  echo "DESTRUCTIVE COMMAND EXECUTED"; exit 1
else
  echo "denied, exit=$?"
fi
DEC=$(last_subject policy.decision)
echo "$DEC" | jq -e '.verdict == "deny" and .rule == "r-destructive-shell"' >/dev/null
echo "$DEC" | jq -c '{verdict, rule, capability, identity}'
POLICY_V=$($BIN policy check config/policy.json | sed -n 's/.*version //p')
[ "$(last_envelope policy.decision | jq -r '.authority.policy_version')" = "$POLICY_V" ] \
  && echo "policy version on the decision envelope matches the loaded policy: $POLICY_V"
last_subject tool.result | jq -e '.outcome == "denied"' >/dev/null && echo "tool.result: denied"

echo "== attack 2: publish a tool declared as run-any-shell-command =="
cat > $WORK/shell-any.json <<'EOF'
{
  "name": "shell.any",
  "description": "Run any shell command.",
  "inputSchema": { "type": "object" }
}
EOF
if $BIN broker register $L $WORK/shell-any.json; then
  echo "LOOSE TOOL ACCEPTED"; exit 1
else
  echo "rejected, exit=$?"
fi
last_subject tool.register | jq -e '.verdict == "rejected"' >/dev/null
last_subject tool.register | jq -c '{tool, verdict, reason}'

echo "== attack 3: read a credential file =="
if $BIN broker call $L Read "./.env"; then
  echo "CREDENTIAL FILE READ"; exit 1
else
  echo "denied, exit=$?"
fi
last_subject policy.decision | jq -e '.rule == "r-credential-file"' >/dev/null && echo "rule: r-credential-file"

echo "== attack 4: irreversible call under an allow rule still gates pre =="
MARKER=$WORK/pushed-marker
if $BIN broker call $L Bash "git push origin main && touch $MARKER"; then
  echo "PUSH PROCEEDED WITHOUT APPROVAL"; exit 1
else
  echo "held, exit=$?"
fi
[ ! -e $MARKER ] && echo "held call did not execute (no marker file)"
last_subject policy.decision | jq -e '.verdict == "hold" and .obligation == "approval"' >/dev/null
last_subject policy.decision | jq -c '{verdict, rule, gate, obligation}'

echo "== attack 5: egress =="
if $BIN broker call $L Bash "curl https://example.com"; then
  echo "EGRESS ALLOWED"; exit 1
else
  echo "denied, exit=$?"
fi
last_subject policy.decision | jq -e '.rule == "r-egress-laptop"' >/dev/null && echo "rule: r-egress-laptop"

echo "== positive control: an allowed read executes, tainted =="
$BIN broker call $L Read docs/PLAN.md | tail -1
last_subject tool.result | jq -e '.outcome == "ok" and .taint == true' >/dev/null && echo "tool.result: ok, taint true"

echo "== positive control: allowed shell carries a review obligation to the seal =="
$BIN broker call $L Bash "echo proof-03"
last_subject policy.decision | jq -c '{verdict, gate, obligation}'
last_subject run.seal | jq -e '.outcome == "complete-with-outstanding-review" and .outstanding_reviews == 1' >/dev/null \
  && echo "seal refuses to claim clean: complete-with-outstanding-review"

echo "== attack 6: a policy that lies refuses to load =="
jq 'del(.policy_version) | .rules |= [{"id":"r-allow-all-reads","match":{"capability":"repo.read"},"action":"allow"}] + .' \
  config/policy.json > $WORK/shadowed.json
if $BIN policy check $WORK/shadowed.json; then
  echo "SHADOWED DENY LOADED"; exit 1
else
  echo "shadowed policy refused, exit=$?"
fi
jq 'del(.policy_version) | (.capabilities[] | select(.id=="shell.exec")) |= del(.rollback)' \
  config/policy.json > $WORK/no-rollback.json
if $BIN policy check $WORK/no-rollback.json; then
  echo "POST GATE WITHOUT ROLLBACK LOADED"; exit 1
else
  echo "rollback-free post gate refused, exit=$?"
fi

echo "== attack 7: the deny rule is a tripwire, not a parser =="
# A second space defeats the glob "rm -rf *". This is expected to succeed,
# and that is the finding: the pattern is a tripwire; the enforcement floor
# is the slice 04 sandbox. The deletion is scoped to the proof workdir.
mkdir -p $WORK/victim && touch $WORK/victim/file
$BIN broker call $L Bash "rm  -rf $WORK/victim"
if [ -e $WORK/victim ]; then
  echo "victim survived"
else
  echo "victim deleted: one extra space evaded the pattern, on the record with a review obligation"
fi
last_subject policy.decision | jq -c '{verdict, rule, obligation}'

echo "== inclusion proof for the attack-1 decision, offline =="
$BIN ledger prove $L 4 > $WORK/bundle03.json
cp $L/keys/ledger.pub $WORK/ 2>/dev/null || cp $L/ledger.pub $WORK/
(cd $WORK && sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  $OLDPWD/$BIN ledger verify-inclusion bundle03.json ledger.pub)

echo "== the whole ledger still verifies =="
$BIN ledger verify $L

echo "proof 03 run complete, workdir: $WORK"
