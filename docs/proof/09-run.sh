#!/bin/zsh
# Proof 09: the resolver refuses a broken skill rather than publishing it on
# its title, and a skill referencing a deleted step fails at resolve time,
# before any run consumes it. Then delegation narrows scope and refuses to
# widen. Run from the repository root after cargo build. No network needed.
set -e
BIN=./target/debug/gantry
WORK=$(mktemp -d /tmp/gantry-proof09.XXXXXX)
L=$WORK/ledger
SRC=docs/proof/fixtures/skill-repo-audit
PKG=$WORK/skill-repo-audit
cp -R $SRC $PKG
echo "workdir: $WORK"
echo "managed key registry: config/skill-keys.json"
jq -c '.keys[] | {owner, key: .public_key_hex[0:16]}' config/skill-keys.json

last_subject() {
  H=$(jq -rs "[.[] | select(.kind==\"skill.resolve\")] | last | .subject_hash" $L/events.jsonl | sed 's/^sha256://')
  cat $L/payloads/$H.json
}

echo "== the signed skill resolves against the managed registry, no key passed =="
$BIN skill resolve $L $PKG
last_subject | jq -c '{id, verdict, signature_state, scope}'

echo "== attack 1: break the metadata (empty description) =="
jq '.description = ""' $PKG/skill.json > $PKG/skill.tmp && mv $PKG/skill.tmp $PKG/skill.json
if $BIN skill resolve $L $PKG; then
  echo "BROKEN SKILL PUBLISHED"; exit 1
else
  echo "refused, exit=$?"
fi
last_subject | jq -c '{verdict, reason}'
# restore
cp $SRC/skill.json $PKG/skill.json

echo "== attack 2: delete a step the skill references =="
rm $PKG/steps/scan.md
if $BIN skill resolve $L $PKG; then
  echo "SKILL WITH A DANGLING STEP PUBLISHED"; exit 1
else
  echo "refused at resolve time, before any run, exit=$?"
fi
last_subject | jq -r '.reason' | head -1
cp $SRC/steps/scan.md $PKG/steps/scan.md

echo "== attack 3: the signature no longer verifies after tampering =="
jq '.description = "a different skill wearing the same signature"' $PKG/skill.json > $PKG/skill.tmp && mv $PKG/skill.tmp $PKG/skill.json
if $BIN skill resolve $L $PKG; then
  echo "TAMPERED SKILL PUBLISHED"; exit 1
else
  echo "tampered signature refused, not downgraded to unsigned, exit=$?"
fi
cp $SRC/skill.json $PKG/skill.json

echo "== delegation narrows scope, and refuses to widen =="
$BIN skill delegate "repo.read,repo.write" $PKG
if $BIN skill delegate "net.egress" $PKG; then
  echo "SCOPE WIDENED"; exit 1
else
  echo "widening refused, exit=$?"
fi

echo "== the ledger of resolutions verifies =="
$BIN ledger verify $L | tail -1

echo "== re-score: primitive 09 is no longer N/A =="
$BIN score $L config/scoring.json 2>/dev/null | grep -E "09 Skills|Overall"

echo "proof 09 run complete, workdir: $WORK"
