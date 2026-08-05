#!/bin/zsh
# Proof 02: one run per environment, three ledgers, one shape.
# Requires: cargo build done, OPENAI_API_KEY with credit, the gpu-box
# reachable over Tailscale, local ollama serving qwen3:0.6b on 127.0.0.1.
# Run from the repository root.
set -e
BIN=./target/debug/gantry
SBX='(version 1)(allow default)(deny network*)(allow network* (remote ip "localhost:11434"))'
WORK=$(mktemp -d /tmp/gantry-proof02.XXXXXX)
echo "workdir: $WORK"

# Leg 1 to 3: the same two-turn workload against each environment. The
# local leg runs inside a sandbox that denies every network destination
# except loopback, which is what makes the no-internet claim a mechanism
# rather than a promise.
for name in openai gpu-box local; do
  echo "== $name =="
  if [ "$name" = "local" ]; then
    sandbox-exec -p $SBX $BIN run config/providers.json local $WORK/ledger-local
  else
    $BIN run config/providers.json $name $WORK/ledger-$name
  fi
  $BIN ledger verify $WORK/ledger-$name
done

# Negative controls: the same sandbox profile must refuse both the
# Tailscale route and the public internet, or the local leg proves nothing.
echo "== sandbox negative controls =="
if sandbox-exec -p $SBX curl -s --max-time 5 http://100.120.203.53:11434/v1/models >/dev/null 2>&1; then
  echo "SANDBOX LEAK: tailscale route allowed"; exit 1
else
  echo "tailscale route denied, as required"
fi
if sandbox-exec -p $SBX curl -s --max-time 5 https://api.openai.com/v1/models >/dev/null 2>&1; then
  echo "SANDBOX LEAK: internet allowed"; exit 1
else
  echo "internet denied, as required"
fi

# Adversarial leg: a provider that cannot answer. The failed call must be
# on the record and the ledger must still verify.
echo "== dead provider =="
printf '[{"name":"dead","base_url":"http://127.0.0.1:1/v1","model":"none","window_budget":1}]' > $WORK/dead.json
if $BIN run $WORK/dead.json dead $WORK/ledger-dead; then
  echo "dead provider unexpectedly answered"; exit 1
else
  echo "dead run failed as expected, exit=$?"
fi
$BIN ledger verify $WORK/ledger-dead

# The shape claim: identical envelope key sets and identical model.call
# subject key sets across all three environments.
echo "== shape diff =="
for name in openai gpu-box local; do
  jq -cS 'keys' $WORK/ledger-$name/events.jsonl | sort -u > $WORK/shape-envelope-$name.txt
  H=$(jq -rs '.[1].subject_hash' $WORK/ledger-$name/events.jsonl | sed 's/^sha256://')
  jq -cS 'keys' $WORK/ledger-$name/payloads/$H.json > $WORK/shape-subject-$name.txt
done
diff $WORK/shape-envelope-openai.txt $WORK/shape-envelope-gpu-box.txt
diff $WORK/shape-envelope-openai.txt $WORK/shape-envelope-local.txt
diff $WORK/shape-subject-openai.txt $WORK/shape-subject-gpu-box.txt
diff $WORK/shape-subject-openai.txt $WORK/shape-subject-local.txt
echo "envelope and model.call subject shapes identical across all three environments"

# Offline inclusion: prove one event from the air-gapped leg with nothing
# but the bundle and the public key, network denied entirely.
echo "== offline inclusion =="
$BIN ledger prove $WORK/ledger-local 1 > $WORK/bundle02.json
cp $WORK/ledger-local/keys/ledger.pub $WORK/ 2>/dev/null || cp $WORK/ledger-local/ledger.pub $WORK/
(cd $WORK && sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  $OLDPWD/$BIN ledger verify-inclusion bundle02.json ledger.pub)

echo "proof 02 run complete, workdir: $WORK"
