# Slice 02 design, model gateway

Approved 2026-08-04. Approach A: library gateway plus CLI runner.

## Goal

One chokepoint. Every model call in this repository goes through
`gateway::call()`, which appends a `model.call` envelope (event schema v2) to
the slice 01 ledger. A run is `run.open`, N `model.call`, `run.seal`. The
slice is done when the same small agent run has executed against three
environments and produced three ledgers with one byte-comparable envelope
shape, recorded in `docs/proof/02.md`.

## Environments

| Environment | Endpoint | Model | Key |
|---|---|---|---|
| Frontier API | `https://api.openai.com/v1` | `gpt-5-mini`, or the cheapest chat model the key reaches, resolved at proof time and named in the proof | `OPENAI_API_KEY` |
| Cloud-hosted | `http://100.120.203.53:11434/v1` (GPU box over Tailscale) | `gemma4-8b-32k` | none |
| Local, no internet | `http://127.0.0.1:11434/v1` (Ollama installed for the proof) | `qwen3:0.6b`, or the smallest chat model that pulls cleanly, named in the proof | none |

All three speak OpenAI-compatible chat completions. One adapter, three base
URLs. The seam under test is the normalised call event, not the adapter
count, so this is an honest test of the model-provider axis. The `Adapter`
trait is the seam for a future Anthropic adapter; it is not implemented in
this slice because no key is available to prove it against.

The local environment runs under a sandbox profile that denies every network
destination except loopback, which keeps the air-gap claim real rather than
asserted.

## Components

- `src/gateway.rs`. `Provider` describes name, base URL, model id, the env
  var holding the key (optional), and the declared window budget in tokens.
  `call()` takes a `Provider`, a message list and the open run context,
  performs the HTTP call, and appends the `model.call` event before
  returning the assistant message. A transport or provider error still
  appends a `model.call` event with an error outcome and a fix-naming
  message; the failed call is on the record.
- One adapter: OpenAI-compatible `POST {base_url}/chat/completions`,
  blocking HTTP via `ureq` with rustls. First dependency with network
  capability; noted in `docs/DEPENDENCIES.md` with the reason in the commit.
- `gantry run --provider <name>` in `src/main.rs`. Executes a fixed
  two-turn workload against the named provider, writing `run.open`, one
  `model.call` per turn, `run.seal` into a fresh ledger directory.
  Provider definitions come from a small tracked config file.

## The model.call subject

Per `docs/EVENT-SCHEMA.md`: provider, model, declared inputs and whether
each arrived, window budget and actual, prompt and completion token counts
from the response `usage`, cost (zero for self-hosted), latency, prompt
hash. Slice 02 records the hash only and stores no prompt payload, by
decision: storage under retention arrives with the broker slices. A
provider error body is likewise recorded as status plus a hash of the body,
never verbatim.

## Pinning

`authority.instruction_version` is the sha256 of the tracked instruction
pack file consumed by the run. `authority.policy_version` is the sha256 of
`docs/POLICY-SCHEMA.md` until the policy engine exists in slice 03. Both
appear on every event, per schema constraint 5.

## Secrets

The adapter reads the key from the environment at the request boundary.
The ledger records the env var name, never the value. Nothing places the
key in a prompt, an argument list, or an event. The no-key-bytes assertion
in the test suite greps the ledger files for the key value.

## Testing

The no-network invariant holds. Tests run against a stdlib `TcpListener`
loopback stub serving canned chat-completion responses, covering: envelope
shape identical across two stub providers, token and window accounting,
error outcome on a 500 and on a connection refused, and no key bytes in any
ledger file. Loopback exists in an empty network namespace, so the suite
stays offline-clean.

## Out of scope

Anthropic adapter (no key), streaming, retries, cost tables beyond a static
per-model rate for the OpenAI call, the proxy service shape (slice 03 will
force it), tool calls (slice 03).
