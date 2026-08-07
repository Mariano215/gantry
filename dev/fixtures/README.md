# These files are hand-authored. They are not gantry output.

Everything under `dev/fixtures/` is a **synthetic response set** for the console's
read-only JSON API, written by hand so the front end could be built and its
failure states exercised before the Rust API existed. See `dev/serve.py`.

They are developer tooling. The Rust build never reads them, nothing is embedded
in the binary, and no number in them was produced by running gantry.

**Do not quote them as evidence, screenshots, or example output.** If you need
real output, run the binary against a real ledger.

## How to tell them apart from real output

A real gantry artifact differs from these fixtures in every one of the following.
If you find yourself unsure which you are holding, check this list:

| Field | Real gantry | These fixtures |
|---|---|---|
| `head.key_id` | `ed25519:` + 16 hex chars | `ledger-local-1` |
| `head.sig` | 128 hex chars (ed25519) | base64, DER-shaped (`MEUCIQD8...`) |
| actor type field | `type` | `kind` |
| `subject_hash` | `sha256:` + 64 hex chars | 56 hex chars |
| rule ids | only ids in `config/policy.json` | includes `r-repo-read`, which is in no tracked policy |
| verify faults | match a `format!` in `src/ledger.rs` | prose that matches none of them |
| `reproduce` paths | a path that exists | `/var/lib/gantry/ledger` |

`healthy/` and `tampered/` differ by exactly one byte in `events.json`, which is
what makes the takeover behaviour testable on demand.
