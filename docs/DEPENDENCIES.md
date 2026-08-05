# Dependencies

Rule from CLAUDE.md: anything with a network or process capability needs a
note here. ureq is the first dependency that does; see below.

| Crate | Why it is here | Network | Process |
|---|---|---|---|
| serde, serde_json | envelope serialisation | no | no |
| serde_jcs | RFC 8785 canonical JSON, EVENT-SCHEMA.md constraint 2 | no | no |
| sha2 | RFC 6962 leaf and node hashing | no | no |
| ed25519-dalek | signed tree heads, actor attestations | no | no |
| getrandom | OS entropy for ledger key generation (syscall only) | no | no |
| hex | hash and key encoding | no | no |
| ureq | gateway adapter HTTP client (rustls) | yes | no |

## ureq

Network capability: yes, and it is the point. The gateway adapter is the one
chokepoint allowed to reach a model provider (architecture invariant one).
Blocking client, rustls, no tokio tree. Tests never use it against a real
host; the suite talks to loopback stubs only.

## site/vendor (not a crate either, noted for the same reason)

The page published to GitHub Pages ships React and ReactDOM 18.3.1, MIT, as
the UMD production builds with their licence headers intact, under
`site/vendor`. They are there so the page fetches nothing at view time: as the
design tool exported it, the page pulled both from unpkg and three font
families from Google Fonts, on a page whose own text says this project fetches
nothing from any host.

Network capability at view time: none, which is the point, and
`ci/site-offline.sh` is what says so rather than this paragraph. The build
(`dev/build-site.py`) copies them from a node_modules directory already on the
build machine and fetches nothing itself; it refuses rather than downloading if
the version `site/support.js` names is not there. Nothing in the Rust binary
links against any of this: it is a static page, served by GitHub, and the
console the binary serves is unrelated and still has no dependency at all.

## std::process (not a crate, noted anyway)

Since slice 03 the broker executes shell commands strictly after an allow
verdict from the policy. Since slice 04 it does so through
`/usr/bin/sandbox-exec` (seatbelt), a platform binary, not a crate: a
per-run profile denies all non-allowlisted network and every write outside
the run's own workdir, and the child's environment is cleared to PATH, HOME,
TMPDIR plus the credential handles the policy granted. This is the crate's
only process capability, and it sits behind the same chokepoint that records
the call. The backend actually in force is recorded on every `tool.request`
(`sandbox`) and on `run.open` (`isolation.active_backend`), so a missing
backend degrades to `none` visibly rather than silently.

`sandbox-exec` is macOS-specific. On a host without it the backend records
`none` and the isolation claim is honestly unmet; a Linux backend
(namespaces or a microvm) is a later slice.
