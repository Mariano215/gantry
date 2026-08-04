# Dependencies

Rule from CLAUDE.md: anything with a network or process capability needs a
note here. Nothing in the current tree has either. Listed anyway so the first
dependency that does has somewhere to go, and so the absence is a statement
rather than an omission.

| Crate | Why it is here | Network | Process |
|---|---|---|---|
| serde, serde_json | envelope serialisation | no | no |
| serde_jcs | RFC 8785 canonical JSON, EVENT-SCHEMA.md constraint 2 | no | no |
| sha2 | RFC 6962 leaf and node hashing | no | no |
| ed25519-dalek | signed tree heads, actor attestations | no | no |
| getrandom | OS entropy for ledger key generation (syscall only) | no | no |
| hex | hash and key encoding | no | no |
