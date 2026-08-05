//! Append-only ledger: canonical envelope lines in events.jsonl, subject
//! payloads beside them in payloads/, a signed tree head per append in
//! heads.jsonl. Verification reads the files, never this process's memory.

use crate::event::{jcs_bytes, subject_hash, Envelope, NewEvent};
use crate::merkle::{self, Hash};
use crate::Fault;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedHead {
    pub size: u64,
    pub root_hash: String,
    pub ts: String,
    pub key_id: String,
    pub sig: String,
}

/// The fields the head signature covers, in one place so signer and verifier
/// cannot drift.
#[derive(Serialize)]
struct HeadCore<'a> {
    size: u64,
    root_hash: &'a str,
    ts: &'a str,
    key_id: &'a str,
}

/// Everything an offline verifier needs: envelope, position, path, one head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionBundle {
    pub envelope: Envelope,
    pub index: u64,
    pub proof: Vec<String>,
    pub head: SignedHead,
}

/// Everything an offline verifier needs to check that an older signed head is
/// a prefix of a newer one: both heads and the proof between them. A bare
/// proof array is not checkable by itself, which is why the producer emits
/// this instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyBundle {
    pub old_head: SignedHead,
    pub new_head: SignedHead,
    pub proof: Vec<String>,
}

/// A hole in one run's `seq`. The run recorded `after`, then `before`, and
/// `missing` events that were numbered in between are on no line of the log.
/// A finding, never a fault: see `docs/proof/18.md` for why the record cannot
/// tell a killed harness from a producer that numbered an event it never
/// appended, and why a removed entry faults elsewhere instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqGap {
    pub run_id: String,
    pub after: u64,
    pub before: u64,
    pub missing: u64,
}

#[derive(Debug)]
pub struct EntryFault {
    pub index: Option<usize>,
    pub id: Option<String>,
    pub fault: Fault,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub entries: usize,
    pub faults: Vec<EntryFault>,
    /// Attestations present in the log whose key id no registered key
    /// matches. A clean report must say out loud that these were counted,
    /// not validated.
    pub attestations_unverified: usize,
    /// Attestations checked against a registered actor key and found good.
    pub attestations_verified: usize,
    /// Of those verified, how many were signed under a key whose seed is
    /// published. They are real signatures over real bytes and they prove
    /// which run wrote the event, but anyone holding the seed can produce
    /// one, so they are not attribution and no report may imply otherwise.
    pub attestations_under_published_seed: usize,
    /// Runs whose `seq` skips. Reported and counted, and deliberately not a
    /// fault, so `ok()` stays a statement about the record's integrity.
    pub seq_gaps: Vec<SeqGap>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.faults.is_empty()
    }
}

pub struct Ledger {
    dir: PathBuf,
    signing: SigningKey,
    key_id: String,
    envelopes: Vec<Envelope>,
    leaves: Vec<Hash>,
}

fn hash_str(h: &Hash) -> String {
    format!("sha256:{}", hex::encode(h))
}

fn parse_hash(s: &str) -> Option<Hash> {
    let hex_part = s.strip_prefix("sha256:")?;
    let bytes = hex::decode(hex_part).ok()?;
    bytes.try_into().ok()
}

fn key_id_for(vk: &VerifyingKey) -> String {
    let digest = Sha256::digest(vk.as_bytes());
    format!("ed25519:{}", &hex::encode(digest)[..16])
}

impl Ledger {
    pub fn init(dir: &Path) -> Result<Ledger, Fault> {
        if dir.join("events.jsonl").exists() {
            return Err(Fault::new(
                format!("a ledger already exists at {}", dir.display()),
                "open it instead of initialising; a ledger is never recreated in place",
            ));
        }
        fs::create_dir_all(dir.join("payloads")).map_err(io_fault(dir))?;
        fs::create_dir_all(dir.join("keys")).map_err(io_fault(dir))?;
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| {
            Fault::new(
                format!("no OS entropy for key generation: {e}"),
                "run on a host with a working random device",
            )
        })?;
        let signing = SigningKey::from_bytes(&seed);
        fs::write(dir.join("keys/ledger.key"), hex::encode(seed)).map_err(io_fault(dir))?;
        fs::write(
            dir.join("keys/ledger.pub"),
            hex::encode(signing.verifying_key().as_bytes()),
        )
        .map_err(io_fault(dir))?;
        fs::write(dir.join("events.jsonl"), "").map_err(io_fault(dir))?;
        fs::write(dir.join("heads.jsonl"), "").map_err(io_fault(dir))?;
        let key_id = key_id_for(&signing.verifying_key());
        Ok(Ledger {
            dir: dir.to_path_buf(),
            signing,
            key_id,
            envelopes: Vec::new(),
            leaves: Vec::new(),
        })
    }

    pub fn open(dir: &Path) -> Result<Ledger, Fault> {
        let seed_hex = fs::read_to_string(dir.join("keys/ledger.key")).map_err(|_| {
            Fault::new(
                format!("no ledger key at {}", dir.join("keys/ledger.key").display()),
                "initialise the ledger first, or point at the right directory",
            )
        })?;
        let seed: [u8; 32] = hex::decode(seed_hex.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                Fault::new(
                    "ledger key file is not 32 hex-encoded bytes",
                    "restore keys/ledger.key from backup; do not regenerate, past heads would become unverifiable",
                )
            })?;
        let signing = SigningKey::from_bytes(&seed);
        let key_id = key_id_for(&signing.verifying_key());
        let mut ledger = Ledger {
            dir: dir.to_path_buf(),
            signing,
            key_id,
            envelopes: Vec::new(),
            leaves: Vec::new(),
        };
        let events = fs::read_to_string(dir.join("events.jsonl")).map_err(io_fault(dir))?;
        for (i, line) in events.lines().enumerate() {
            let env: Envelope = serde_json::from_str(line).map_err(|e| {
                Fault::new(
                    format!("entry {i} does not parse: {e}"),
                    "run verify to locate the damage, then restore from a replica",
                )
            })?;
            ledger.leaves.push(merkle::leaf_hash(line.as_bytes()));
            ledger.envelopes.push(env);
        }
        Ok(ledger)
    }

    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// The parsed envelopes in append order, positionally identical to what
    /// `events_with_subjects` returns. A caller deriving a per-event property
    /// (an attestation state, say) zips the two rather than re-parsing.
    pub fn envelopes(&self) -> &[Envelope] {
        &self.envelopes
    }

    /// Every appended event as a JSON object with its subject payload inlined
    /// under `_subject`, in append order. This is what a replay over the
    /// ledger reads: the same envelopes an auditor exports, joined to the
    /// payloads that are still retained. An expired payload inlines as null.
    pub fn events_with_subjects(&self) -> Result<Vec<Value>, Fault> {
        let mut out = Vec::with_capacity(self.envelopes.len());
        for env in &self.envelopes {
            let mut obj = serde_json::to_value(env).map_err(|e| {
                Fault::new(
                    format!("envelope does not serialise: {e}"),
                    "report this as a bug; Envelope is serialisable by construction",
                )
            })?;
            let subject = self
                .payload_path(&env.subject_hash)
                .ok()
                .and_then(|p| fs::read_to_string(p).ok())
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .unwrap_or(Value::Null);
            obj["_subject"] = subject;
            out.push(obj);
        }
        Ok(out)
    }

    pub fn append(&mut self, ev: NewEvent) -> Result<Envelope, Fault> {
        let s_hash = subject_hash(&ev.subject)?;
        let payload_path = self.payload_path(&s_hash)?;
        fs::write(&payload_path, jcs_bytes(&ev.subject)?).map_err(io_fault(&self.dir))?;

        let envelope = Envelope {
            v: 2,
            id: ev.id,
            run_id: ev.run_id,
            parent_id: ev.parent_id,
            seq: ev.seq,
            ts: ev.ts,
            kind: ev.kind,
            actor: ev.actor,
            authority: ev.authority,
            subject_hash: s_hash,
            redacted: ev.redacted,
            prev_hash: self.leaves.last().map(hash_str),
            attestation: ev.attestation,
        };
        let bytes = envelope.canonical_bytes()?;
        let leaf = merkle::leaf_hash(&bytes);

        let mut events = fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("events.jsonl"))
            .map_err(io_fault(&self.dir))?;
        events.write_all(&bytes).map_err(io_fault(&self.dir))?;
        events.write_all(b"\n").map_err(io_fault(&self.dir))?;

        self.leaves.push(leaf);
        // ponytail: full recompute per append, O(n) hashing. Incremental tree
        // when append volume makes this measurable.
        let root = merkle::root(&self.leaves);
        let head = self.sign_head(self.leaves.len() as u64, &root, &envelope.ts)?;
        let mut heads = fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("heads.jsonl"))
            .map_err(io_fault(&self.dir))?;
        heads
            .write_all(jcs_bytes(&head)?.as_slice())
            .map_err(io_fault(&self.dir))?;
        heads.write_all(b"\n").map_err(io_fault(&self.dir))?;

        self.envelopes.push(envelope.clone());
        Ok(envelope)
    }

    /// Record the expiry as an event, then remove the payload. The envelope
    /// referencing the expired hash stays, which is the whole point.
    pub fn expire(&mut self, target_hash: &str, ev: NewEvent) -> Result<Envelope, Fault> {
        if ev.kind != "retention.expire" {
            return Err(Fault::new(
                format!("expiry submitted as kind {}", ev.kind),
                "submit the expiry as a retention.expire event so it is on the record",
            ));
        }
        let referenced = self.envelopes.iter().any(|e| e.subject_hash == target_hash);
        if !referenced {
            return Err(Fault::new(
                format!("no envelope references {target_hash}"),
                "expire only payloads the ledger knows; check the hash",
            ));
        }
        let envelope = self.append(ev)?;
        let path = self.payload_path(target_hash)?;
        if path.exists() {
            fs::remove_file(&path).map_err(io_fault(&self.dir))?;
        }
        Ok(envelope)
    }

    pub fn latest_head(&self) -> Result<SignedHead, Fault> {
        let heads =
            fs::read_to_string(self.dir.join("heads.jsonl")).map_err(io_fault(&self.dir))?;
        let last = heads.lines().last().ok_or_else(|| {
            Fault::new(
                "the ledger has no head yet",
                "append at least one event before asking for a head",
            )
        })?;
        serde_json::from_str(last).map_err(|e| {
            Fault::new(
                format!("latest head does not parse: {e}"),
                "run verify to locate the damage, then restore heads.jsonl from a replica",
            )
        })
    }

    pub fn prove(&self, index: usize) -> Result<InclusionBundle, Fault> {
        let envelope = self.envelopes.get(index).cloned().ok_or_else(|| {
            Fault::new(
                format!("no entry at index {index}, ledger has {}", self.size()),
                "ask for an index below the ledger size",
            )
        })?;
        let proof = merkle::inclusion_proof(&self.leaves, index)
            .iter()
            .map(hash_str)
            .collect();
        Ok(InclusionBundle {
            envelope,
            index: index as u64,
            proof,
            head: self.latest_head()?,
        })
    }

    /// The head this ledger signed when it held exactly `size` entries. Every
    /// append writes one, so a size a head was never written at is an error
    /// rather than an empty answer.
    pub fn head_at(&self, size: u64) -> Result<SignedHead, Fault> {
        let heads =
            fs::read_to_string(self.dir.join("heads.jsonl")).map_err(io_fault(&self.dir))?;
        heads
            .lines()
            .filter_map(|l| serde_json::from_str::<SignedHead>(l).ok())
            .find(|h| h.size == size)
            .ok_or_else(|| {
                Fault::new(
                    format!(
                        "no signed head at size {size}; the ledger holds {} entries",
                        self.size()
                    ),
                    "ask for a size between 1 and the ledger size; every append writes one head, so a missing one means heads.jsonl was truncated and must be restored from a replica",
                )
            })
    }

    /// The proof plus both heads, which is what a third party can actually
    /// check. `m` is the older tree size.
    pub fn consistency_bundle(&self, m: usize) -> Result<ConsistencyBundle, Fault> {
        Ok(ConsistencyBundle {
            old_head: self.head_at(m as u64)?,
            new_head: self.latest_head()?,
            proof: self.consistency(m)?,
        })
    }

    /// Copy the current signed head to `dest` and record a `ledger.anchor`
    /// naming it. The caller supplies the event so the ledger stays free of
    /// policy; the subject is built here so an anchor event cannot name a head
    /// that was not written. What this proves is bounded and the payload says
    /// so: a copy the log's writer can rewrite proves nothing, so the
    /// destination is refused inside the ledger directory and refused when a
    /// file is already there, because overwriting an older anchor destroys the
    /// only thing an anchor is.
    pub fn anchor(
        &mut self,
        dest: &Path,
        mut ev: NewEvent,
    ) -> Result<(SignedHead, Envelope), Fault> {
        if ev.kind != "ledger.anchor" {
            return Err(Fault::new(
                format!("anchor submitted as kind {}", ev.kind),
                "submit the anchor as a ledger.anchor event so the copy is on the record",
            ));
        }
        let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
        let parent_abs = match parent {
            Some(p) => p.canonicalize().map_err(|e| {
                Fault::new(
                    format!("no directory for the anchor at {}: {e}", p.display()),
                    "create the destination directory first, on storage the process writing this ledger cannot rewrite",
                )
            })?,
            None => Path::new(".").canonicalize().map_err(io_fault(&self.dir))?,
        };
        let dir_abs = self
            .dir
            .canonicalize()
            .unwrap_or_else(|_| self.dir.to_path_buf());
        if parent_abs.starts_with(&dir_abs) {
            return Err(Fault::new(
                format!(
                    "the anchor destination {} is inside the ledger at {}",
                    dest.display(),
                    self.dir.display()
                ),
                "anchor outside the ledger directory; a copy that whoever rewrites the log also rewrites detects nothing",
            ));
        }
        if dest.exists() {
            return Err(Fault::new(
                format!("an anchor already exists at {}", dest.display()),
                "anchor to a new path; overwriting the older copy destroys the record this check compares against",
            ));
        }
        let head = self.latest_head()?;
        ev.subject = serde_json::json!({
            "anchor_kind": "file_copy",
            "destination": parent_abs.join(dest.file_name().unwrap_or_default()).display().to_string(),
            "tree_size": head.size,
            "head": head,
            "anchored_at": ev.ts,
            "receipt": null,
            "proves": "a party holding this copy detects a later rewrite of any entry at or before tree_size, by checking a consistency proof from the anchored head against the log's current head",
            "does_not_prove": "anything at all to a party who does not hold the copy, and nothing about a rewrite that also rewrites the copy. The file was written by the process that writes this ledger, so this anchor is worth exactly the independence of where it was put.",
        });
        let mut bytes = jcs_bytes(&head)?;
        bytes.push(b'\n');
        fs::write(dest, bytes).map_err(|e| {
            Fault::new(
                format!("could not write the anchor to {}: {e}", dest.display()),
                "point the anchor at a writable path outside the ledger directory",
            )
        })?;
        let envelope = self.append(ev)?;
        Ok((head, envelope))
    }

    pub fn consistency(&self, m: usize) -> Result<Vec<String>, Fault> {
        if m == 0 || m > self.size() {
            return Err(Fault::new(
                format!(
                    "no tree of size {m} to prove consistent, ledger has {}",
                    self.size()
                ),
                "ask for a size between 1 and the ledger size",
            ));
        }
        Ok(merkle::consistency_proof(&self.leaves, m)
            .iter()
            .map(hash_str)
            .collect())
    }

    fn sign_head(&self, size: u64, root: &Hash, ts: &str) -> Result<SignedHead, Fault> {
        // ponytail: head ts is the appended event's ts, not a wall clock, so
        // appends are deterministic and replayable. A clock source lands with
        // the anchor feature that needs one.
        let root_hash = hash_str(root);
        let core = HeadCore {
            size,
            root_hash: &root_hash,
            ts,
            key_id: &self.key_id,
        };
        let sig = self.signing.sign(&jcs_bytes(&core)?);
        Ok(SignedHead {
            size,
            root_hash,
            ts: ts.to_string(),
            key_id: self.key_id.clone(),
            sig: hex::encode(sig.to_bytes()),
        })
    }

    fn payload_path(&self, s_hash: &str) -> Result<PathBuf, Fault> {
        let hex_part = s_hash.strip_prefix("sha256:").ok_or_else(|| {
            Fault::new(
                format!("subject hash {s_hash} is not sha256:<hex>"),
                "hash the payload with sha256 over its RFC 8785 form",
            )
        })?;
        Ok(self.dir.join("payloads").join(format!("{hex_part}.json")))
    }
}

fn io_fault(dir: &Path) -> impl Fn(std::io::Error) -> Fault + '_ {
    move |e| {
        Fault::new(
            format!("ledger io failed under {}: {e}", dir.display()),
            "check the directory exists and is writable",
        )
    }
}

/// What an event's attestation is worth. Four values, derived per event and
/// never assumed. `absent` and `verified` are different facts and a reader
/// that renders them the same way is the failure this project exists to
/// catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationState {
    /// Checked against a registered actor key and good.
    Verified,
    /// An attestation is present but no registered key matches its key id.
    /// Counted, never passed.
    Unverified,
    /// An attestation under a registered key id that fails the check: the
    /// envelope was altered after signing, or the signature was forged.
    Forged,
    /// No attestation on the event.
    Absent,
}

impl AttestationState {
    /// The wire spelling, shared by the API and any message that names it.
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationState::Verified => "verified",
            AttestationState::Unverified => "unverified",
            AttestationState::Forged => "forged",
            AttestationState::Absent => "absent",
        }
    }
}

/// Registered actor keys, parsed once and indexed by the key id an
/// attestation names. A hex key that does not parse is dropped here rather
/// than treated as a match, so an event signed under it reads as unverified
/// and never as verified.
pub struct ActorKeys(Vec<(String, VerifyingKey)>, Vec<String>);

impl ActorKeys {
    pub fn parse(hex_keys: &[String]) -> ActorKeys {
        ActorKeys::parse_with_published(hex_keys, &[])
    }

    /// `published` names the subset whose seed is public. Those keys still
    /// verify, and `trust_of` reports them as `fixture` so no caller can
    /// count them as attribution by accident.
    pub fn parse_with_published(hex_keys: &[String], published: &[String]) -> ActorKeys {
        let ids = |keys: &[String]| -> Vec<(String, VerifyingKey)> {
            keys.iter()
                .filter_map(|hex_key| {
                    crate::skills::parse_vk(hex_key).map(|vk| (crate::skills::key_id_for(&vk), vk))
                })
                .collect()
        };
        let published_ids = ids(published).into_iter().map(|(id, _)| id).collect();
        ActorKeys(ids(hex_keys), published_ids)
    }

    /// What a verified signature under this event's key is worth: `registered`
    /// when the seed is held, `fixture` when it is published. Only meaningful
    /// alongside a `Verified` state.
    pub fn trust_of(&self, env: &Envelope) -> &'static str {
        let key_id = env
            .attestation
            .as_ref()
            .and_then(|a| a["key_id"].as_str())
            .unwrap_or("");
        if self.1.iter().any(|id| id == key_id) {
            "fixture"
        } else {
            "registered"
        }
    }

    /// The one place an attestation is judged. The full verifier and the
    /// console API both call it, so they cannot disagree about whether a
    /// signature is good.
    pub fn state_of(&self, env: &Envelope) -> AttestationState {
        let Some(att) = &env.attestation else {
            return AttestationState::Absent;
        };
        let key_id = att["key_id"].as_str().unwrap_or("");
        let Some((_, vk)) = self.0.iter().find(|(id, _)| id == key_id) else {
            return AttestationState::Unverified;
        };
        let sig = att["value"]
            .as_str()
            .and_then(|v| hex::decode(v).ok())
            .and_then(|b| b.try_into().ok())
            .map(|b: [u8; 64]| Signature::from_bytes(&b));
        match (&sig, env.attestation_bytes()) {
            (Some(sig), Ok(msg)) if vk.verify(&msg, sig).is_ok() => AttestationState::Verified,
            _ => AttestationState::Forged,
        }
    }
}

/// Verify one event offline: the bundle plus the ledger public key, no
/// filesystem, no ledger.
pub fn verify_bundle(bundle: &InclusionBundle, pub_key_hex: &str) -> Result<(), Fault> {
    let vk = parse_pub_key(pub_key_hex)?;
    verify_head_sig(&bundle.head, &vk)?;
    let leaf = merkle::leaf_hash(&bundle.envelope.canonical_bytes()?);
    let root = parse_hash(&bundle.head.root_hash).ok_or_else(bad_hash(&bundle.head.root_hash))?;
    let proof: Vec<Hash> = bundle
        .proof
        .iter()
        .map(|s| parse_hash(s).ok_or_else(bad_hash(s)))
        .collect::<Result<_, _>>()?;
    if !merkle::verify_inclusion(
        &leaf,
        bundle.index as usize,
        bundle.head.size as usize,
        &proof,
        &root,
    ) {
        return Err(Fault::new(
            format!(
                "inclusion fails: entry {} (id {}) does not resolve to the signed root at size {}",
                bundle.index, bundle.envelope.id, bundle.head.size
            ),
            "the envelope or the proof was altered; fetch a fresh bundle from the ledger",
        ));
    }
    Ok(())
}

/// Check a consistency bundle offline: both heads must be this ledger's, and
/// the older tree must be a prefix of the newer one. The old head's signature
/// is checked too, because "a head this log signed" is half the claim; a root
/// a stranger typed in proves nothing about what the log ever published.
pub fn verify_consistency_bundle(
    bundle: &ConsistencyBundle,
    pub_key_hex: &str,
) -> Result<(), Fault> {
    let vk = parse_pub_key(pub_key_hex)?;
    verify_head_sig(&bundle.old_head, &vk)?;
    verify_consistency_hex(
        bundle.old_head.size,
        &bundle.old_head.root_hash,
        &bundle.new_head,
        &bundle.proof,
        pub_key_hex,
    )
}

pub fn verify_consistency_hex(
    m: u64,
    old_root: &str,
    new_head: &SignedHead,
    proof_hex: &[String],
    pub_key_hex: &str,
) -> Result<(), Fault> {
    let vk = parse_pub_key(pub_key_hex)?;
    verify_head_sig(new_head, &vk)?;
    let old = parse_hash(old_root).ok_or_else(bad_hash(old_root))?;
    let new = parse_hash(&new_head.root_hash).ok_or_else(bad_hash(&new_head.root_hash))?;
    let proof: Vec<Hash> = proof_hex
        .iter()
        .map(|s| parse_hash(s).ok_or_else(bad_hash(s)))
        .collect::<Result<_, _>>()?;
    if !merkle::verify_consistency(m as usize, new_head.size as usize, &old, &new, &proof) {
        return Err(Fault::new(
            format!(
                "consistency fails: the tree of size {m} is not a prefix of the signed tree of size {}",
                new_head.size
            ),
            "the log was rewritten between the two heads; treat every entry after the old head as suspect and restore from a replica",
        ));
    }
    Ok(())
}

/// Holes in `seq`, per run, in the order the runs first appear. Interior gaps
/// only: what a run's numbering starts at is the producer's business (the
/// gateway and the broker start at 0, a hand-written trace at 1), so a first
/// recorded seq above zero is not read as a missing opening. A sensor that
/// fires on everything is as broken as one that never fires.
fn seq_gaps(envelopes: &[Option<Envelope>]) -> Vec<SeqGap> {
    let mut runs: Vec<(String, Vec<u64>)> = Vec::new();
    for env in envelopes.iter().flatten() {
        match runs.iter_mut().find(|(id, _)| *id == env.run_id) {
            Some((_, seqs)) => seqs.push(env.seq),
            None => runs.push((env.run_id.clone(), vec![env.seq])),
        }
    }
    let mut gaps = Vec::new();
    for (run_id, mut seqs) in runs {
        seqs.sort_unstable();
        seqs.dedup();
        for pair in seqs.windows(2) {
            if pair[1] > pair[0] + 1 {
                gaps.push(SeqGap {
                    run_id: run_id.clone(),
                    after: pair[0],
                    before: pair[1],
                    missing: pair[1] - pair[0] - 1,
                });
            }
        }
    }
    gaps
}

fn bad_hash(s: &str) -> impl Fn() -> Fault + '_ {
    move || {
        Fault::new(
            format!("{s} is not sha256:<64 hex>"),
            "regenerate the artifact from the ledger",
        )
    }
}

fn parse_pub_key(pub_key_hex: &str) -> Result<VerifyingKey, Fault> {
    hex::decode(pub_key_hex.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| {
            Fault::new(
                "public key is not a valid hex-encoded ed25519 key",
                "use the contents of keys/ledger.pub from the ledger that issued the head",
            )
        })
}

fn verify_head_sig(head: &SignedHead, vk: &VerifyingKey) -> Result<(), Fault> {
    let core = HeadCore {
        size: head.size,
        root_hash: &head.root_hash,
        ts: &head.ts,
        key_id: &head.key_id,
    };
    let sig_bytes: [u8; 64] = hex::decode(&head.sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            Fault::new(
                "head signature is not 64 hex-encoded bytes",
                "fetch the head again from heads.jsonl",
            )
        })?;
    vk.verify(&jcs_bytes(&core)?, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| {
            Fault::new(
                format!("head signature at size {} does not verify", head.size),
                "the head was altered or signed by a different key; check keys/ledger.pub matches the ledger that wrote it",
            )
        })
}

/// Full verification from the files alone. Every fault names the entry and
/// the divergence, because the reader repairing this is an agent.
pub fn verify(dir: &Path) -> Result<VerifyReport, Fault> {
    verify_with_actor_keys(dir, &[])
}

/// ci/secret-in-prompt: grep every stored byte of a ledger for known secret
/// values. `secrets` pairs a handle name with its value; the caller reads
/// them from the same GANTRY_HANDLE_* environment the credential broker
/// substitutes from, so the scanner and the broker agree on what a secret
/// is. A hit names the handle and the file, never the value.
pub fn scan_for_secrets(dir: &Path, secrets: &[(String, String)]) -> Result<Vec<Fault>, Fault> {
    let mut hits = Vec::new();
    let mut files: Vec<PathBuf> = vec![dir.join("events.jsonl"), dir.join("heads.jsonl")];
    if let Ok(entries) = fs::read_dir(dir.join("payloads")) {
        for entry in entries.flatten() {
            files.push(entry.path());
        }
    }
    for file in files {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for (handle, value) in secrets {
            if !value.is_empty() && text.contains(value.as_str()) {
                hits.push(Fault::new(
                    format!(
                        "the value of secret handle {handle} appears in {}",
                        file.display()
                    ),
                    "a secret value must never be stored; expire the payload, rotate the credential, and find the code path that wrote the value instead of the handle",
                ));
            }
        }
    }
    Ok(hits)
}

/// Full verification with an actor key registry. An attestation whose key id
/// resolves to a registered key is checked and a failure is a fault; one
/// whose key id no registered key matches is counted unverified and the
/// report says so, because a partial registry must not turn "unchecked" into
/// "clean".
pub fn verify_with_actor_keys(dir: &Path, actor_keys: &[String]) -> Result<VerifyReport, Fault> {
    verify_with_actor_keys_and_published(dir, actor_keys, &[])
}

/// The same verification, told which registered keys have a published seed.
/// A signature under one of those still verifies, and the report counts it
/// separately so a caller cannot present a laptop fixture attestation as
/// attribution. Callers that hold a registry should use this form; the
/// two-argument version exists for callers that have no registry to ask.
pub fn verify_with_actor_keys_and_published(
    dir: &Path,
    actor_keys: &[String],
    published_seeds: &[String],
) -> Result<VerifyReport, Fault> {
    let mut report = VerifyReport::default();
    let events = fs::read_to_string(dir.join("events.jsonl")).map_err(io_fault(dir))?;
    let pub_hex = fs::read_to_string(dir.join("keys/ledger.pub")).map_err(io_fault(dir))?;
    let vk = parse_pub_key(&pub_hex)?;

    let mut envelopes: Vec<Option<Envelope>> = Vec::new();
    let mut leaves: Vec<Hash> = Vec::new();
    for (i, line) in events.lines().enumerate() {
        leaves.push(merkle::leaf_hash(line.as_bytes()));
        match serde_json::from_str::<Envelope>(line) {
            Ok(env) => {
                match env.canonical_bytes() {
                    Ok(canon) if canon != line.as_bytes() => report.faults.push(EntryFault {
                        index: Some(i),
                        id: Some(env.id.clone()),
                        fault: Fault::new(
                            format!("entry {i} (id {}) is not in canonical form", env.id),
                            "the line was rewritten after append; restore it from a replica",
                        ),
                    }),
                    _ => {}
                }
                envelopes.push(Some(env));
            }
            Err(e) => {
                report.faults.push(EntryFault {
                    index: Some(i),
                    id: None,
                    fault: Fault::new(
                        format!("entry {i} does not parse as an envelope: {e}"),
                        "restore the line from a replica; the ledger is append-only",
                    ),
                });
                envelopes.push(None);
            }
        }
    }
    report.entries = leaves.len();
    report.seq_gaps = seq_gaps(&envelopes);

    // Chain: prev_hash of entry i must equal the leaf hash of entry i-1.
    for i in 0..envelopes.len() {
        let Some(env) = &envelopes[i] else { continue };
        let expected = if i == 0 {
            None
        } else {
            Some(hash_str(&leaves[i - 1]))
        };
        if env.prev_hash != expected {
            report.faults.push(EntryFault {
                index: Some(i.saturating_sub(1)),
                id: envelopes[i.saturating_sub(1)]
                    .as_ref()
                    .map(|e| e.id.clone()),
                fault: Fault::new(
                    format!(
                        "chain diverges between entry {} and entry {i}: entry {i} records prev_hash {:?}, recomputed leaf hash of entry {} is {:?}",
                        i.saturating_sub(1),
                        env.prev_hash,
                        i.saturating_sub(1),
                        expected
                    ),
                    format!(
                        "entry {} was altered after append; restore it from a replica",
                        i.saturating_sub(1)
                    ),
                ),
            });
        }
    }

    // Heads: every signed head must match the recomputed prefix root. The
    // first mismatching head names the newest entry it covers, which is how a
    // tamper in the final entry (invisible to the chain) still gets a name.
    // The walk stops at the first divergence: every later head necessarily
    // diverges too, and repeating the fault would bury the entry that matters.
    let heads_text = fs::read_to_string(dir.join("heads.jsonl")).map_err(io_fault(dir))?;
    let mut covered = 0usize;
    let mut head_walk_faulted = false;
    for (h_idx, line) in heads_text.lines().enumerate() {
        let head: SignedHead = match serde_json::from_str(line) {
            Ok(h) => h,
            Err(e) => {
                report.faults.push(EntryFault {
                    index: None,
                    id: None,
                    fault: Fault::new(
                        format!("head {h_idx} does not parse: {e}"),
                        "restore heads.jsonl from a replica",
                    ),
                });
                head_walk_faulted = true;
                continue;
            }
        };
        if let Err(f) = verify_head_sig(&head, &vk) {
            report.faults.push(EntryFault {
                index: None,
                id: None,
                fault: f,
            });
            head_walk_faulted = true;
            continue;
        }
        let size = head.size as usize;
        if size > leaves.len() {
            report.faults.push(EntryFault {
                index: Some(leaves.len()),
                id: None,
                fault: Fault::new(
                    format!(
                        "the log was truncated: signed head {h_idx} covers {size} entries, events.jsonl has {}",
                        leaves.len()
                    ),
                    "restore the missing entries from a replica; deleting an envelope is never permitted",
                ),
            });
            head_walk_faulted = true;
            break;
        }
        let recomputed = hash_str(&merkle::root(&leaves[..size]));
        if recomputed != head.root_hash {
            let suspect = size - 1;
            report.faults.push(EntryFault {
                index: Some(suspect),
                id: envelopes[suspect].as_ref().map(|e| e.id.clone()),
                fault: Fault::new(
                    format!(
                        "Merkle root diverges first at tree size {size}: recomputed {recomputed}, signed head says {}. Newest entry under that head is entry {suspect}{}",
                        head.root_hash,
                        envelopes[suspect]
                            .as_ref()
                            .map(|e| format!(" (id {})", e.id))
                            .unwrap_or_default()
                    ),
                    format!("restore entry {suspect} from a replica and re-verify"),
                ),
            });
            head_walk_faulted = true;
            break;
        }
        covered = size;
    }

    // Tail coverage: the newest entry has no successor to chain-check it, so
    // a signed head over the full log is its only defence. A log whose tail
    // no head covers is unattested, not clean.
    if !head_walk_faulted && covered < leaves.len() {
        let first_uncovered = covered;
        report.faults.push(EntryFault {
            index: Some(first_uncovered),
            id: envelopes[first_uncovered].as_ref().map(|e| e.id.clone()),
            fault: Fault::new(
                format!(
                    "entries {first_uncovered}..{} have no signed head covering them{}",
                    leaves.len() - 1,
                    if covered == 0 {
                        "; no signed head verifies at all"
                    } else {
                        ""
                    }
                ),
                "restore heads.jsonl from a replica; every append writes a head, so an uncovered tail means heads were removed",
            ),
        });
    }

    // Attestations: checked against the registry where a key id matches;
    // counted unverified where none does. A registered key that fails to
    // verify is a fault, not a count: the actor either signed different
    // bytes or someone forged the attestation.
    let registered = ActorKeys::parse_with_published(actor_keys, published_seeds);
    for (i, env) in envelopes.iter().enumerate() {
        let Some(env) = env else { continue };
        match registered.state_of(env) {
            AttestationState::Absent => {}
            AttestationState::Unverified => report.attestations_unverified += 1,
            AttestationState::Verified => {
                report.attestations_verified += 1;
                if registered.trust_of(env) == "fixture" {
                    report.attestations_under_published_seed += 1;
                }
            }
            AttestationState::Forged => {
                let key_id = env
                    .attestation
                    .as_ref()
                    .and_then(|att| att["key_id"].as_str())
                    .unwrap_or("")
                    .to_string();
                report.faults.push(EntryFault {
                    index: Some(i),
                    id: Some(env.id.clone()),
                    fault: Fault::new(
                        format!(
                            "entry {i} (id {}) carries an attestation under registered key {key_id} that does not verify",
                            env.id
                        ),
                        "the envelope was altered after signing, or the attestation was forged; restore the entry from a replica or revoke the key",
                    ),
                });
            }
        }
    }

    // Payloads: present means hash must match; absent means an on-record
    // retention.expire must cover it.
    let mut expired: Vec<String> = Vec::new();
    for env in envelopes.iter().flatten() {
        if env.kind == "retention.expire" {
            if let Some(hex_part) = env.subject_hash.strip_prefix("sha256:") {
                let p = dir.join("payloads").join(format!("{hex_part}.json"));
                if let Ok(bytes) = fs::read(&p) {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(target) = v.get("expired").and_then(|t| t.as_str()) {
                            expired.push(target.to_string());
                        }
                    }
                }
            }
        }
    }
    for (i, env) in envelopes.iter().enumerate() {
        let Some(env) = env else { continue };
        let Some(hex_part) = env.subject_hash.strip_prefix("sha256:") else {
            continue;
        };
        let p = dir.join("payloads").join(format!("{hex_part}.json"));
        match fs::read(&p) {
            Ok(bytes) => {
                let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
                if actual != env.subject_hash {
                    report.faults.push(EntryFault {
                        index: Some(i),
                        id: Some(env.id.clone()),
                        fault: Fault::new(
                            format!(
                                "payload for entry {i} (id {}) hashes to {actual}, envelope says {}",
                                env.id, env.subject_hash
                            ),
                            "restore the payload file from a replica; the envelope is the authority",
                        ),
                    });
                }
            }
            Err(_) => {
                if !expired.contains(&env.subject_hash) {
                    report.faults.push(EntryFault {
                        index: Some(i),
                        id: Some(env.id.clone()),
                        fault: Fault::new(
                            format!(
                                "payload for entry {i} (id {}) is missing and no retention.expire event covers {}",
                                env.id, env.subject_hash
                            ),
                            "restore the payload from a replica, or record the expiry as a retention.expire event",
                        ),
                    });
                }
            }
        }
    }

    Ok(report)
}
