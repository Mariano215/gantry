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
    /// Attestations present in the log that this verifier did not check.
    /// Actor key distribution does not exist yet, so a clean report must say
    /// out loud that these were counted, not validated.
    pub attestations_unverified: usize,
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

    // Attestations: counted, not validated. There is no actor key registry
    // yet, so pretending to check them would be worse than saying they were
    // not checked. The count travels in the report.
    report.attestations_unverified = envelopes
        .iter()
        .flatten()
        .filter(|e| e.attestation.is_some())
        .count();

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
