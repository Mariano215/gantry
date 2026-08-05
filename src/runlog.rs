//! The run event plumbing shared by the gateway and the broker: one run id,
//! one monotonic seq, one actor and authority stamped on every event. Owning
//! this in one place is what keeps "every event answers under whose
//! authority" a property of the type rather than of each caller's diligence.

use crate::event::{subject_hash, Envelope, NewEvent};
use crate::ledger::{Ledger, SignedHead};
use crate::Fault;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::path::Path;

/// The actor key a profile declares, resolved once at run open and used for
/// every append of that run.
///
/// The declaration lives in the policy, under
/// `profile_requirements.attestation`, because the policy is the one
/// authority document that is tracked, content-hashed and pinned on every
/// event as `authority.policy_version`. A key named there is checkable after
/// the fact: a reader takes the policy version off any event, reads the
/// declared key id, and knows which key that event should carry. A key the
/// code found in an ambient file would be none of those things.
///
/// The seed itself is never the declaration. The profile names where to read
/// it (an environment variable, a file beside the policy) and which key id it
/// must produce; a seed that produces a different key id is refused, so
/// swapping the key material without updating the declaration fails the run
/// rather than quietly signing under a key nothing registered.
pub struct ActorSigner {
    key: SigningKey,
    key_id: String,
}

impl ActorSigner {
    /// Resolves `profile_requirements.attestation`. `Ok(None)` means the
    /// profile declares no actor key and the run appends unsigned, which
    /// `gantry ledger verify` reports as a count of zero attestations rather
    /// than as a pass. Every other failure is a refusal: a profile that
    /// declares a key it cannot load must not start, because appending
    /// unsigned under a profile that says it signs is the silent degradation
    /// the attestation exists to rule out.
    ///
    /// `seed_dir` is the directory holding the policy file, which is what a
    /// relative `seed_file` resolves against, so the declaration travels with
    /// the harness directory rather than with the caller's working directory.
    pub fn declared(requirements: &Value, seed_dir: &Path) -> Result<Option<ActorSigner>, Fault> {
        let block = &requirements["attestation"];
        let declared = block["declared"].as_str().unwrap_or("none");
        if block.is_null() || declared == "none" {
            return Ok(None);
        }
        if declared != "ed25519" {
            return Err(Fault::new(
                format!("profile declares actor attestation algorithm {declared}, which this build cannot sign with"),
                "set profile_requirements.attestation.declared to ed25519, or to none to append unsigned",
            ));
        }
        let seed_hex = match block["seed_env"].as_str().and_then(|var| {
            std::env::var(var)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(|v| (var.to_string(), v))
        }) {
            Some((_, value)) => value,
            None => {
                let file = block["seed_file"].as_str().ok_or_else(|| {
                    Fault::new(
                        format!(
                            "profile declares an actor key but no seed source{}",
                            match block["seed_env"].as_str() {
                                Some(var) => format!(" ({var} is unset or empty)"),
                                None => String::new(),
                            }
                        ),
                        "set profile_requirements.attestation.seed_env and export it, or set seed_file to a seed beside the policy",
                    )
                })?;
                let path = seed_dir.join(file);
                std::fs::read_to_string(&path).map_err(|e| {
                    Fault::new(
                        format!("profile declares actor key seed {} which cannot be read: {e}", path.display()),
                        "restore the seed file, or export the seed under the declared seed_env; a declared key that cannot load refuses the run rather than appending unsigned",
                    )
                })?
            }
        };
        let seed: [u8; 32] = hex::decode(seed_hex.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                Fault::new(
                    "actor key seed is not 32 hex-encoded bytes",
                    "provide a 64-character hex seed; generate one with head -c 32 /dev/urandom | xxd -p -c 32",
                )
            })?;
        let key = SigningKey::from_bytes(&seed);
        let key_id = crate::skills::key_id_for(&key.verifying_key());
        let claimed = block["key_id"].as_str().unwrap_or("");
        if claimed != key_id {
            return Err(Fault::new(
                format!(
                    "profile declares actor key {claimed} but the seed produces {key_id}"
                ),
                format!("set profile_requirements.attestation.key_id to {key_id} and register the public key in config/actor-keys.json, or point the seed source at the declared key"),
            ));
        }
        Ok(Some(ActorSigner { key, key_id }))
    }

    /// The attestation for one event: the actor's signature over
    /// `Envelope::attestation_bytes`, which is the field set the schema says
    /// an actor signs. The envelope built here carries the fields those bytes
    /// cover; `prev_hash` is the ledger's to assign and is excluded by the
    /// signing form.
    fn attest(&self, ev: &NewEvent) -> Result<Value, Fault> {
        let signed_form = Envelope {
            v: 2,
            id: ev.id.clone(),
            run_id: ev.run_id.clone(),
            parent_id: ev.parent_id.clone(),
            seq: ev.seq,
            ts: ev.ts.clone(),
            kind: ev.kind.clone(),
            actor: ev.actor.clone(),
            authority: ev.authority.clone(),
            subject_hash: subject_hash(&ev.subject)?,
            redacted: ev.redacted.clone(),
            prev_hash: None,
            attestation: None,
        };
        let sig = self.key.sign(&signed_form.attestation_bytes()?);
        Ok(json!({
            "alg": "ed25519",
            "key_id": self.key_id,
            "value": hex::encode(sig.to_bytes()),
        }))
    }
}

pub struct RunCore {
    ledger: Ledger,
    run_id: String,
    next_seq: u64,
    actor: Value,
    authority: Value,
    signer: Option<ActorSigner>,
}

impl RunCore {
    pub fn open(ledger: Ledger, actor: Value, authority: Value) -> RunCore {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        RunCore {
            ledger,
            run_id: format!("run-{}", d.as_millis()),
            next_seq: 0,
            actor,
            authority,
            signer: None,
        }
    }

    /// Signs every event of this run with the profile's declared actor key.
    /// `None` leaves the run unsigned, which is what a profile that declares
    /// no key gets. The caller resolves the key before the run opens, so a
    /// declared key that will not load has already refused by here.
    pub fn signed_by(mut self, signer: Option<ActorSigner>) -> RunCore {
        self.signer = signer;
        self
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn event_count(&self) -> u64 {
        self.next_seq
    }

    pub fn authority(&self) -> &Value {
        &self.authority
    }

    pub fn actor(&self) -> &Value {
        &self.actor
    }

    pub fn latest_head(&self) -> Result<SignedHead, Fault> {
        self.ledger.latest_head()
    }

    /// The run's events so far, subjects inlined under `_subject`, for
    /// replaying state (rung history, trust budget) off the ledger itself.
    pub fn replayable_events(&self) -> Result<Vec<Value>, Fault> {
        self.ledger.events_with_subjects()
    }

    pub fn append(&mut self, kind: &str, subject: Value) -> Result<(), Fault> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let mut ev = NewEvent {
            id: format!("{}-{seq}", self.run_id),
            run_id: self.run_id.clone(),
            parent_id: None,
            seq,
            ts: crate::gateway::rfc3339_now(),
            kind: kind.to_string(),
            actor: self.actor.clone(),
            authority: self.authority.clone(),
            subject,
            redacted: Vec::new(),
            attestation: None,
        };
        if let Some(signer) = &self.signer {
            ev.attestation = Some(signer.attest(&ev)?);
        }
        self.ledger.append(ev)?;
        Ok(())
    }

    /// Appends `run.seal` and returns the head covering it. Consumes the run:
    /// nothing can be appended after a seal.
    pub fn seal(mut self, subject_extra: Value, outcome: &str) -> Result<SignedHead, Fault> {
        let head_at_seal = self.ledger.latest_head()?;
        let head_at_seal = serde_json::to_value(&head_at_seal).map_err(|e| {
            Fault::new(
                format!("SignedHead did not serialise: {e}"),
                "report this as a bug; SignedHead is serialisable by construction",
            )
        })?;
        let mut subject = json!({
            "outcome": outcome,
            "event_count": self.next_seq,
            "head_at_seal": head_at_seal,
        });
        if let (Some(map), Some(extra)) = (subject.as_object_mut(), subject_extra.as_object()) {
            for (k, v) in extra {
                map.insert(k.clone(), v.clone());
            }
        }
        self.append("run.seal", subject)?;
        self.ledger.latest_head()
    }
}
