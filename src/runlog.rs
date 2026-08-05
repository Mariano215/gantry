//! The run event plumbing shared by the gateway and the broker: one run id,
//! one monotonic seq, one actor and authority stamped on every event. Owning
//! this in one place is what keeps "every event answers under whose
//! authority" a property of the type rather than of each caller's diligence.

use crate::event::NewEvent;
use crate::ledger::{Ledger, SignedHead};
use crate::Fault;
use serde_json::{json, Value};

pub struct RunCore {
    ledger: Ledger,
    run_id: String,
    next_seq: u64,
    actor: Value,
    authority: Value,
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
        }
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

    pub fn append(&mut self, kind: &str, subject: Value) -> Result<(), Fault> {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.ledger.append(NewEvent {
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
        })?;
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
