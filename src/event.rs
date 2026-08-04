use crate::Fault;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The signed, hashed, proved unit. Subject payload lives outside, behind
/// `subject_hash`. See docs/EVENT-SCHEMA.md v2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub v: u32,
    pub id: String,
    pub run_id: String,
    pub parent_id: Option<String>,
    pub seq: u64,
    pub ts: String,
    pub kind: String,
    pub actor: Value,
    pub authority: Value,
    pub subject_hash: String,
    pub redacted: Vec<String>,
    pub prev_hash: Option<String>,
    pub attestation: Option<Value>,
}

/// What a producer submits: an envelope minus the fields the ledger assigns
/// (`subject_hash`, `prev_hash`), plus the subject payload inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEvent {
    pub id: String,
    pub run_id: String,
    pub parent_id: Option<String>,
    pub seq: u64,
    pub ts: String,
    pub kind: String,
    pub actor: Value,
    pub authority: Value,
    pub subject: Value,
    #[serde(default)]
    pub redacted: Vec<String>,
    #[serde(default)]
    pub attestation: Option<Value>,
}

/// RFC 8785 canonical bytes of any serialisable value.
pub fn jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, Fault> {
    serde_jcs::to_vec(value).map_err(|e| {
        Fault::new(
            format!("value does not canonicalise under RFC 8785: {e}"),
            "make every field JSON-representable; numbers must be finite",
        )
    })
}

/// `sha256:<hex>` over the JCS form, the format every hash field uses.
pub fn subject_hash(subject: &Value) -> Result<String, Fault> {
    let bytes = jcs_bytes(subject)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

impl Envelope {
    /// The exact bytes the ledger stores and the tree hashes over.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Fault> {
        jcs_bytes(self)
    }
}
