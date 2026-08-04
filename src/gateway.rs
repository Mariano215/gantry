//! Slice 02: the model gateway. Every model call in this crate goes through
//! GatewayRun, which appends the call to the evidence ledger. See
//! docs/superpowers/specs/2026-08-04-model-gateway-design.md.

use crate::event::NewEvent;
use crate::ledger::{Ledger, SignedHead};
use crate::Fault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// RFC 3339 UTC with millisecond precision, the `ts` format the schema uses.
pub fn rfc3339_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339_from_unix(d.as_secs(), d.subsec_millis())
}

pub fn rfc3339_from_unix(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days, the standard days-to-date algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// `sha256:<hex>` over raw file bytes, for authority version pinning.
pub fn file_hash(path: &Path) -> Result<String, Fault> {
    let bytes = std::fs::read(path).map_err(|e| {
        Fault::new(
            format!("cannot read {} for version pinning: {e}", path.display()),
            "check the path exists; every call must pin instruction and policy versions",
        )
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

/// One reachable model endpoint. All three proof environments are entries of
/// this one shape; the seam under test is the event, not the adapter count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    pub base_url: String,
    pub model: String,
    #[serde(default)]
    pub key_env: Option<String>,
    pub window_budget: u64,
    #[serde(default)]
    pub cost_in_per_mtok: f64,
    #[serde(default)]
    pub cost_out_per_mtok: f64,
}

/// The tracked files whose hashes pin authority per event (schema constraint 5).
pub struct Pinning {
    pub policy: PathBuf,
    pub instructions: PathBuf,
    pub settings: Option<PathBuf>,
}

/// An open run. Owning the only route to a model call is what makes the
/// gateway a chokepoint rather than a convention.
pub struct GatewayRun {
    ledger: Ledger,
    run_id: String,
    next_seq: u64,
    actor: Value,
    authority: Value,
    cost_total_usd: f64,
}

pub fn load_providers(path: &Path) -> Result<Vec<Provider>, Fault> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Fault::new(
            format!("cannot read providers file {}: {e}", path.display()),
            "check the path; the tracked file is config/providers.json",
        )
    })?;
    serde_json::from_str(&text).map_err(|e| {
        Fault::new(
            format!("{} does not parse as a provider list: {e}", path.display()),
            "each entry needs name, base_url, model, window_budget; key_env and cost rates are optional",
        )
    })
}

impl GatewayRun {
    pub fn open(ledger: Ledger, workload: &str, pin: &Pinning) -> Result<GatewayRun, Fault> {
        let instruction_version = file_hash(&pin.instructions)?;
        let settings_hash = match &pin.settings {
            Some(p) => Value::String(file_hash(p)?),
            None => Value::Null,
        };
        let authority = json!({
            "profile": "laptop",
            "policy_version": file_hash(&pin.policy)?,
            "instruction_version": instruction_version,
            "settings_hash": settings_hash,
            "diverged": [],
        });
        let actor = json!({
            "type": "agent",
            "id": "agent:gantry-run",
            "identity_source": "local",
            "rung": "assisted",
        });
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let run_id = format!("run-{}", d.as_millis());
        let mut run = GatewayRun {
            ledger,
            run_id,
            next_seq: 0,
            actor,
            authority,
            cost_total_usd: 0.0,
        };
        run.append_event(
            "run.open",
            json!({
                "profile": "laptop",
                "workload": workload,
                "instruction_pack": instruction_version,
                "settings_hash": run.authority["settings_hash"],
                "restored_checkpoint": null,
            }),
        )?;
        Ok(run)
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn seal(mut self, outcome: &str) -> Result<SignedHead, Fault> {
        let head_at_seal = self.ledger.latest_head()?;
        let head_at_seal = serde_json::to_value(&head_at_seal).map_err(|e| {
            Fault::new(
                format!("SignedHead did not serialise: {e}"),
                "report this as a bug; SignedHead is serialisable by construction",
            )
        })?;
        let event_count = self.next_seq;
        let cost = self.cost_total_usd;
        self.append_event(
            "run.seal",
            json!({
                "outcome": outcome,
                "event_count": event_count,
                "head_at_seal": head_at_seal,
                "cost_total_usd": cost,
            }),
        )?;
        self.ledger.latest_head()
    }

    fn append_event(&mut self, kind: &str, subject: Value) -> Result<(), Fault> {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.ledger.append(NewEvent {
            id: format!("{}-{seq}", self.run_id),
            run_id: self.run_id.clone(),
            parent_id: None,
            seq,
            ts: rfc3339_now(),
            kind: kind.to_string(),
            actor: self.actor.clone(),
            authority: self.authority.clone(),
            subject,
            redacted: Vec::new(),
            attestation: None,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339_from_unix(0, 0), "1970-01-01T00:00:00.000Z");
        // date -u -r 1785873600 => 2026-08-04T20:00:00Z
        assert_eq!(rfc3339_from_unix(1_785_873_600, 481), "2026-08-04T20:00:00.481Z");
        // leap-year boundary: 2024-02-29T00:00:00Z
        assert_eq!(rfc3339_from_unix(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn file_hash_pins_bytes() {
        let dir = std::env::temp_dir().join(format!("gantry-gw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pack.md");
        std::fs::write(&p, b"instruction pack v1").unwrap();
        let h1 = file_hash(&p).unwrap();
        assert!(h1.starts_with("sha256:"));
        std::fs::write(&p, b"instruction pack v2").unwrap();
        assert_ne!(file_hash(&p).unwrap(), h1);
        let fault = file_hash(&dir.join("missing.md")).unwrap_err();
        assert!(fault.fix.contains("pin"), "fix names pinning: {fault}");
    }
}
