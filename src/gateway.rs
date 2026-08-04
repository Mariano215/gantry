//! Slice 02: the model gateway. Every model call in this crate goes through
//! GatewayRun, which appends the call to the evidence ledger. See
//! docs/superpowers/specs/2026-08-04-model-gateway-design.md.

use crate::Fault;
use sha2::{Digest, Sha256};
use std::path::Path;

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
