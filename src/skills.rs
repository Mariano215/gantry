//! Slice 09: signed skill packages, a resolver that refuses to publish a
//! broken one, and delegation that can only narrow scope. The failure this
//! slice prevents is the quiet one: a skill whose metadata is broken being
//! loaded anyway on the strength of its title, or a skill that references a
//! step which no longer exists failing only once an agent is mid-run. The
//! resolver makes both fail at resolve time, loudly, with a reason.

use crate::event::jcs_bytes;
use crate::Fault;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

/// A skill's declared scope: the capability ids it may use. Delegation
/// intersects this with the parent's grant and refuses to widen.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature64 {
    pub alg: String,
    pub key_id: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub id: String,
    pub version: String,
    pub description: String,
    /// Step ids the skill runs, each resolved to `steps/<id>.md` under the
    /// package directory. A missing step is a resolve-time failure.
    pub steps: Vec<String>,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub signature: Option<Signature64>,
}

/// The outcome of resolving a skill, one-to-one with a `skill.resolve` event.
#[derive(Debug, Clone, Serialize)]
pub struct Resolved {
    pub id: String,
    pub version: String,
    pub verdict: String,
    pub signature_state: String,
    pub steps: Vec<String>,
    pub scope: Vec<String>,
}

impl SkillManifest {
    pub fn load(path: &Path) -> Result<SkillManifest, Fault> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Fault::new(
                format!("cannot read skill manifest {}: {e}", path.display()),
                "check the path; a skill package is a directory with a skill.json manifest",
            )
        })?;
        serde_json::from_str(&text).map_err(|e| {
            Fault::new(
                format!("{} does not parse as a skill manifest: {e}", path.display()),
                "a manifest needs id, version, description and steps; scope and signature are optional",
            )
        })
    }

    /// The bytes a signature covers: the manifest minus the signature field,
    /// canonicalised. Signing the whole manifest including its own signature
    /// would be circular.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Fault> {
        let mut v = serde_json::to_value(self).map_err(|e| {
            Fault::new(
                format!("skill does not serialise: {e}"),
                "report this as a bug; SkillManifest is serialisable by construction",
            )
        })?;
        if let Some(obj) = v.as_object_mut() {
            obj.remove("signature");
        }
        jcs_bytes(&v)
    }

    /// Metadata validation: the checks that stop a broken skill from being
    /// published on the strength of its title. Every field an agent depends on
    /// must be present and non-empty; the id and description are not
    /// interchangeable, so an empty description is a hard failure even though
    /// the id could stand in for a name.
    pub fn validate_metadata(&self) -> Result<(), Fault> {
        for (field, value) in [
            ("id", &self.id),
            ("version", &self.version),
            ("description", &self.description),
        ] {
            if value.trim().is_empty() {
                return Err(Fault::new(
                    format!("skill {} has an empty {field}", self.id),
                    format!("set a non-empty {field}; the resolver never substitutes the title for a missing field"),
                ));
            }
        }
        if self.steps.is_empty() {
            return Err(Fault::new(
                format!("skill {} declares no steps", self.id),
                "list at least one step id; a skill that does nothing is not published",
            ));
        }
        Ok(())
    }

    /// Resolve the skill against its package directory and an optional key
    /// registry. Refuses on broken metadata, a missing step, or a signature
    /// that is present but does not verify. Returns `Resolved` on success,
    /// which the caller records as a `skill.resolve` event.
    pub fn resolve(&self, package_dir: &Path, registry: &[String]) -> Result<Resolved, Fault> {
        self.validate_metadata()?;
        for step in &self.steps {
            let step_path = package_dir.join("steps").join(format!("{step}.md"));
            if !step_path.exists() {
                return Err(Fault::new(
                    format!(
                        "skill {} references step {step}, but {} does not exist",
                        self.id,
                        step_path.display()
                    ),
                    "restore the missing step file or remove the step from the manifest; a skill is not published with a dangling step",
                ));
            }
        }
        let signature_state = self.verify_signature(registry)?;
        Ok(Resolved {
            id: self.id.clone(),
            version: self.version.clone(),
            verdict: "resolved".to_string(),
            signature_state,
            steps: self.steps.clone(),
            scope: self.scope.capabilities.clone(),
        })
    }

    /// "verified" if a present signature checks against a registered key,
    /// "unsigned" if there is no signature, and a hard error if a signature is
    /// present but does not verify. An unverifiable signature is worse than no
    /// signature, so it refuses rather than degrading to "unsigned".
    fn verify_signature(&self, registry: &[String]) -> Result<String, Fault> {
        let sig = match &self.signature {
            None => return Ok("unsigned".to_string()),
            Some(s) => s,
        };
        if sig.alg != "ed25519" {
            return Err(Fault::new(
                format!(
                    "skill {} signature alg {} is not supported",
                    self.id, sig.alg
                ),
                "sign with ed25519, the only algorithm the resolver verifies",
            ));
        }
        let sig_bytes = hex::decode(&sig.value)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|b: [u8; 64]| Signature::from_bytes(&b))
            .ok_or_else(|| {
                Fault::new(
                    format!("skill {} signature is not 64 hex-encoded bytes", self.id),
                    "re-sign the manifest; the signature value is malformed",
                )
            })?;
        let msg = self.signing_bytes()?;
        for key_hex in registry {
            if let Some(vk) = parse_vk(key_hex) {
                if key_id_for(&vk) == sig.key_id && vk.verify(&msg, &sig_bytes).is_ok() {
                    return Ok(format!("verified:{}", sig.key_id));
                }
            }
        }
        Err(Fault::new(
            format!(
                "skill {} carries a signature ({}) that no registered key verifies",
                self.id, sig.key_id
            ),
            "register the signing key, or re-sign the manifest with a registered key; an unverifiable signature is refused, never downgraded to unsigned",
        ))
    }

    /// Sign the manifest with a hex-encoded ed25519 seed, returning a manifest
    /// carrying the signature. Used to build fixtures and by a future publish
    /// path.
    pub fn signed_with(mut self, seed_hex: &str) -> Result<SkillManifest, Fault> {
        let seed: [u8; 32] = hex::decode(seed_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                Fault::new(
                    "signing seed is not 32 hex-encoded bytes",
                    "pass a 64-character hex seed",
                )
            })?;
        let sk = SigningKey::from_bytes(&seed);
        self.signature = None;
        let msg = self.signing_bytes()?;
        let sig = sk.sign(&msg);
        self.signature = Some(Signature64 {
            alg: "ed25519".to_string(),
            key_id: key_id_for(&sk.verifying_key()),
            value: hex::encode(sig.to_bytes()),
        });
        Ok(self)
    }
}

/// One registered signing key: who owns it and the ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredKey {
    pub owner: String,
    pub public_key_hex: String,
    /// True when the private half is published rather than held, as the
    /// tracked laptop fixture key is. A signature under such a key proves
    /// which run wrote an event, never who operated it, because anyone
    /// holding the repository can produce one. Every report that counts a
    /// verified attestation must say which kind it verified, or a laptop
    /// run reads exactly like an HSM-backed one.
    #[serde(default)]
    pub seed_published: bool,
}

/// The managed key registry, a tracked file (`config/skill-keys.json`). A
/// key that does not parse, or an entry with no owner, refuses the whole
/// registry at load: a registry that silently dropped bad entries would trust
/// fewer keys than version control says it does, and the divergence would be
/// invisible.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyRegistry {
    pub keys: Vec<RegisteredKey>,
}

impl KeyRegistry {
    pub fn load(path: &Path) -> Result<KeyRegistry, Fault> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Fault::new(
                format!("cannot read key registry {}: {e}", path.display()),
                "check the path; the tracked registry is config/skill-keys.json",
            )
        })?;
        let registry: KeyRegistry = serde_json::from_str(&text).map_err(|e| {
            Fault::new(
                format!("{} does not parse as a key registry: {e}", path.display()),
                "the registry is { \"keys\": [ { \"owner\", \"public_key_hex\" } ] }",
            )
        })?;
        for key in &registry.keys {
            if key.owner.trim().is_empty() {
                return Err(Fault::new(
                    format!(
                        "registered key {} names no owner",
                        key.public_key_hex.chars().take(16).collect::<String>()
                    ),
                    "name the owner on every registry entry; an anonymous trust root cannot be audited or revoked",
                ));
            }
            if parse_vk(&key.public_key_hex).is_none() {
                return Err(Fault::new(
                    format!(
                        "registered key for {} is not a valid ed25519 public key",
                        key.owner
                    ),
                    "fix or remove the entry; a corrupt registry is refused whole rather than silently trusting fewer keys",
                ));
            }
        }
        Ok(registry)
    }

    /// The key material in the form `SkillManifest::resolve` consumes.
    pub fn key_hexes(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.public_key_hex.clone()).collect()
    }

    /// The subset whose seed is published. Kept separate from `key_hexes` so
    /// a caller that wants to count verified attestations honestly cannot
    /// forget to ask which of them were signed under a key anyone can use.
    pub fn published_seed_hexes(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|k| k.seed_published)
            .map(|k| k.public_key_hex.clone())
            .collect()
    }
}

/// Delegation: a sub-agent may hold only capabilities the parent holds and the
/// skill's scope names. Scope can narrow, never widen; a skill asking for a
/// capability the parent lacks is refused. Returns the granted set.
pub fn delegate(parent_grant: &[String], skill_scope: &[String]) -> Result<Vec<String>, Fault> {
    for cap in skill_scope {
        if !parent_grant.iter().any(|p| p == cap) {
            return Err(Fault::new(
                format!("skill scope requests capability {cap}, which the parent does not hold"),
                "delegation can only narrow scope; remove the capability from the skill or grant it to the parent first",
            ));
        }
    }
    // The grant is the intersection, which equals the scope here since scope
    // is a proven subset. Stated as an intersection so the direction is clear.
    Ok(skill_scope
        .iter()
        .filter(|c| parent_grant.iter().any(|p| p == *c))
        .cloned()
        .collect())
}

impl Resolved {
    pub fn subject(&self) -> Value {
        json!(self)
    }
}

/// Parse a hex-encoded ed25519 public key. Shared with the ledger verifier,
/// which checks actor attestations against the same registry format.
pub fn parse_vk(hex_str: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_str.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// The key id a public key resolves to: `ed25519:` plus the first 16 hex
/// chars of the SHA-256 of the key bytes.
pub fn key_id_for(vk: &VerifyingKey) -> String {
    let digest = sha2::Sha256::digest(vk.as_bytes());
    format!("ed25519:{}", &hex::encode(digest)[..16])
}

use sha2::Digest as _;

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("gantry-skill-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("steps")).unwrap();
        d
    }

    fn manifest() -> SkillManifest {
        SkillManifest {
            id: "repo-audit".into(),
            version: "1.0".into(),
            description: "Audit a repository for committed secrets.".into(),
            steps: vec!["checkout".into(), "scan".into()],
            scope: Scope {
                capabilities: vec!["repo.read".into()],
            },
            signature: None,
        }
    }

    fn write_steps(dir: &Path, steps: &[&str]) {
        for s in steps {
            std::fs::write(dir.join("steps").join(format!("{s}.md")), "step body").unwrap();
        }
    }

    #[test]
    fn a_good_skill_resolves() {
        let dir = pkg("good");
        write_steps(&dir, &["checkout", "scan"]);
        let r = manifest().resolve(&dir, &[]).unwrap();
        assert_eq!(r.verdict, "resolved");
        assert_eq!(r.signature_state, "unsigned");
    }

    #[test]
    fn broken_metadata_is_refused_not_titled() {
        let dir = pkg("broken");
        write_steps(&dir, &["checkout", "scan"]);
        let mut m = manifest();
        m.description = "  ".into();
        let err = m.resolve(&dir, &[]).unwrap_err();
        assert!(err.cause.contains("empty description"), "{err}");
        assert!(err.fix.contains("never substitutes the title"), "{err}");
    }

    #[test]
    fn a_missing_step_fails_at_resolve_not_at_run() {
        let dir = pkg("missingstep");
        write_steps(&dir, &["checkout"]); // "scan" deliberately absent
        let err = manifest().resolve(&dir, &[]).unwrap_err();
        assert!(err.cause.contains("references step scan"), "{err}");
        assert!(err.cause.contains("does not exist"), "{err}");
    }

    #[test]
    fn a_valid_signature_verifies_and_a_tampered_one_is_refused() {
        let dir = pkg("signed");
        write_steps(&dir, &["checkout", "scan"]);
        let seed = "11".repeat(32);
        let signed = manifest().signed_with(&seed).unwrap();
        let sk = SigningKey::from_bytes(&hex::decode(&seed).unwrap().try_into().unwrap());
        let pub_hex = hex::encode(sk.verifying_key().as_bytes());

        let r = signed
            .resolve(&dir, std::slice::from_ref(&pub_hex))
            .unwrap();
        assert!(
            r.signature_state.starts_with("verified:"),
            "{}",
            r.signature_state
        );

        // Tamper: change the description after signing.
        let mut tampered = signed.clone();
        tampered.description = "now it does something else entirely".into();
        let err = tampered.resolve(&dir, &[pub_hex]).unwrap_err();
        assert!(err.cause.contains("no registered key verifies"), "{err}");
    }

    #[test]
    fn a_signature_from_an_unregistered_key_is_refused() {
        let dir = pkg("unregistered");
        write_steps(&dir, &["checkout", "scan"]);
        let signed = manifest().signed_with(&"22".repeat(32)).unwrap();
        // Empty registry: the signature cannot be verified, so it is refused,
        // not downgraded to unsigned.
        let err = signed.resolve(&dir, &[]).unwrap_err();
        assert!(err.cause.contains("no registered key verifies"), "{err}");
    }

    #[test]
    fn a_registry_with_a_corrupt_key_or_anonymous_entry_refuses_whole() {
        let dir = pkg("registry");
        let path = dir.join("skill-keys.json");

        std::fs::write(
            &path,
            r#"{"keys": [{"owner": "user:mariano@local", "public_key_hex": "not-hex"}]}"#,
        )
        .unwrap();
        let err = KeyRegistry::load(&path).unwrap_err();
        assert!(err.cause.contains("not a valid ed25519"), "{err}");

        std::fs::write(
            &path,
            format!(
                r#"{{"keys": [{{"owner": "  ", "public_key_hex": "{}"}}]}}"#,
                hex::encode(
                    SigningKey::from_bytes(&[7u8; 32])
                        .verifying_key()
                        .as_bytes()
                )
            ),
        )
        .unwrap();
        let err = KeyRegistry::load(&path).unwrap_err();
        assert!(err.cause.contains("names no owner"), "{err}");
    }

    #[test]
    fn a_signed_skill_resolves_against_the_managed_registry() {
        let dir = pkg("managedreg");
        write_steps(&dir, &["checkout", "scan"]);
        let seed = "33".repeat(32);
        let signed = manifest().signed_with(&seed).unwrap();
        let sk = SigningKey::from_bytes(&hex::decode(&seed).unwrap().try_into().unwrap());
        let path = dir.join("skill-keys.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"keys": [{{"owner": "user:mariano@local", "public_key_hex": "{}"}}]}}"#,
                hex::encode(sk.verifying_key().as_bytes())
            ),
        )
        .unwrap();
        let registry = KeyRegistry::load(&path).unwrap();
        let r = signed.resolve(&dir, &registry.key_hexes()).unwrap();
        assert!(r.signature_state.starts_with("verified:"));
    }

    #[test]
    fn delegation_narrows_and_refuses_to_widen() {
        let granted = delegate(
            &["repo.read".into(), "repo.write".into()],
            &["repo.read".into()],
        )
        .unwrap();
        assert_eq!(granted, vec!["repo.read".to_string()]);

        let err = delegate(&["repo.read".into()], &["net.egress".into()]).unwrap_err();
        assert!(err.cause.contains("does not hold"), "{err}");
    }
}
