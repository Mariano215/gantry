//! Slice 09 integration: the resolver refuses a broken skill rather than
//! publishing it on its title, and a skill that references a missing step
//! fails at resolve time, not at run time. Uses the tracked fixture package.

use gantry::skills::{delegate, SkillManifest};
use std::fs;
use std::path::{Path, PathBuf};

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn fixture() -> PathBuf {
    repo_path("docs/proof/fixtures/skill-repo-audit")
}

fn registered_key() -> String {
    fs::read_to_string(repo_path("docs/proof/fixtures/skill-repo-audit.pub"))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn the_signed_fixture_resolves_and_verifies() {
    let pkg = fixture();
    let manifest = SkillManifest::load(&pkg.join("skill.json")).unwrap();
    let resolved = manifest.resolve(&pkg, &[registered_key()]).unwrap();
    assert_eq!(resolved.verdict, "resolved");
    assert!(
        resolved.signature_state.starts_with("verified:"),
        "{}",
        resolved.signature_state
    );
    assert_eq!(resolved.steps.len(), 3);
}

#[test]
fn the_fixture_signature_is_refused_without_the_key() {
    let pkg = fixture();
    let manifest = SkillManifest::load(&pkg.join("skill.json")).unwrap();
    // No registered key: a present signature that cannot be verified is
    // refused, never downgraded to unsigned.
    let err = manifest.resolve(&pkg, &[]).unwrap_err();
    assert!(err.cause.contains("no registered key verifies"), "{err}");
}

#[test]
fn broken_metadata_is_refused_not_titled() {
    let pkg = fixture();
    let mut manifest = SkillManifest::load(&pkg.join("skill.json")).unwrap();
    manifest.description = "   ".into();
    let err = manifest.resolve(&pkg, &[registered_key()]).unwrap_err();
    assert!(err.cause.contains("empty description"), "{err}");
    assert!(err.fix.contains("never substitutes the title"), "{err}");
}

#[test]
fn a_deleted_step_fails_at_resolve_time() {
    let pkg = fixture();
    let mut manifest = SkillManifest::load(&pkg.join("skill.json")).unwrap();
    manifest.steps.push("nonexistent-step".into());
    let err = manifest.resolve(&pkg, &[registered_key()]).unwrap_err();
    assert!(
        err.cause.contains("references step nonexistent-step"),
        "{err}"
    );
    assert!(err.cause.contains("does not exist"), "{err}");
}

#[test]
fn delegation_cannot_widen_scope() {
    let pkg = fixture();
    let manifest = SkillManifest::load(&pkg.join("skill.json")).unwrap();
    // Parent holds repo.read: the skill's scope is a subset, so it narrows.
    let granted = delegate(
        &["repo.read".into(), "repo.write".into()],
        &manifest.scope.capabilities,
    )
    .unwrap();
    assert_eq!(granted, vec!["repo.read".to_string()]);
    // A parent without repo.read cannot delegate the skill at all.
    let err = delegate(&["net.egress".into()], &manifest.scope.capabilities).unwrap_err();
    assert!(err.cause.contains("does not hold"), "{err}");
}
