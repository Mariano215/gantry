//! Slice 16 integration: `gantry scan` reads a repository and writes nothing.
//! The two properties that matter are that every number carries a path behind
//! it, including the numbers that are zero, and that the tree the scan was
//! pointed at is byte-identical afterwards. Both are asserted here, and the
//! second is asserted twice: once against the running scan, once against the
//! shape of the module, because a read-only property that depends on nobody
//! adding a write later is a promise rather than a control.

use gantry::scan::{scan, RepoRead, STATIC_CEILING};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gantry-scan-it-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Every file under a tree with its bytes and its modification time, which is
/// what a scan that touched anything would change.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>, SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let meta = fs::metadata(&path).unwrap();
                out.push((
                    path.clone(),
                    fs::read(&path).unwrap(),
                    meta.modified().unwrap(),
                ));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn an_empty_repository_scores_zero_and_says_where_it_looked() {
    let dir = workdir("empty");
    let report = scan(&RepoRead::open(&dir).unwrap());

    assert_eq!(report.findings.len(), 12, "twelve primitives, always");
    assert_eq!(report.overall, 0);
    for f in &report.findings {
        assert_eq!(f.score, 0, "primitive {} found nothing", f.primitive);
        assert!(
            f.evidence.contains("looked in") && f.evidence.contains("found nothing"),
            "primitive {} scored 0 without naming the paths it looked in: {}",
            f.primitive,
            f.evidence
        );
        // The paths have to be real strings, not an empty list rendered as a
        // sentence: a zero with no path behind it is the thing this command
        // exists to refuse.
        assert!(f.evidence.len() > "looked in : found nothing".len());
    }
    assert!(report.checks_read.is_empty());
    assert!(report.markers.is_empty());
    let text = report.text();
    assert!(text.contains("no primitive here can score above 2"));
}

#[test]
fn a_scan_never_writes_to_the_target() {
    let dir = workdir("readonly");
    fs::create_dir_all(dir.join(".claude/hooks")).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(
        dir.join("CLAUDE.md"),
        "# rules\n`[UNENFORCED]` `ci/nothing`\n",
    )
    .unwrap();
    fs::write(dir.join(".claude/hooks/pre.sh"), "echo hi\n").unwrap();
    fs::write(dir.join("tests/t.rs"), "fn main() {}\n").unwrap();

    let before = snapshot(&dir);
    let report = scan(&RepoRead::open(&dir).unwrap());
    let after = snapshot(&dir);

    assert_eq!(
        before, after,
        "the scan changed the tree it was pointed at; it reads and nothing else"
    );
    // And it did do the work, so the comparison is not passing on an empty run.
    assert!(report.findings.iter().any(|f| f.score > 0));
}

#[test]
fn the_scanner_holds_no_write_capable_filesystem_call() {
    let source = fs::read_to_string(repo_path("src/scan.rs")).unwrap();
    // The names of every std::fs entry point that can change a tree. The scan
    // is read-only because none of them is reachable from this module, not
    // because the author meant well.
    for forbidden in [
        "fs::write",
        "File::create",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "remove_dir",
        "fs::rename",
        "fs::copy",
        "set_permissions",
        "fs::hard_link",
        "fs::soft_link",
    ] {
        assert!(
            !source.contains(forbidden),
            "src/scan.rs references {forbidden}; gantry scan is read-only, so every filesystem call in it goes through RepoRead, which has no write"
        );
    }
}

#[test]
fn an_artifact_scores_two_and_a_check_naming_it_scores_three() {
    let dir = workdir("tiers");
    fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(dir.join("tests/t.rs"), "fn main() {}\n").unwrap();

    let verification = |root: &Path| {
        scan(&RepoRead::open(root).unwrap())
            .findings
            .into_iter()
            .find(|f| f.primitive == 10)
            .unwrap()
    };

    let before = verification(&dir);
    assert_eq!(before.score, 2, "tests exist and nothing runs them");
    assert!(before.evidence.contains("tests/"));

    fs::create_dir_all(dir.join("ci")).unwrap();
    fs::write(dir.join("ci/run.sh"), "cargo test --all\n").unwrap();
    let after = verification(&dir);
    assert_eq!(after.score, 3, "a check file names the tests");
    assert!(
        after.evidence.contains("ci/run.sh"),
        "the score has to name the check: {}",
        after.evidence
    );

    // A comment is not a check. This is the line between measuring a
    // repository and flattering a well-commented one.
    fs::write(
        dir.join("ci/run.sh"),
        "# we should run cargo test one day\n",
    )
    .unwrap();
    let commented = verification(&dir);
    assert_eq!(
        commented.score, 2,
        "a comment mentioning tests is not a gate"
    );
}

#[test]
fn scanning_this_repository_stays_under_its_own_ceiling_and_reports_its_markers() {
    let report = scan(&RepoRead::open(&repo_path(".")).unwrap());

    for f in &report.findings {
        assert!(
            f.score <= STATIC_CEILING,
            "primitive {} scored {}, above the static ceiling; a file cannot show a check running",
            f.primitive,
            f.score
        );
        assert!(
            !f.evidence.trim().is_empty(),
            "primitive {} scored with no evidence behind it",
            f.primitive
        );
    }
    assert!(
        report.overall <= STATIC_CEILING,
        "the static overall must not exceed the ceiling, and must not exceed what gantry score reads off a real ledger"
    );
    assert!(
        report
            .markers
            .iter()
            .any(|m| m.check.as_deref() == Some("ci/sensor-placement-honoured")),
        "the scan did not report the [UNENFORCED] marker CLAUDE.md carries, which is the one thing CLAUDE.md says it will do"
    );
}
