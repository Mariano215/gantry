//! Chokepoint invariant: every provider call goes through the gateway. A
//! direct ureq call anywhere else in src/ or tests/ is a hole in primitive
//! 11, so this test greps for the literal and fails the build if it turns
//! up outside src/gateway.rs.
use std::fs;
use std::path::{Path, PathBuf};

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn ureq_only_in_gateway() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let allowed = root.join("src").join("gateway.rs");
    // This file names the invariant in its own doc comment and assertion
    // message, so it is excluded from its own scan rather than matched.
    let self_file = root.join("tests").join("invariants.rs");

    let mut files = Vec::new();
    files_under(&root.join("src"), &mut files);
    files_under(&root.join("tests"), &mut files);

    for f in files {
        if f == allowed || f == self_file {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap_or_default();
        assert!(
            !text.contains("ureq"),
            "every provider call goes through the gateway, but {} references ureq directly",
            f.display()
        );
    }
}
