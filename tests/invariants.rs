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

/// An arrow asserts a handoff, and an event records one end of it. A table
/// mapping an event kind to a source and a destination lane would make every
/// event an arrow, and the diagram would be complete and partly untrue, which
/// is the defect this project exists to prevent one layer down from a scorer
/// that reads configuration. Every peer in trace.js is read out of a subject
/// field, so this asserts the shape that keeps it that way.
#[test]
fn the_trace_view_derives_no_edge_from_an_event_kind_alone() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = fs::read_to_string(root.join("assets/trace.js")).unwrap();
    let peers = src
        .split_once("const PEER_FIELD = {")
        .expect("trace.js declares PEER_FIELD, the one place a peer is read")
        .1
        .split_once("};")
        .expect("PEER_FIELD is a closed object literal")
        .0;
    let mut entries = 0;
    for line in peers.lines().filter(|l| l.contains("=>")) {
        entries += 1;
        assert!(
            line.contains("s."),
            "every PEER_FIELD entry reads a subject field, and this one does not: {line}"
        );
    }
    assert!(
        entries > 0,
        "PEER_FIELD is empty, so this test asserted nothing. Fix: it is the one place a peer is read and it should list every kind whose producer records one"
    );
    // The rendered edge count states both halves, so a reader knows what the
    // picture refused to draw and not only what it drew.
    assert!(
        src.contains("inferred: 0"),
        "the legend prints the inferred count, which is zero by construction and printed anyway"
    );
}
