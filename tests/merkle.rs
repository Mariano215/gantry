use gantry::merkle::*;
use sha2::{Digest, Sha256};

fn leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| leaf_hash(format!("leaf-{i}").as_bytes()))
        .collect()
}

#[test]
fn empty_root_is_sha256_of_empty_string() {
    let expected: Hash = Sha256::digest([]).into();
    assert_eq!(root(&[]), expected);
}

#[test]
fn single_leaf_root_is_the_leaf_hash() {
    let l = leaves(1);
    assert_eq!(root(&l), l[0]);
}

#[test]
fn leaf_hash_uses_rfc6962_prefix() {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(b"x");
    let manual: Hash = h.finalize().into();
    assert_eq!(leaf_hash(b"x"), manual);
}

#[test]
fn inclusion_proofs_verify_for_every_index_and_size() {
    for n in 1..=32 {
        let l = leaves(n);
        let r = root(&l);
        for i in 0..n {
            let p = inclusion_proof(&l, i);
            assert!(
                verify_inclusion(&l[i], i, n, &p, &r),
                "inclusion failed at index {i} size {n}"
            );
        }
    }
}

#[test]
fn inclusion_fails_for_wrong_leaf_index_or_proof() {
    let l = leaves(11);
    let r = root(&l);
    let p = inclusion_proof(&l, 4);
    assert!(
        !verify_inclusion(&l[5], 4, 11, &p, &r),
        "wrong leaf accepted"
    );
    assert!(
        !verify_inclusion(&l[4], 5, 11, &p, &r),
        "wrong index accepted"
    );
    let mut bad = p.clone();
    bad[0][0] ^= 1;
    assert!(
        !verify_inclusion(&l[4], 4, 11, &bad, &r),
        "tampered proof accepted"
    );
    assert!(
        !verify_inclusion(&l[4], 4, 11, &p[..p.len() - 1], &r),
        "short proof accepted"
    );
}

#[test]
fn consistency_proofs_verify_for_every_prefix() {
    for n in 1..=20 {
        let l = leaves(n);
        let new_root = root(&l);
        for m in 1..=n {
            let old_root = root(&l[..m]);
            let p = consistency_proof(&l, m);
            assert!(
                verify_consistency(m, n, &old_root, &new_root, &p),
                "consistency failed for m={m} n={n}"
            );
        }
    }
}

#[test]
fn consistency_fails_when_history_rewritten() {
    let l = leaves(12);
    let new_root = root(&l);
    let p = consistency_proof(&l, 7);
    // a different history of size 7
    let other: Vec<Hash> = (0..7)
        .map(|i| leaf_hash(format!("rewritten-{i}").as_bytes()))
        .collect();
    let fake_old = root(&other);
    assert!(!verify_consistency(7, 12, &fake_old, &new_root, &p));
    let mut bad = p.clone();
    bad[0][0] ^= 1;
    let old_root = root(&l[..7]);
    assert!(!verify_consistency(7, 12, &old_root, &new_root, &bad));
}
