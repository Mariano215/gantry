//! RFC 6962 Merkle tree over leaf byte strings. Pure functions, no IO, so the
//! offline verifier is this module and nothing else.

pub type Hash = [u8; 32];

use sha2::{Digest, Sha256};

/// SHA-256(0x00 || leaf_bytes)
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(leaf_bytes);
    h.finalize().into()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly smaller than n. n must be >= 2.
fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// MTH over already-hashed leaves. Empty tree is SHA-256 of the empty string.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// RFC 6962 PATH(index, leaves). Sibling roots bottom-up; the recursive
/// definition appends the top-level sibling last.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if index < k {
        let mut p = inclusion_proof(&leaves[..k], index);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(&leaves[k..], index - k);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Recompute the root an inclusion proof implies. None when the proof shape
/// does not fit (index, size).
pub fn root_from_inclusion(leaf: &Hash, index: usize, size: usize, proof: &[Hash]) -> Option<Hash> {
    if index >= size {
        return None;
    }
    if size == 1 {
        return proof.is_empty().then_some(*leaf);
    }
    let (last, rest) = proof.split_last()?;
    let k = split_point(size);
    if index < k {
        let sub = root_from_inclusion(leaf, index, k, rest)?;
        Some(node_hash(&sub, last))
    } else {
        let sub = root_from_inclusion(leaf, index - k, size - k, rest)?;
        Some(node_hash(last, &sub))
    }
}

pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    size: usize,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    root_from_inclusion(leaf, index, size, proof) == Some(*expected_root)
}

/// RFC 6962 PROOF(m, leaves): what a verifier needs to check the tree of the
/// first m leaves is a prefix of the tree over all of them.
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    subproof(leaves, m, true)
}

fn subproof(leaves: &[Hash], m: usize, complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if complete {
            Vec::new()
        } else {
            vec![root(leaves)]
        };
    }
    let k = split_point(n);
    if m <= k {
        let mut p = subproof(&leaves[..k], m, complete);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(&leaves[k..], m - k, false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Reconstruct (old_root, new_root) from a consistency proof, mirroring the
/// recursion that built it. `old_root` is the trusted root of the first m
/// leaves, needed because a complete-subtree branch contributes no element.
fn roots_from_consistency(
    m: usize,
    n: usize,
    complete: bool,
    proof: &[Hash],
    old_root: &Hash,
) -> Option<(Hash, Hash)> {
    if m == n {
        return if complete {
            proof.is_empty().then_some((*old_root, *old_root))
        } else {
            match proof {
                [h] => Some((*h, *h)),
                _ => None,
            }
        };
    }
    let (last, rest) = proof.split_last()?;
    let k = split_point(n);
    if m <= k {
        let (o, ne) = roots_from_consistency(m, k, complete, rest, old_root)?;
        Some((o, node_hash(&ne, last)))
    } else {
        // the left subtree of size k is complete and shared by both trees, so
        // its root (the proof element) folds into old and new alike
        let (o, ne) = roots_from_consistency(m - k, n - k, false, rest, old_root)?;
        Some((node_hash(last, &o), node_hash(last, &ne)))
    }
}

pub fn verify_consistency(
    m: usize,
    n: usize,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if m > n || m == 0 {
        // consistency with an empty log is vacuous and never proved
        return m == n && old_root == new_root && proof.is_empty();
    }
    match roots_from_consistency(m, n, true, proof, old_root) {
        Some((o, ne)) => o == *old_root && ne == *new_root,
        None => false,
    }
}
