//! Slice 07: the corpus graph. A persisted index over a set of files that an
//! agent traverses instead of re-reading the corpus. Each node holds the
//! file's content hash and the symbols it defines or mentions; a query walks
//! the index and reads only the files it points at, where a flat baseline
//! reads everything. The honest part is staleness: a node whose stored hash
//! no longer matches the file is expired and must be re-read, and a query
//! run against a stale graph can lose to the flat scan, which the proof shows
//! rather than hides.

use crate::Fault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub path: String,
    pub content_hash: String,
    pub symbols: BTreeSet<String>,
    /// Bytes of the file at index time, the token proxy a graph hit avoids
    /// re-reading.
    pub size: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Graph {
    pub nodes: Vec<Node>,
}

/// What one retrieval cost and returned, for the flat-vs-graph comparison.
#[derive(Debug, Clone)]
pub struct Retrieval {
    /// Files that matched, sorted.
    pub hits: Vec<String>,
    /// Bytes read to answer, the token proxy.
    pub bytes_read: usize,
    /// Files whose stored hash was stale and had to be re-read.
    pub stale_reread: Vec<String>,
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Symbols are identifier-shaped tokens of four or more characters. Crude on
/// purpose: a real extractor is a language server, and the crudeness is
/// exactly what produces the losing case the proof needs.
pub fn symbols_in(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else {
            if cur.len() >= 4 {
                out.insert(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= 4 {
        out.insert(cur);
    }
    out
}

impl Graph {
    /// Build an index over the given files. Reads every file once, which is
    /// the one-time cost the graph amortises over later queries.
    pub fn build(paths: &[PathBuf]) -> Result<Graph, Fault> {
        let mut nodes = Vec::new();
        for path in paths {
            let bytes = std::fs::read(path).map_err(|e| {
                Fault::new(
                    format!("cannot read {} to index: {e}", path.display()),
                    "check the path exists and is a readable file",
                )
            })?;
            let text = String::from_utf8_lossy(&bytes);
            nodes.push(Node {
                path: path.display().to_string(),
                content_hash: hash_bytes(&bytes),
                symbols: symbols_in(&text),
                size: bytes.len(),
            });
        }
        Ok(Graph { nodes })
    }

    pub fn save(&self, path: &Path) -> Result<(), Fault> {
        let json = serde_json::to_string(self).map_err(|e| {
            Fault::new(
                format!("graph does not serialise: {e}"),
                "report this as a bug; Graph is serialisable by construction",
            )
        })?;
        std::fs::write(path, json).map_err(|e| {
            Fault::new(
                format!("cannot write graph {}: {e}", path.display()),
                "check the directory is writable",
            )
        })
    }

    pub fn load(path: &Path) -> Result<Graph, Fault> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Fault::new(
                format!("cannot read graph {}: {e}", path.display()),
                "build it first with Graph::build then save",
            )
        })?;
        serde_json::from_str(&text).map_err(|e| {
            Fault::new(
                format!("{} does not parse as a graph: {e}", path.display()),
                "rebuild the graph; the on-disk form may be from an older schema",
            )
        })
    }

    /// The index size, the token proxy a graph query pays instead of reading
    /// the whole corpus.
    pub fn index_bytes(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| {
                n.path.len()
                    + n.content_hash.len()
                    + n.symbols.iter().map(|s| s.len()).sum::<usize>()
            })
            .sum()
    }

    /// Graph retrieval. Walk the index for nodes whose symbol set contains
    /// `symbol`; that costs `index_bytes`, not the corpus. If `verify_stale`
    /// is set, re-read any hit whose file hash has changed, and also re-read
    /// stale nodes to catch a symbol the stale index missed. Returns hits and
    /// the bytes read.
    pub fn query(&self, symbol: &str, verify_stale: bool) -> Result<Retrieval, Fault> {
        let mut bytes_read = self.index_bytes();
        let mut hits = BTreeSet::new();
        let mut stale_reread = Vec::new();
        for node in &self.nodes {
            let indexed_hit = node.symbols.contains(symbol);
            if indexed_hit {
                hits.insert(node.path.clone());
            }
            if verify_stale {
                // Re-read to check staleness. A real system reads only nodes a
                // cheaper signal flags; here every node is checked so the
                // expiry path is exercised.
                if let Ok(bytes) = std::fs::read(&node.path) {
                    let current = hash_bytes(&bytes);
                    if current != node.content_hash {
                        stale_reread.push(node.path.clone());
                        bytes_read += bytes.len();
                        if String::from_utf8_lossy(&bytes)
                            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                            .any(|w| w == symbol)
                        {
                            hits.insert(node.path.clone());
                        } else {
                            hits.remove(&node.path);
                        }
                    }
                }
            }
        }
        Ok(Retrieval {
            hits: hits.into_iter().collect(),
            bytes_read,
            stale_reread,
        })
    }

    /// Which nodes are stale against the files on disk right now.
    pub fn stale_nodes(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|n| match std::fs::read(&n.path) {
                Ok(b) => hash_bytes(&b) != n.content_hash,
                Err(_) => true,
            })
            .map(|n| n.path.clone())
            .collect()
    }
}

/// The flat baseline: read every file and scan for the symbol. Always
/// correct against the current corpus, always pays the full read.
pub fn flat_query(paths: &[PathBuf], symbol: &str) -> Result<Retrieval, Fault> {
    let mut hits = BTreeSet::new();
    let mut bytes_read = 0usize;
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| {
            Fault::new(
                format!("cannot read {} for a flat scan: {e}", path.display()),
                "check the path exists and is readable",
            )
        })?;
        bytes_read += bytes.len();
        if String::from_utf8_lossy(&bytes)
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|w| w == symbol)
        {
            hits.insert(path.display().to_string());
        }
    }
    Ok(Retrieval {
        hits: hits.into_iter().collect(),
        bytes_read,
        stale_reread: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gantry-graph-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn graph_query_reads_less_than_flat_and_agrees_when_fresh() {
        let dir = corpus("fresh");
        let a = write(
            &dir,
            "a.txt",
            "the function parse_config lives here and is large "
                .repeat(50)
                .as_str(),
        );
        let b = write(
            &dir,
            "b.txt",
            "unrelated content about widgets ".repeat(50).as_str(),
        );
        let c = write(
            &dir,
            "c.txt",
            "also mentions parse_config once ".repeat(50).as_str(),
        );
        let paths = vec![a.clone(), b, c.clone()];
        let g = Graph::build(&paths).unwrap();

        let flat = flat_query(&paths, "parse_config").unwrap();
        let graph = g.query("parse_config", false).unwrap();
        assert_eq!(graph.hits, flat.hits, "same answer when the graph is fresh");
        assert!(
            graph.bytes_read < flat.bytes_read,
            "graph {} should read less than flat {}",
            graph.bytes_read,
            flat.bytes_read
        );
    }

    #[test]
    fn a_stale_graph_can_lose_and_expiry_recovers() {
        let dir = corpus("stale");
        let a = write(
            &dir,
            "a.txt",
            "nothing interesting here yet ".repeat(20).as_str(),
        );
        let paths = vec![a.clone()];
        let g = Graph::build(&paths).unwrap();

        // The file gains a symbol after indexing; the stale graph misses it.
        std::fs::write(&a, "now it defines dynamic_symbol_xyz somewhere").unwrap();
        let stale = g.query("dynamic_symbol_xyz", false).unwrap();
        assert!(stale.hits.is_empty(), "stale graph misses the new symbol");

        let flat = flat_query(&paths, "dynamic_symbol_xyz").unwrap();
        assert_eq!(flat.hits, vec![a.display().to_string()], "flat finds it");

        // With staleness verification, the graph re-reads and recovers.
        let expired = g.query("dynamic_symbol_xyz", true).unwrap();
        assert_eq!(
            expired.hits, flat.hits,
            "expiry re-read recovers the answer"
        );
        assert!(!expired.stale_reread.is_empty(), "the re-read is recorded");
        assert!(g.stale_nodes().contains(&a.display().to_string()));
    }
}
