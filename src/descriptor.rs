use crate::Result;
use helium_crypto::PublicKey;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};

#[derive(Debug, Serialize, Deserialize)]
pub struct Descriptor {
    pub nodes: IndexSet<Node>,
    pub edges: Edges,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Edges {
    pub keys: IndexSet<PublicKey>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Edge {
    source: u32,
    target: u32,
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Eq)]
pub struct Node {
    key: PublicKey,
    reason: Option<String>,
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl std::hash::Hash for Node {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.key.partial_cmp(&other.key)
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

//
// Private
//
#[derive(Debug, Deserialize)]
struct CsvRow {
    pub public_key: PublicKey,
    pub target_key: Option<PublicKey>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Eq)]
struct EdgeNode {
    source: PublicKey,
    target: PublicKey,
    reason: Option<String>,
}

impl std::hash::Hash for EdgeNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.source.hash(state);
        self.target.hash(state);
    }
}

impl PartialEq for EdgeNode {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.target == other.target
    }
}

impl PartialOrd for EdgeNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.source.partial_cmp(&other.source)
    }
}

impl Ord for EdgeNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source.cmp(&other.source)
    }
}

impl EdgeNode {
    pub fn new(source: PublicKey, target: PublicKey, reason: Option<String>) -> Self {
        Self {
            source,
            target,
            reason,
        }
    }
}

impl Descriptor {
    pub fn from_csv(path: &Path) -> Result<Self> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(File::open(path)?);
        let mut nodes = IndexSet::new();
        let mut edge_nodes: IndexSet<EdgeNode> = IndexSet::new();
        let mut edge_keys: IndexSet<PublicKey> = IndexSet::new();

        for record in rdr.deserialize() {
            let row: CsvRow = record?;
            if let Some(target_key) = row.target_key {
                // edge key order needs to be sorted to be deterministic
                // irregardless of edge direction
                let mut a = [row.public_key, target_key];
                a.sort();
                let edge = EdgeNode::new(a[0].clone(), a[1].clone(), row.reason);
                edge_keys.insert(edge.source.clone());
                edge_keys.insert(edge.target.clone());
                edge_nodes.insert(edge);
            } else {
                nodes.insert(Node {
                    key: row.public_key,
                    reason: row.reason,
                });
            }
        }

        nodes.sort_unstable();
        edge_nodes.sort_unstable();
        let edges = edge_nodes
            .into_iter()
            .map(|node| {
                let source = edge_keys.get_index_of(&node.source).unwrap() as u32;
                let target = edge_keys.get_index_of(&node.target).unwrap() as u32;
                Edge {
                    source,
                    target,
                    reason: node.reason,
                }
            })
            .collect();

        Ok(Self {
            nodes,
            edges: Edges {
                keys: edge_keys,
                edges,
            },
        })
    }
}
