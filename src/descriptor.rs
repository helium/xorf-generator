use crate::{edge_order, Result};
use helium_crypto::PublicKeyBinary;
use indexmap::IndexSet;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, path::Path};

include!(concat!(env!("OUT_DIR"), "/denylist.descriptor.rs"));

#[derive(Debug, Deserialize)]
struct CsvRow {
    pub public_key: PublicKeyBinary,
    pub target_key: Option<PublicKeyBinary>,
    pub reason: Option<String>,
    pub carryover: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Eq)]
pub struct FullNode {
    pub key: PublicKeyBinary,
    pub reason: Option<String>,
    pub carryover: u32,
}

impl PartialEq for FullNode {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl std::hash::Hash for FullNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl PartialOrd for FullNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FullNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

impl From<FullNode> for Node {
    fn from(node: FullNode) -> Self {
        Self {
            key: node.key.into(),
            reason: node.reason.unwrap_or_default(),
            carryover: node.carryover,
        }
    }
}

impl From<Node> for FullNode {
    fn from(node: Node) -> Self {
        Self {
            key: node.key.into(),
            reason: Some(node.reason),
            carryover: node.carryover,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Eq)]
pub struct EdgeNode {
    source: PublicKeyBinary,
    target: PublicKeyBinary,
    reason: Option<String>,
    carryover: u32,
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
        Some(self.cmp(other))
    }
}

impl Ord for EdgeNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source.cmp(&other.source)
    }
}

impl EdgeNode {
    pub fn new(
        source: PublicKeyBinary,
        target: PublicKeyBinary,
        reason: Option<String>,
        carryover: u32,
    ) -> Self {
        Self {
            source,
            target,
            reason,
            carryover,
        }
    }
}

impl Descriptor {
    pub fn from_path(path: &Path) -> Result<Self> {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut reader = flate2::read::GzDecoder::new(File::open(path)?);
        reader.read_to_end(&mut buf)?;
        Ok(Self::decode(buf.as_ref())?)
    }

    pub fn to_path<W: std::io::Write>(&self, writer: W) -> Result<()> {
        use std::io::Write;
        let mut file = flate2::write::GzEncoder::new(writer, flate2::Compression::best());
        file.write_all(&self.encode_to_vec())?;
        Ok(())
    }

    pub fn edge_counts(&self) -> HashMap<PublicKeyBinary, i32> {
        let mut counts: HashMap<PublicKeyBinary, i32> = HashMap::new();
        for node in &self.nodes {
            let key = PublicKeyBinary::from(node.key.as_slice());
            counts.insert(key, -1); // -1 denotes all edges
        }
        if let Some(edges) = &self.edges {
            for edge in &edges.edges {
                let src = edges.keys[edge.source as usize].as_slice();
                let dst = edges.keys[edge.target as usize].as_slice();
                let source = PublicKeyBinary::from(src);
                let target = PublicKeyBinary::from(dst);
                counts
                    .entry(source)
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
                counts
                    .entry(target)
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
            }
        }
        counts
    }

    pub fn from_csv(path: &Path) -> Result<Self> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(File::open(path)?);
        let mut full_nodes: IndexSet<FullNode> = IndexSet::new();
        let mut edge_nodes: IndexSet<EdgeNode> = IndexSet::new();
        let mut edge_keys: IndexSet<PublicKeyBinary> = IndexSet::new();

        for record in rdr.deserialize() {
            let row: CsvRow = record?;
            if let Some(target_key) = row.target_key {
                // we enforce edge order here to dedupe two way edges.
                let (source, target) = edge_order(&row.public_key, &target_key);
                let edge = EdgeNode::new(
                    source.clone(),
                    target.clone(),
                    row.reason,
                    row.carryover.unwrap_or(0),
                );
                if !(full_nodes.contains(&FullNode {
                    key: edge.source.clone(),
                    reason: None,
                    carryover: row.carryover.unwrap_or(0),
                }) || full_nodes.contains(&FullNode {
                    key: edge.target.clone(),
                    reason: None,
                    carryover: row.carryover.unwrap_or(0),
                })) {
                    edge_keys.insert(edge.source.clone());
                    edge_keys.insert(edge.target.clone());
                    edge_nodes.insert(edge);
                }
            } else {
                full_nodes.insert(FullNode {
                    key: row.public_key,
                    reason: row.reason,
                    carryover: row.carryover.unwrap_or(0),
                });
            }
        }

        full_nodes.sort_unstable();
        edge_nodes.sort_unstable();
        let edges = edge_nodes
            .into_iter()
            .map(|node| {
                let source = edge_keys.get_index_of(&node.source).unwrap() as u32;
                let target = edge_keys.get_index_of(&node.target).unwrap() as u32;
                Edge {
                    source,
                    target,
                    reason: node.reason.unwrap_or_default(),
                    carryover: node.carryover,
                }
            })
            .collect();

        Ok(Self {
            nodes: full_nodes.into_iter().map(Into::into).collect(),
            edges: Some(Edges {
                keys: edge_keys.into_iter().map(Into::into).collect(),
                edges,
            }),
        })
    }

    pub fn find_node(&self, key: &PublicKeyBinary) -> Option<FullNode> {
        self.nodes
            .iter()
            .find(|node| node.key.as_slice() == key.as_ref())
            .cloned()
            .map(Into::into)
    }

    pub fn find_edges(&self, key: &PublicKeyBinary) -> Vec<EdgeNode> {
        if let Some(edges) = &self.edges {
            let key_index = edges
                .keys
                .iter()
                .position(|entry| entry.as_slice() == key.as_ref());

            if let Some(key_index) = key_index {
                let key_index = key_index as u32;
                edges
                    .edges
                    .iter()
                    .filter_map(|edge| {
                        if edge.source == key_index || edge.target == key_index {
                            let source = edges.keys[edge.source as usize].clone().into();
                            let target = edges.keys[edge.target as usize].clone().into();
                            let reason = if edge.reason.is_empty() {
                                None
                            } else {
                                Some(edge.reason.clone())
                            };
                            Some(EdgeNode::new(source, target, reason, edge.carryover))
                        } else {
                            None
                        }
                    })
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }
}
