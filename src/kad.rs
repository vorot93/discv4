use crate::{message::*, util::*, NodeRecord, PeerId};
use array_init::array_init;
use arrayvec::ArrayVec;
use primitive_types::H256;
use std::collections::{BTreeMap, VecDeque};

pub const BUCKET_SIZE: usize = 16;
pub const REPLACEMENTS_SIZE: usize = 16;
pub const ADDRESS_BYTES_SIZE: usize = 256;

pub fn distance(n1: PeerId, n2: PeerId) -> H256 {
    keccak256(n1) ^ keccak256(n2)
}

pub type NodeBucket = ArrayVec<[NodeRecord; BUCKET_SIZE]>;

#[derive(Default)]
pub struct KBucket {
    bucket: VecDeque<NodeRecord>,
    replacements: VecDeque<NodeRecord>,
}

impl KBucket {
    pub fn find_peer_pos(&self, peer: PeerId) -> Option<usize> {
        for i in 0..self.bucket.len() {
            if self.bucket[i].id == peer {
                return Some(i);
            }
        }

        None
    }

    pub fn push_replacement(&mut self, peer: NodeRecord) {
        if self.replacements.len() < REPLACEMENTS_SIZE {
            self.replacements.push_back(peer)
        }
    }
}

pub struct Table {
    id_hash: H256,
    kbuckets: [KBucket; ADDRESS_BYTES_SIZE],
}

impl Table {
    pub fn new(id: PeerId) -> Self {
        Self {
            id_hash: keccak256(id),
            kbuckets: array_init(|_| Default::default()),
        }
    }

    fn logdistance(&self, peer: PeerId) -> Option<usize> {
        let remote_hash = keccak256(peer);
        for i in (0..ADDRESS_BYTES_SIZE).rev() {
            let byte_index = ADDRESS_BYTES_SIZE - i - 1;
            let d = self.id_hash[byte_index] ^ remote_hash[byte_index];
            if d != 0 {
                let high_bit_index = 7 - d.leading_zeros() as usize;
                return Some(i * 8 + high_bit_index);
            }
        }
        None // n1 and n2 are equal, so logdistance is -inf
    }

    fn bucket(&self, peer: PeerId) -> Option<&KBucket> {
        if let Some(distance) = self.logdistance(peer) {
            return Some(&self.kbuckets[distance]);
        }

        None
    }

    fn bucket_mut(&mut self, peer: PeerId) -> Option<&mut KBucket> {
        if let Some(distance) = self.logdistance(peer) {
            return Some(&mut self.kbuckets[distance]);
        }

        None
    }

    pub fn get(&self, peer: PeerId) -> Option<Endpoint> {
        if let Some(bucket) = self.bucket(peer) {
            for entry in &bucket.bucket {
                if entry.id == peer {
                    return Some((*entry).into());
                }
            }
        }

        None
    }

    /// Add verified peer if there is space.
    pub fn add_verified(&mut self, peer: NodeRecord) {
        if let Some(bucket) = self.bucket_mut(peer.id) {
            if let Some(pos) = bucket.find_peer_pos(peer.id) {
                bucket.bucket.remove(pos);
            }

            // Push to front of bucket if we have less than BUCKET_SIZE peers, or we are shuffling existing peer...
            if bucket.bucket.len() < BUCKET_SIZE {
                bucket.bucket.push_front(peer);
            } else {
                // ...add to replacements otherwise
                bucket.push_replacement(peer);
            }
        }
    }

    /// Add seen peer if there is space.
    pub fn add_seen(&mut self, peer: NodeRecord) {
        if let Some(bucket) = self.bucket_mut(peer.id) {
            if bucket.find_peer_pos(peer.id).is_some() {
                // Peer exists already, do nothing
                return;
            }

            // Push to back of bucket if we have less than BUCKET_SIZE peers...
            if bucket.bucket.len() < BUCKET_SIZE {
                bucket.bucket.push_back(peer);
            } else {
                // ...add to replacements otherwise
                bucket.push_replacement(peer);
            }
        }
    }

    /// Remove node from the bucket
    pub fn remove(&mut self, peer: PeerId) -> bool {
        if let Some(bucket) = self.bucket_mut(peer) {
            for i in 0..bucket.bucket.len() {
                if bucket.bucket[i].id == peer {
                    bucket.bucket.remove(i);
                    if let Some(node) = bucket.replacements.pop_front() {
                        bucket.bucket.push_back(node);
                    }

                    return true;
                }
            }
        }

        false
    }

    pub fn neighbours(&self, peer: PeerId) -> Option<NodeBucket> {
        self.bucket(peer).map(|bucket| {
            bucket
                .bucket
                .iter()
                .filter_map(|neighbour| {
                    if peer == neighbour.id {
                        None
                    } else {
                        Some(*neighbour)
                    }
                })
                .collect()
        })
    }

    pub fn nearest_node_entries(&self, target: PeerId) -> BTreeMap<H256, NodeRecord> {
        self.kbuckets
            .iter()
            .map(|bucket| &bucket.bucket)
            .flatten()
            .map(|n| (distance(n.id, target), *n))
            .collect()
    }
}
