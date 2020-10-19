use crate::{message::*, util::*, PeerId};
use array_init::array_init;
use arrayvec::ArrayVec;
use parking_lot::Mutex;
use primitive_types::H256;
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};

pub const BUCKET_SIZE: usize = 16;
pub const ADDRESS_BYTES_SIZE: usize = 256;

pub type KBucket = VecDeque<Neighbour>;

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
            for entry in bucket {
                if entry.id == peer {
                    return Some((*entry).into());
                }
            }
        }

        None
    }

    pub fn push(&mut self, peer: Neighbour) -> bool {
        if let Some(bucket) = self.bucket_mut(peer.id) {
            if bucket.len() >= BUCKET_SIZE {
                return false;
            }

            for entry in &*bucket {
                if entry.id == peer.id {
                    return false;
                }
            }

            bucket.push_front(peer);
            return true;
        }

        false
    }

    pub fn remove(&mut self, peer: PeerId) -> bool {
        if let Some(bucket) = self.bucket_mut(peer) {
            for i in 0..bucket.len() {
                if bucket[i].id == peer {
                    bucket.remove(i);
                    return true;
                }
            }
        }

        false
    }

    pub fn neighbours(&self, peer: PeerId) -> Option<ArrayVec<[Neighbour; BUCKET_SIZE]>> {
        self.bucket(peer).map(|bucket| {
            bucket
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

    pub fn nearest_node_entries(&self, target: PeerId) -> Vec<Neighbour> {
        let mut out = self
            .kbuckets
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();

        out.sort_unstable_by_key(|n| n.id);

        out
    }
}
