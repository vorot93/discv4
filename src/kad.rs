use crate::{util::*, PeerId};
use array_init::array_init;
use parking_lot::Mutex;
use primitive_types::H256;
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

pub fn logdistance(n1: PeerId, n2: PeerId) -> H256 {
    let n1_hash = H256::from_slice(Keccak256::digest(n1.as_bytes()).as_slice());
    let n2_hash = H256::from_slice(Keccak256::digest(n2.as_bytes()).as_slice());

    n1_hash ^ n2_hash
}

#[derive(Default)]
pub struct KBucket(HashMap<PeerId, Instant>);

pub struct Table {
    kbuckets: [KBucket; 256],
}

impl Table {
    pub fn new() -> Self {
        Self {
            kbuckets: array_init(|_| Default::default()),
        }
    }
}
