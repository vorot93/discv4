use crate::PeerId;
use k256::{ecdsa::VerifyKey, EncodedPoint};
use plain_hasher::PlainHasher;
use primitive_types::H256;
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasherDefault,
};

pub type H256Map<T> = HashMap<H256, T, BuildHasherDefault<PlainHasher>>;
pub type H256Set = HashSet<H256, BuildHasherDefault<PlainHasher>>;

pub fn keccak256<T: AsRef<[u8]>>(data: T) -> H256 {
    H256::from(Keccak256::digest(data.as_ref()).as_ref())
}

pub fn pk2id(pk: &VerifyKey) -> PeerId {
    PeerId::from_slice(&*EncodedPoint::from(pk).to_untagged_bytes().unwrap())
}
