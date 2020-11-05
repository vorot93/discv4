use crate::NodeId;
use plain_hasher::PlainHasher;
use primitive_types::H256;
use secp256k1::{Message, PublicKey};
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, hash::BuildHasherDefault};

pub type H256Map<T> = HashMap<H256, T, BuildHasherDefault<PlainHasher>>;

pub fn keccak256<T: AsRef<[u8]>>(data: T) -> H256 {
    H256::from_slice(Keccak256::digest(data.as_ref()).as_slice())
}

pub fn keccak256_message<T: AsRef<[u8]>>(data: T) -> Message {
    Message::from_slice(Keccak256::digest(data.as_ref()).as_slice()).unwrap()
}

pub fn pk2id(pk: &PublicKey) -> NodeId {
    NodeId::from_slice(&pk.serialize_uncompressed()[1..])
}
