use crate::PeerId;
use bigint::H256;
use secp256k1::{key::PublicKey, SECP256K1};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> H256 {
    H256::from(Keccak256::digest(data).as_slice())
}

pub fn pk2id(pk: &PublicKey) -> PeerId {
    let v = pk.serialize_vec(&SECP256K1, false);
    debug_assert!(v.len() == 65);
    PeerId::from(&v[1..])
}
