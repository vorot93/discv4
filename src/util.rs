use crate::PeerId;
use bigint::H256;
use k256::{ecdsa::VerifyKey, EncodedPoint};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> H256 {
    H256::from(Keccak256::digest(data).as_slice())
}

pub fn pk2id(pk: &VerifyKey) -> PeerId {
    PeerId::from_slice(&*EncodedPoint::from(pk).to_untagged_bytes().unwrap())
}
