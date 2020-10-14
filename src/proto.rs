use crate::{
    util::{keccak256, pk2id},
    PeerId,
};
use k256::ecdsa::{
    recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
    signature::{DigestSigner, Signature as _},
    Signature, SigningKey,
};
use primitive_types::H256;
use sha3::{Digest, Keccak256};
use std::{io, net::SocketAddr};
use tokio_core::net::UdpCodec;

macro_rules! try_none {
    ( $ex:expr ) => {
        match $ex {
            Ok(val) => val,
            Err(_) => return Ok(None),
        }
    };
}

pub struct DPTCodec {
    secret_key: SigningKey,
}

pub struct DPTCodecMessage {
    pub addr: SocketAddr,
    pub typ: u8,
    pub data: Vec<u8>,
}

impl DPTCodec {
    pub const fn new(secret_key: SigningKey) -> Self {
        Self { secret_key }
    }
}

impl UdpCodec for DPTCodec {
    type In = Option<(DPTCodecMessage, PeerId, H256)>;
    type Out = DPTCodecMessage;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> Result<Self::In, io::Error> {
        if buf.len() < 98 {
            return Ok(None);
        }

        let hash = keccak256(&buf[32..]);
        let check_hash = H256::from_slice(&buf[0..32]);
        if check_hash != hash {
            return Ok(None);
        }

        let rec_id = try_none!(RecoveryId::new(buf[96]));
        let rec_sig = try_none!(RecoverableSignature::new(
            &try_none!(Signature::from_bytes(&buf[32..96])),
            rec_id
        ));
        let public_key =
            try_none!(rec_sig.recover_verify_key_from_digest(Keccak256::new().chain(&buf[97..])));
        let remote_id = pk2id(&public_key);

        let typ = buf[97];
        let mut data = Vec::new();
        for item in buf.iter().skip(98) {
            data.push(*item);
        }

        Ok(Some((
            DPTCodecMessage {
                addr: *src,
                typ,
                data,
            },
            remote_id,
            hash,
        )))
    }

    fn encode(&mut self, mut msg: DPTCodecMessage, buf: &mut Vec<u8>) -> SocketAddr {
        let mut typdata = Vec::new();
        typdata.push(msg.typ);
        typdata.append(&mut msg.data);

        let signature: RecoverableSignature = self
            .secret_key
            .sign_digest(Keccak256::new().chain(&typdata));

        let mut hashdata = signature.as_bytes().to_vec();
        hashdata.append(&mut typdata);

        buf.extend_from_slice(Keccak256::digest(&hashdata).as_slice());
        buf.append(&mut hashdata);

        msg.addr
    }
}
