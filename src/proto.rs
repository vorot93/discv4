use crate::{
    util::{keccak256, pk2id},
    PeerId,
};
use bytes::BytesMut;
use k256::ecdsa::{
    recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
    signature::{DigestSigner, Signature as _},
    Signature, SigningKey,
};
use primitive_types::H256;
use sha3::{Digest, Keccak256};
use std::io;
use tokio::codec::{Decoder, Encoder};

macro_rules! try_none {
    ( $ex:expr ) => {
        match $ex {
            Ok(val) => val,
            Err(_) => return Ok(Some(None)),
        }
    };
}

pub struct DPTCodec {
    secret_key: SigningKey,
}

pub struct DPTCodecMessage {
    pub typ: u8,
    pub data: Vec<u8>,
}

impl DPTCodec {
    pub const fn new(secret_key: SigningKey) -> Self {
        Self { secret_key }
    }
}

impl Decoder for DPTCodec {
    type Item = Option<(DPTCodecMessage, PeerId, H256)>;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() < 98 {
            return Ok(None);
        }

        let hash = keccak256(&buf[32..]);
        let check_hash = H256::from_slice(&buf[0..32]);
        if check_hash != hash {
            return Ok(Some(None));
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

        Ok(Some(Some((DPTCodecMessage { typ, data }, remote_id, hash))))
    }
}

impl Encoder for DPTCodec {
    type Item = DPTCodecMessage;
    type Error = io::Error;

    fn encode(&mut self, mut msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let mut typdata = Vec::new();
        typdata.push(msg.typ);
        typdata.append(&mut msg.data);

        let signature: RecoverableSignature = self
            .secret_key
            .sign_digest(Keccak256::new().chain(&typdata));

        let mut hashdata = signature.as_bytes().to_vec();
        hashdata.append(&mut typdata);

        buf.extend_from_slice(Keccak256::digest(&hashdata).as_slice());
        buf.extend_from_slice(&hashdata);

        Ok(())
    }
}
