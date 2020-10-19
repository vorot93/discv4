use crate::{message::*, util::*, PeerId};
use anyhow::anyhow;
use bytes::BytesMut;
use enum_primitive_derive::Primitive;
use k256::ecdsa::{
    recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
    signature::{DigestSigner, Signature as _},
    Signature, SigningKey,
};
use num_traits::FromPrimitive;
use parking_lot::Mutex;
use primitive_types::H256;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, io, iter::once, sync::Arc};
use tokio::sync::oneshot::Sender as OneshotSender;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Primitive)]
pub enum MessageId {
    Ping = 1,
    Pong = 2,
    FindNode = 3,
    Neighbours = 4,
}

pub enum EgressMessage {
    Ping(PingMessage),
    Pong(PongMessage),
    FindNode((FindNodeMessage, Option<OneshotSender<NeighboursMessage>>)),
    Neighbours(NeighboursMessage),
}
