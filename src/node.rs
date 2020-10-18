use crate::{message::*, proto::*, util::*, PeerId};
use anyhow::{anyhow, bail};
use bytes::BytesMut;
use chrono::Utc;
use fixed_hash::rustc_hex::FromHexError;
use futures::SinkExt;
use k256::ecdsa::{
    recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
    signature::{DigestSigner, Signature as _},
    Signature, SigningKey,
};
use parking_lot::Mutex;
use primitive_types::H256;
use rand::{rngs::OsRng, seq::IteratorRandom};
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::{
    collections::HashMap,
    convert::TryFrom,
    io,
    iter::once,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use task_group::TaskGroup;
use thiserror::Error;
use tokio::{net::UdpSocket, stream::StreamExt, sync::mpsc::channel, time::DelayQueue};
use tokio_util::{
    codec::{Decoder, Encoder},
    udp::UdpFramed,
};
use tracing::*;
use url::{Host, Url};

pub const MAX_PACKET_SIZE: usize = 1280;
pub const TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
pub const PING_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
pub struct NodeRecord {
    pub address: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub id: PeerId,
}

#[derive(Debug, Error)]
pub enum NodeRecordParseError {
    #[error("failed to parse url")]
    InvalidUrl(#[source] anyhow::Error),
    #[error("failed to parse id")]
    InvalidId(#[source] anyhow::Error),
}

impl NodeRecord {
    /// The TCP socket address of this node
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.tcp_port)
    }

    /// The UDP socket address of this node
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.udp_port)
    }

    pub fn from_url(url: &Url) -> Result<Self, NodeRecordParseError> {
        let address = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
            Some(Host::Domain(ip)) => IpAddr::V4(
                Ipv4Addr::from_str(ip).map_err(|e| NodeRecordParseError::InvalidUrl(e.into()))?,
            ),
            other => {
                return Err(NodeRecordParseError::InvalidUrl(anyhow!(
                    "invalid host: {:?}",
                    other
                )))
            }
        };
        let port = url
            .port()
            .ok_or_else(|| NodeRecordParseError::InvalidUrl(anyhow!("no port specified")))?;
        let id = url
            .username()
            .parse()
            .map_err(|e: FromHexError| NodeRecordParseError::InvalidId(e.into()))?;

        Ok(Self {
            address,
            id,
            tcp_port: port,
            udp_port: port,
        })
    }
}

enum TimeoutRequest {
    /// Node is stale, need a ping
    Stale,
    /// Node is alive, reset timeout
    Communication,
}

enum TimeoutEvent {
    Stale,
    PingExpired,
}

pub struct Node {
    task_group: Arc<TaskGroup>,
    connected: Arc<Mutex<HashMap<PeerId, Endpoint>>>,
    outstanding_pings: Arc<Mutex<H256Set>>,
}

impl Node {
    pub async fn new(
        addr: SocketAddr,
        secret_key: SigningKey,
        bootstrap_nodes: Vec<NodeRecord>,
        public_address: IpAddr,
        tcp_port: u16,
    ) -> anyhow::Result<Self> {
        let node_endpoint = Endpoint {
            address: public_address,
            udp_port: addr.port(),
            tcp_port,
        };

        let task_group = Arc::new(TaskGroup::new());
        let id = pk2id(&secret_key.verify_key());

        // let (mut udp_tx, mut udp_rx) = futures::stream::StreamExt::split(UdpFramed::new(
        //     UdpSocket::bind(&addr).await?,
        //     DPTCodec::new(secret_key, ping_filter),
        // ));

        let (mut udp_rx, mut udp_tx) = UdpSocket::bind(&addr).await?.split();

        let (egress_requests_tx, mut egress_requests) = channel(1);

        let connected = Arc::new(Mutex::new(HashMap::new()));
        let outstanding_pings = Arc::new(Mutex::new(H256Set::default()));

        task_group.spawn_with_name("discv4 egress router", {
            let outstanding_pings = outstanding_pings.clone();
            async move {
                while let Some((message, addr)) = egress_requests.next().await {
                    let mut pinged_peer = false;
                    let mut typdata = match &message {
                        DPTCodecMessage::Ping(message) => {
                            pinged_peer = true;
                            once(1).chain(rlp::encode(message)).collect()
                        }
                        DPTCodecMessage::Pong(message) => {
                            once(2).chain(rlp::encode(message)).collect()
                        }
                        DPTCodecMessage::FindNeighbours(message) => {
                            once(3).chain(rlp::encode(message)).collect()
                        }
                        DPTCodecMessage::Neighbours(message) => {
                            once(4).chain(rlp::encode(message)).collect()
                        }
                    };

                    let signature: RecoverableSignature =
                        secret_key.sign_digest(Keccak256::new().chain(&typdata));

                    let mut hashdata = signature.as_bytes().to_vec();
                    hashdata.append(&mut typdata);

                    let hash = Keccak256::digest(&hashdata);

                    if pinged_peer {
                        outstanding_pings
                            .lock()
                            .insert(H256::from_slice(hash.as_slice()));
                    }

                    let mut datagram = vec![];
                    datagram.extend_from_slice(hash.as_slice());
                    datagram.extend_from_slice(&hashdata);

                    if let Err(e) = udp_tx.send_to(&datagram, &addr).await {
                        warn!("UDP socket send failure: {}", e);
                        return;
                    } else {
                    }
                }
            }
        });

        let (mut seen_tx, mut seen_rx) = channel(1);

        task_group.spawn_with_name("discv4 ingress router", {
            let egress_requests_tx = egress_requests_tx.clone();
            async move {
                loop {
                    let mut buf = [0_u8; MAX_PACKET_SIZE];
                    match udp_rx.recv_from(&mut buf).await {
                        Err(e) => {
                            warn!("UDP socket recv failure: {}", e);
                            break;
                        }
                        Ok((size, addr)) => {
                            if let Err(e) = async {
                                let buf = &buf[..MAX_PACKET_SIZE];

                                let min_len = 32 + 65 + 1;

                                if buf.len() < min_len {
                                    bail!("Packet too short: {} < {}", buf.len(), min_len);
                                }

                                let hash = keccak256(&buf[32..]);
                                let check_hash = H256::from_slice(&buf[0..32]);
                                if check_hash != hash {
                                    bail!(
                                        "Hash check failed: computed {}, prefix {}",
                                        hash,
                                        check_hash
                                    );
                                }

                                let rec_id = RecoveryId::new(buf[96])?;
                                let rec_sig = RecoverableSignature::new(
                                    &Signature::from_bytes(&buf[32..96])?,
                                    rec_id,
                                )?;
                                let public_key = rec_sig.recover_verify_key_from_digest(
                                    Keccak256::new().chain(&buf[97..]),
                                )?;
                                let remote_id = pk2id(&public_key);

                                let typ = buf[97];
                                let data = &buf[98..];

                                let message = match typ {
                                    1 => DPTCodecMessage::Ping(Rlp::new(data).as_val()?),
                                    2 => DPTCodecMessage::Pong(Rlp::new(data).as_val()?),
                                    3 => DPTCodecMessage::FindNeighbours(Rlp::new(data).as_val()?),
                                    4 => DPTCodecMessage::Neighbours(Rlp::new(data).as_val()?),
                                    other => bail!("Invalid message type: {}", other),
                                };

                                Ok(())

                                // match message {
                                //     Err(e) => {
                                //         warn!("Received invalid message: {}", e);
                                //     }
                                //     Ok((message, peer_id, hash)) => {
                                //         seen_tx.send(peer_id).await;
                                //         match message {
                                //             DPTCodecMessage::Ping(message) => {
                                //                 // handle ping
                                //             }
                                //             DPTCodecMessage::Pong(message) => {}
                                //             _ => todo!(),
                                //         }
                                //     }
                                // }
                            }
                            .await
                            {
                                warn!("Failed to handle message from {}: {}", addr, e);
                            }
                        }
                    }
                }
            }
        });

        task_group.spawn_with_name("discv4 timeout tracker", {
            let connected = connected.clone();
            let mut egress_requests_tx = egress_requests_tx.clone();
            async move {
                let mut pending_timeouts = DelayQueue::new();
                let mut mapping = HashMap::new();
                loop {
                    tokio::select! {
                        Some(Ok(timeoutted)) = pending_timeouts.next() => {
                            let (event, node) = timeoutted.into_inner();
                            debug!("node {} timeoutted", node);
                            mapping.remove(&node);

                            match event {
                                TimeoutEvent::Stale => {
                                    let to = connected.lock().get(&node).copied();
                                    if let Some(to) = to {
                                        let _ = egress_requests_tx.send((DPTCodecMessage::Ping(PingMessage {
                                            from: todo!(),
                                            to,
                                            expire: u64::try_from(Utc::now().timestamp()).expect("this would predate the protocol inception") + PING_TIMEOUT.as_secs()
                                        }), SocketAddr::from((to.address, to.udp_port)))).await;

                                        mapping.insert(node, pending_timeouts.insert((TimeoutEvent::Stale, node), PING_TIMEOUT));
                                    }
                                }
                                TimeoutEvent::PingExpired => {
                                    connected.lock().remove(&node);
                                }
                            }
                        }
                        Some(node) = seen_rx.next() => {
                            // Just seen node, refresh its timeout
                            if let Some(key) = mapping.remove(&node) {
                                pending_timeouts.remove(&key);
                            }

                            mapping.insert(node, pending_timeouts.insert((TimeoutEvent::Stale, node), TIMEOUT));
                        }
                        else => {
                            return;
                        }
                    }
                }
            }
        });

        Ok(Self {
            task_group,
            connected,
            outstanding_pings,
            // stream: ,
            // id,
            // connected: bootstrap_nodes.clone(),
            // incoming: bootstrap_nodes,
            // pingponged: Vec::new(),
            // bootstrapped: false,
            // timeout: None,
            // address: public_address,
            // udp_port: addr.port(),
            // tcp_port,
        })
    }

    pub fn random(&self) -> Option<NodeRecord> {
        self.connected
            .lock()
            .iter()
            .map(|(&peer, &endpoint)| (peer, endpoint))
            .choose(&mut OsRng)
            .map(
                |(
                    id,
                    Endpoint {
                        address,
                        udp_port,
                        tcp_port,
                    },
                )| NodeRecord {
                    id,
                    address,
                    udp_port,
                    tcp_port,
                },
            )
    }
}
