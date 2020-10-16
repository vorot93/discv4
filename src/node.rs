use crate::{message::*, proto::*, util::*, PeerId};
use anyhow::anyhow;
use chrono::Utc;
use fixed_hash::rustc_hex::FromHexError;
use futures::SinkExt;
use k256::ecdsa::SigningKey;
use parking_lot::Mutex;
use rand::{rngs::OsRng, seq::IteratorRandom};
use std::{
    collections::HashMap,
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use task_group::TaskGroup;
use thiserror::Error;
use tokio::{net::UdpSocket, stream::StreamExt, sync::mpsc::channel, time::DelayQueue};
use tokio_util::udp::UdpFramed;
use tracing::*;
use url::{Host, Url};

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

#[derive(Default)]
struct Inner {
    connected: HashMap<PeerId, Endpoint>,
}

pub struct Node {
    task_group: Arc<TaskGroup>,
    inner: Arc<Mutex<Inner>>,
}

impl Node {
    pub async fn new(
        addr: SocketAddr,
        secret_key: SigningKey,
        bootstrap_nodes: Vec<NodeRecord>,
        public_address: IpAddr,
        tcp_port: u16,
    ) -> anyhow::Result<Self> {
        let task_group = Arc::new(TaskGroup::new());
        let id = pk2id(&secret_key.verify_key());

        let ping_filter = Arc::new(Mutex::new(H256Set::default()));

        let (mut udp_tx, mut udp_rx) = futures::stream::StreamExt::split(UdpFramed::new(
            UdpSocket::bind(&addr).await?,
            DPTCodec::new(secret_key, ping_filter),
        ));

        let (egress_requests_tx, mut egress_requests) = channel(1);

        let inner = Arc::new(Mutex::new(Inner::default()));

        task_group.spawn_with_name("discv4 egress router", {
            async move {
                while let Some((message, addr)) = egress_requests.next().await {
                    if let Err(e) = udp_tx.send((message, addr)).await {
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
                while let Some(res) = udp_rx.next().await {
                    match res {
                        Err(e) => {
                            warn!("UDP socket recv failure: {}", e);
                            break;
                        }
                        Ok((message, addr)) => {
                            match message {
                                Err(e) => {
                                    warn!("Received invalid message: {}", e);
                                }
                                Ok((message, peer_id, hash)) => {
                                    seen_tx.send(peer_id).await;
                                    match message {
                                        DPTCodecMessage::Ping(message) => {
                                            // handle ping
                                        }
                                        DPTCodecMessage::Pong(message) => {}
                                        _ => todo!(),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        task_group.spawn_with_name("discv4 timeout tracker", {
            let inner = inner.clone();
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
                                    let to = inner.lock().connected.get(&node).copied();
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
                                    inner.lock().connected.remove(&node);
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
            inner,
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
        self.inner
            .lock()
            .connected
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
