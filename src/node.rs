use crate::{kad::*, message::*, proto::*, util::*, NodeId};
use anyhow::{anyhow, bail};
use chrono::Utc;
use fixed_hash::rustc_hex::FromHexError;
use futures::{future::join_all, SinkExt};
use k256::ecdsa::{
    recoverable::{Id as RecoveryId, Signature as RecoverableSignature},
    signature::{DigestSigner, Signature as _},
    Signature, SigningKey,
};
use num_traits::FromPrimitive;
use parking_lot::{Mutex, RwLock};
use primitive_types::H256;
use rand::{distributions::Standard, rngs::OsRng, Rng};
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    convert::TryFrom,
    iter::once,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use task_group::TaskGroup;
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    select,
    stream::StreamExt,
    sync::{
        mpsc::{channel, Sender},
        oneshot::{channel as oneshot, Sender as OneshotSender},
    },
    time::{delay_for, timeout},
};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};
use tracing::*;
use url::{Host, Url};

pub type RequestId = u64;

pub const MAX_PACKET_SIZE: usize = 1280;
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(15);
pub const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub const FIND_NODE_TIMEOUT: Duration = Duration::from_secs(10);
pub const QUERY_AWAIT_PING_TIME: Duration = Duration::from_secs(2);

fn expiry(timeout: Duration) -> u64 {
    u64::try_from(Utc::now().timestamp()).expect("this would predate the protocol inception")
        + timeout.as_secs()
}

fn ping_expiry() -> u64 {
    expiry(PING_TIMEOUT)
}

fn find_node_expiry() -> u64 {
    expiry(FIND_NODE_TIMEOUT)
}

pub const ALPHA: usize = 3;

#[derive(Clone, Copy, Debug)]
pub struct NodeRecord {
    pub address: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub id: NodeId,
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

pub struct Node {
    task_group: Arc<TaskGroup>,
    connected: Arc<Mutex<Table>>,

    id: NodeId,
    node_endpoint: Arc<RwLock<Endpoint>>,

    egress_requests_tx: Sender<(SocketAddr, NodeId, EgressMessage)>,
    expected_pings: Arc<Mutex<HashMap<SocketAddr, HashMap<RequestId, OneshotSender<()>>>>>,
    inflight_find_node_requests:
        Arc<Mutex<HashMap<NodeId, HashMap<RequestId, Sender<NeighboursMessage>>>>>,
}

enum PreTrigger {
    Ping(Option<OneshotSender<()>>),
    FindNode(u64, Sender<NeighboursMessage>),
}

enum PostSendTrigger {
    Ping,
}

impl Node {
    pub async fn new(
        addr: SocketAddr,
        secret_key: SigningKey,
        bootstrap_nodes: Vec<NodeRecord>,
        public_address: Option<IpAddr>,
        tcp_port: u16,
    ) -> anyhow::Result<Arc<Self>> {
        let node_endpoint = Arc::new(RwLock::new(Endpoint {
            address: public_address.unwrap_or_else(|| addr.ip()),
            udp_port: addr.port(),
            tcp_port,
        }));

        let task_group = Arc::new(TaskGroup::new());
        let id = pk2id(&secret_key.verify_key());

        debug!("Starting node with id: {}", id);

        let (mut udp_tx, mut udp_rx) = futures::stream::StreamExt::split(UdpFramed::new(
            UdpSocket::bind(&addr).await?,
            BytesCodec::new(),
        ));

        let (egress_requests_tx, mut egress_requests) = channel(1);

        let mut table = Table::new(id);
        for node in bootstrap_nodes {
            debug!("Adding bootstrap node: {:?}", node);
            table.add_verified(node);
        }

        let connected = Arc::new(Mutex::new(table));

        let inflight_find_node_requests = Arc::new(Mutex::new(HashMap::<
            NodeId,
            HashMap<RequestId, Sender<NeighboursMessage>>,
        >::default()));
        let inflight_ping_requests = Arc::new(Mutex::new(H256Map::<Vec<_>>::default()));
        let expected_pings = Arc::new(Mutex::new(HashMap::<
            SocketAddr,
            HashMap<RequestId, OneshotSender<_>>,
        >::new()));

        task_group.spawn_with_name("discv4 egress router", {
            let task_group = Arc::downgrade(&task_group);
            let connected = connected.clone();
            let inflight_find_node_requests = inflight_find_node_requests.clone();
            let inflight_ping_requests = inflight_ping_requests.clone();
            async move {
                while let Some((addr, peer, message)) = egress_requests.next().await {
                    async {
                        if peer == id {
                            return;
                        }

                        trace!("Sending datagram {:?}", message);

                        let mut pre_trigger = None;
                        let mut post_trigger = None;
                        let mut typdata = match message {
                            EgressMessage::Ping(message, sender) => {
                                pre_trigger = Some(PreTrigger::Ping(sender));
                                post_trigger = Some(PostSendTrigger::Ping);
                                once(1).chain(rlp::encode(&message)).collect()
                            }
                            EgressMessage::Pong(message) => {
                                once(2).chain(rlp::encode(&message)).collect()
                            }
                            EgressMessage::FindNode(message, id, sender) => {
                                pre_trigger = Some(PreTrigger::FindNode(id, sender));
                                once(3).chain(rlp::encode(&message)).collect()
                            }
                            EgressMessage::Neighbours(message) => {
                                once(4).chain(rlp::encode(&message)).collect()
                            }
                        };

                        let signature: RecoverableSignature =
                            secret_key.sign_digest(Keccak256::new().chain(&typdata));

                        let mut hashdata = signature.as_bytes().to_vec();
                        hashdata.append(&mut typdata);

                        let hash = keccak256(&hashdata);

                        let mut datagram = Vec::with_capacity(MAX_PACKET_SIZE);
                        datagram.extend_from_slice(hash.as_bytes());
                        datagram.extend_from_slice(&hashdata);

                        let mut do_send = false;
                        match pre_trigger {
                            Some(PreTrigger::Ping(sender)) => {
                                let mut inflight_ping_requests = inflight_ping_requests.lock();
                                let cbs = inflight_ping_requests.entry(hash).or_insert_with(|| {
                                    do_send = true;
                                    Vec::new()
                                });
                                if let Some(sender) = sender {
                                    cbs.push(sender);
                                }
                            }
                            Some(PreTrigger::FindNode(id, sender)) => {
                                assert!(inflight_find_node_requests
                                    .lock()
                                    .entry(peer)
                                    .or_default()
                                    .insert(id, sender)
                                    .is_none());
                                do_send = true;
                            }
                            None => {
                                do_send = true;
                            }
                        }

                        if !do_send {
                            return;
                        }

                        if let Err(e) = udp_tx.send((datagram.clone().into(), addr)).await {
                            warn!("UDP socket send failure: {}", e);
                            return;
                        } else if let Some(trigger) = post_trigger {
                            match trigger {
                                PostSendTrigger::Ping => {
                                    if let Some(task_group) = task_group.upgrade() {
                                        task_group.spawn({
                                            let connected = connected.clone();
                                            let inflight_ping_requests =
                                                inflight_ping_requests.clone();
                                            async move {
                                                delay_for(PING_TIMEOUT).await;
                                                let mut connected = connected.lock();
                                                let mut inflight_ping_requests =
                                                    inflight_ping_requests.lock();
                                                if inflight_ping_requests.remove(&hash).is_some() {
                                                    connected.remove(peer);
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                    .instrument(span!(
                        Level::TRACE,
                        "OUT",
                        "addr={},node={}",
                        addr,
                        &*peer.to_string(),
                    ))
                    .await;
                }
            }
        });

        task_group.spawn_with_name("discv4 ingress router", {
            let mut egress_requests_tx = egress_requests_tx.clone();
            let connected = connected.clone();
            let node_endpoint = node_endpoint.clone();
            let expected_pings = expected_pings.clone();
            let inflight_find_node_requests = inflight_find_node_requests.clone();
            async move {
                while let Some(res) = udp_rx.next().await {
                    match res {
                        Err(e) => {
                            warn!("UDP socket recv failure: {}", e);
                            break;
                        }
                        Ok((buf, addr)) => {
                            if let Err(e) = async {
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

                                if remote_id == id {
                                    return Ok(());
                                }

                                let typ = buf[97];
                                let data = &buf[98..];

                                match MessageId::from_u8(typ) {
                                    Some(MessageId::Ping) => {
                                        let ping_data = Rlp::new(data).as_val::<PingMessage>()?;

                                        trace!("PING");

                                        connected.lock().add_verified(NodeRecord {
                                            address: ping_data.from.address,
                                            udp_port: ping_data.from.udp_port,
                                            tcp_port: ping_data.from.udp_port,
                                            id: remote_id,
                                        });

                                        let _ = egress_requests_tx
                                            .send((
                                                addr,
                                                remote_id,
                                                EgressMessage::Pong(PongMessage {
                                                    to: ping_data.from,
                                                    echo: hash,
                                                    expire: ping_data.expire,
                                                }),
                                            ))
                                            .await;

                                        if let Some(cbs) = expected_pings.lock().remove(&addr) {
                                            for (_, cb) in cbs {
                                                let _ = cb.send(());
                                            }
                                        }
                                    }
                                    Some(MessageId::Pong) => {
                                        let message = Rlp::new(data).as_val::<PongMessage>()?;

                                        // Did we actually ask for this? Ignore message if not.
                                        if let Some(cbs) =
                                            inflight_ping_requests.lock().remove(&message.echo)
                                        {
                                            trace!("PONG - our endpoint is: {:?}", message.to);
                                            {
                                                let mut node_endpoint = node_endpoint.write();
                                                node_endpoint.address = message.to.address;
                                                node_endpoint.udp_port = message.to.udp_port;
                                            }
                                            for cb in cbs {
                                                let _ = cb.send(());
                                            }
                                        } else {
                                            warn!("PONG (ignore)")
                                        }
                                    }
                                    Some(MessageId::FindNode) => {
                                        let message = Rlp::new(data).as_val::<FindNodeMessage>()?;

                                        let mut neighbours = None;
                                        {
                                            let connected = connected.lock();

                                            // Only send to nodes that have been proofed.
                                            if connected.get(remote_id).is_some() {
                                                trace!("FINDNODE");
                                                neighbours =
                                                    connected.neighbours(remote_id).map(Box::new);
                                            } else {
                                                warn!("FINDNODE (ignore)");
                                            }
                                        }

                                        if let Some(nodes) = neighbours {
                                            let _ = egress_requests_tx
                                                .send((
                                                    addr,
                                                    remote_id,
                                                    EgressMessage::Neighbours(NeighboursMessage {
                                                        nodes,
                                                        expire: message.expire,
                                                    }),
                                                ))
                                                .await;
                                        }
                                    }
                                    Some(MessageId::Neighbours) => {
                                        // Did we actually ask for this? Ignore message if not.
                                        let cbs = inflight_find_node_requests
                                            .lock()
                                            .get(&remote_id)
                                            .map(|cbs| cbs.values().cloned().collect::<Vec<_>>());
                                        if let Some(cbs) = cbs {
                                            trace!("NEIGHBOURS");

                                            // OK, so we did ask, let's handle the message.
                                            let message =
                                                Rlp::new(data).as_val::<NeighboursMessage>()?;
                                            {
                                                let mut connected = connected.lock();

                                                for peer in message.nodes.iter() {
                                                    connected.add_seen(*peer);
                                                }
                                            }

                                            for mut cb in cbs {
                                                let _ = cb.send(message.clone()).await;
                                            }
                                        } else {
                                            trace!("NEIGHBOURS (ignore)")
                                        }
                                    }
                                    None => bail!("Invalid message type: {}", typ),
                                };

                                Ok(())
                            }
                            .instrument(span!(Level::TRACE, "IN", "addr={}", &*addr.to_string()))
                            .await
                            {
                                warn!("Failed to handle message from {}: {}", addr, e);
                            }
                        }
                    }
                }
            }
        });

        let this = Arc::new(Self {
            task_group,
            connected,
            id,
            node_endpoint,
            egress_requests_tx,
            expected_pings,
            inflight_find_node_requests,
        });

        this.task_group.spawn_with_name("discv4 refresher", {
            let this = Arc::downgrade(&this);
            async move {
                while let Some(this) = this.upgrade() {
                    delay_for(REFRESH_TIMEOUT / 4).await;

                    this.lookup(this.id).await;
                    drop(this);

                    delay_for(3 * REFRESH_TIMEOUT / 4).await;
                }
            }
        });

        for bucket_no in 0..ADDRESS_BITS {
            this.task_group.spawn_with_name(
                format!("discv4 oldest node pinger - bucket #{}", bucket_no),
                {
                    let connected = this.connected.clone();
                    let mut egress_requests_tx = this.egress_requests_tx.clone();
                    let node_endpoint = this.node_endpoint.clone();
                    async move {
                        loop {
                            let oldest = connected.lock().oldest(bucket_no as u8);

                            let (tx, rx) = oneshot();
                            if let Some(node) = oldest {
                                let from = *node_endpoint.read();
                                if egress_requests_tx
                                    .send((
                                        node.udp_addr(),
                                        id,
                                        EgressMessage::Ping(
                                            PingMessage {
                                                from,
                                                to: node.into(),
                                                expire: ping_expiry(),
                                            },
                                            Some(tx),
                                        ),
                                    ))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }

                                let _ = rx.await;
                            }

                            delay_for(Duration::from_secs_f32(
                                BUCKET_REFRESH_INTERVAL.as_secs_f32()
                                    * OsRng.sample::<f32, _>(Standard),
                            ))
                            .await;
                        }
                    }
                },
            );
        }

        Ok(this)
    }

    #[instrument(skip(self, target), fields(target=&*target.to_string()))]
    pub async fn lookup(&self, target: NodeId) -> Vec<NodeRecord> {
        #[derive(Clone, Copy)]
        struct QueryNode {
            record: NodeRecord,
            queried: bool,
        }

        let node_endpoint = *self.node_endpoint.read();
        let egress_requests_tx = self.egress_requests_tx.clone();

        // Get all nodes from local table sorted by distance
        let mut nearest_nodes = self
            .connected
            .lock()
            .nearest_node_entries(target)
            .into_iter()
            .map(|(distance, record)| {
                (
                    distance,
                    QueryNode {
                        record,
                        queried: false,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut lookup_round = 0_usize;
        loop {
            // For each node of ALPHA closest and not queried yet...
            // TODO: mark queried nodes as such
            let picked_nodes = nearest_nodes
                .iter_mut()
                .take(ALPHA)
                .filter_map(|(_, node)| if !node.queried { Some(node) } else { None })
                .collect::<Vec<_>>();

            if picked_nodes.is_empty() {
                debug!("No picked nodes, ending lookup");
                break;
            }

            let fut = picked_nodes.into_iter().map(|node| {
                // ...send find node request...
                node.queried = true;
                let node = *node;
                let mut egress_requests_tx = egress_requests_tx.clone();
                let expected_pings = self.expected_pings.clone();
                let inflight_find_node_requests = self.inflight_find_node_requests.clone();
                let expected_ping_id = rand::random();
                async move {
                    let addr = SocketAddr::new(node.record.address, node.record.udp_port);

                    let res = timeout(FIND_NODE_TIMEOUT, async {
                        let (expected_ping_tx, expected_ping_rx) = oneshot();
                        expected_pings
                            .lock()
                            .entry(addr)
                            .or_default()
                            .insert(expected_ping_id, expected_ping_tx);

                        // Make sure our endpoint is proven.
                        let (tx, rx) = oneshot();
                        egress_requests_tx
                            .send((
                                addr,
                                node.record.id,
                                EgressMessage::Ping(
                                    PingMessage {
                                        from: node_endpoint,
                                        to: node.record.into(),
                                        expire: ping_expiry(),
                                    },
                                    Some(tx),
                                ),
                            ))
                            .await
                            .map_err(|_| anyhow!("Sender shutdown"))?;
                        // ...and await for Pong response
                        rx.await.map_err(|_| anyhow!("Pong timeout"))?;

                        trace!("Our endpoint is proven");

                        // In case the node wants to ping us, give it an opportunity to do so
                        let _ = timeout(QUERY_AWAIT_PING_TIME, expected_ping_rx).await;

                        // TODO: insert into inflight_find_node_requests here
                        // TODO: guarantee execution even if through lookup future drop (otherwise dangling find node request possible)
                        let find_node_id = rand::random();
                        let (tx, mut rx) = channel(1);
                        egress_requests_tx
                            .send((
                                addr,
                                node.record.id,
                                EgressMessage::FindNode(
                                    FindNodeMessage {
                                        id: target,
                                        expire: find_node_expiry(),
                                    },
                                    find_node_id,
                                    tx,
                                ),
                            ))
                            .await
                            .map_err(|_| anyhow!("Sender shutdown"))?;

                        debug!("Awaiting neighbours");

                        // ...and await for Neighbours response
                        let mut received_neighbours = Vec::new();
                        loop {
                            let timeout = delay_for(Duration::from_secs(2));
                            select! {
                                neighbours = rx.recv() => {
                                    received_neighbours.push(neighbours.expect("we drop the sending channel, not the ingress router"));
                                }
                                _ = timeout => {
                                    break;
                                }
                            }
                        }
                        {
                            let mut inflight_find_node_requests = inflight_find_node_requests.lock();
                            let entry = inflight_find_node_requests.entry(node.record.id);
                            if let hash_map::Entry::Occupied(mut entry) = entry {
                                entry.get_mut().remove(&find_node_id);
                                if entry.get().is_empty() {
                                    entry.remove();
                                }
                            }
                        }
                        if received_neighbours.is_empty() {
                            bail!("No neigbours received");
                        }

                        debug!("Received neighbours");

                        Ok::<_, anyhow::Error>(received_neighbours)
                    })
                    .await;

                    if let hash_map::Entry::Occupied(mut entry) = expected_pings.lock().entry(addr)
                    {
                        entry.get_mut().remove(&expected_ping_id);
                        if entry.get().is_empty() {
                            entry.remove();
                        }
                    }

                    match res {
                        Ok(Ok(v)) => {
                            return Some(v);
                        }
                        Ok(Err(e)) => {
                            debug!("Query error: {}", e);
                        }
                        Err(_) => {
                            debug!("Query timeout");
                        }
                    }

                    None
                }
                .instrument(span!(
                    Level::DEBUG,
                    "query",
                    "#{},node={}",
                    lookup_round,
                    node.record.id
                ))
            });

            for message in join_all(fut).await {
                if let Some(messages) = message {
                    for message in messages {
                        // If we have a node...
                        for record in message.nodes.into_iter() {
                            // ...and it's not been seen yet...
                            if let btree_map::Entry::Vacant(vacant) =
                                nearest_nodes.entry(distance(target, record.id))
                            {
                                // ...add to the set and continue the query
                                vacant.insert(QueryNode {
                                    record,
                                    queried: false,
                                });
                            }
                        }
                    }
                }
            }

            lookup_round += 1;
        }

        nearest_nodes
            .into_iter()
            .map(|(_, node)| node.record)
            .collect()
    }

    pub fn num_nodes(&self) -> usize {
        self.connected.lock().len()
    }
}
