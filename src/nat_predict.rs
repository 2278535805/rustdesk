use std::{
    net::{IpAddr, SocketAddr},
    ops::RangeInclusive,
    sync::Arc,
    time::Duration,
};

use hbb_common::{
    anyhow::bail,
    bytes::BytesMut,
    config::{option2bool, Config},
    futures::{
        future::{select_all, BoxFuture},
        FutureExt,
    },
    log,
    tokio::{
        self,
        net::UdpSocket,
        time::{sleep_until, Instant},
    },
    ResultType,
};

use base::config::keys;

use crate::common::{punch_packet, punch_tid, PUNCH_ACK, PUNCH_PROBE};

/// How far past the peer's last sampled port the probe window reaches. Covers
/// the allocations between the peer's sampling and its probes toward us.
pub const WINDOW: u16 = 256;
/// A step larger than this between two samples means the NAT does not allocate
/// sequentially, so prediction is abandoned and relay is used.
pub const MAX_STEP: u16 = 64;
/// Hard cap on probe packets per punch, bounding traffic and NAT mapping state.
pub const MAX_PACKETS: u32 = 2000;
/// Gap between probe packets (~250 pps).
pub const SEND_INTERVAL_MS: u64 = 4;
/// How long a predictive punch may run.
pub const TIMEOUT_MS: u64 = 5000;
/// Local sockets a predictive punch uses. More sockets mean more source ports
/// (which helps against address-and-port-dependent filtering) at the cost of
/// more NAT mappings and packets.
pub const SOCKETS: usize = 2;

pub fn enabled() -> bool {
    option2bool(
        keys::OPTION_ENABLE_NAT_PREDICTION,
        &Config::get_option(keys::OPTION_ENABLE_NAT_PREDICTION),
    )
}

/// The sockets and window a controller's predictive punch runs with.
pub struct PredictCtx {
    pub sockets: Vec<Arc<UdpSocket>>,
    pub peer_ip: IpAddr,
    pub window: RangeInclusive<u16>,
}

/// The external port window to probe on the peer, from its samples in allocation
/// order. `None` when the samples say the NAT is not predictable.
pub fn predict_port_window(samples: &[i32]) -> Option<RangeInclusive<u16>> {
    let mut ports: Vec<u16> = samples
        .iter()
        .filter_map(|p| u16::try_from(*p).ok())
        .filter(|p| *p > 0)
        .collect();
    if ports.is_empty() {
        return None;
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.len() >= 2 {
        let max_step = ports.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0);
        if max_step == 0 || max_step > MAX_STEP {
            return None;
        }
    }
    let base = *ports.last()?;
    let end = base.checked_add(WINDOW)?;
    Some(base..=end)
}

/// One `TestNatRequest` on `socket`, returning the external port the rendezvous
/// server observed for it. The socket's mapping to the server is what the
/// prediction is anchored on.
pub async fn sample_udp_port(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    timeout_ms: u64,
) -> Option<u16> {
    use hbb_common::{
        protobuf::Message as _,
        rendezvous_proto::{rendezvous_message, RendezvousMessage, TestNatRequest},
    };

    let mut msg_out = RendezvousMessage::new();
    msg_out.set_test_nat_request(TestNatRequest::default());
    let data = msg_out.write_to_bytes().ok()?;
    socket.send_to(&data, server_addr).await.ok()?;
    let mut buf = [0u8; 1500];
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let (n, _) = hbb_common::timeout(left.as_millis() as u64, socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&buf[..n]) {
            if let Some(rendezvous_message::Union::TestNatResponse(res)) = msg_in.union {
                return u16::try_from(res.port).ok().filter(|p| *p > 0);
            }
        }
    }
}

/// Probe the peer's predicted port window from every socket, birthday-style:
/// our probes create our own mappings, the peer's probes create its, and one
/// probe that gets acknowledged proves a path that carries traffic both ways.
///
/// Returns the socket that carried the confirmed flow, the peer's external
/// address on it, and (for a listener) the first non-punch packet, which is the
/// peer's KCP SYN.
pub async fn punch_udp_predictive(
    sockets: Vec<Arc<UdpSocket>>,
    peer_ip: IpAddr,
    window: RangeInclusive<u16>,
    listen: bool,
) -> ResultType<Option<(Arc<UdpSocket>, SocketAddr, Option<BytesMut>)>> {
    if sockets.is_empty() {
        bail!("no sockets for predictive punch");
    }
    let ports: Vec<u16> = window.collect();
    if ports.is_empty() {
        bail!("empty prediction window");
    }
    let tid = ((hbb_common::time_based_rand() as u64) << 32) | hbb_common::time_based_rand() as u64;
    let start = Instant::now();
    let deadline = start + Duration::from_millis(TIMEOUT_MS);
    // The NAT test's replies may still be queued (e.g. on the controller's
    // punch socket); a non-punch packet would otherwise be taken for KCP data.
    let mut stale = [0u8; 1500];
    for socket in &sockets {
        while socket.try_recv_from(&mut stale).is_ok() {}
    }
    let mut next_send = start;
    let mut next_port = 0usize;
    let mut next_socket = 0usize;
    let mut probes_sent = 0u32;
    let mut confirmed = false;
    loop {
        let send_at = std::cmp::max(next_send, Instant::now());
        let recv_futs: Vec<BoxFuture<'static, std::io::Result<(Vec<u8>, SocketAddr)>>> = sockets
            .iter()
            .map(|socket| {
                let socket = socket.clone();
                async move {
                    let mut buf = vec![0u8; 1500];
                    let res = socket.recv_from(&mut buf).await;
                    res.map(|(n, src)| {
                        buf.truncate(n);
                        (buf, src)
                    })
                }
                .boxed()
            })
            .collect();
        tokio::select! {
            _ = sleep_until(send_at) => {
                if probes_sent < MAX_PACKETS {
                    let port = ports[next_port];
                    next_port = (next_port + 1) % ports.len();
                    let socket = &sockets[next_socket % sockets.len()];
                    next_socket = next_socket.wrapping_add(1);
                    let probe = punch_packet(&PUNCH_PROBE, tid);
                    socket.send_to(&probe, SocketAddr::new(peer_ip, port)).await.ok();
                    probes_sent += 1;
                }
                next_send = Instant::now() + Duration::from_millis(SEND_INTERVAL_MS);
            }
            (res, idx, _rest) = select_all(recv_futs) => {
                let (buf, src) = match res {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(peer_tid) = punch_tid(&buf, &PUNCH_PROBE) {
                    let ack = punch_packet(&PUNCH_ACK, peer_tid);
                    sockets[idx].send_to(&ack, src).await.ok();
                } else if punch_tid(&buf, &PUNCH_ACK) == Some(tid) {
                    if !listen {
                        log::debug!(
                            "predictive punch confirmed in {:?}, {probes_sent} probes sent",
                            start.elapsed()
                        );
                        return Ok(Some((sockets[idx].clone(), src, None)));
                    }
                    confirmed = true;
                } else if !buf.is_empty() {
                    // The peer is already speaking KCP: the path is proven.
                    log::debug!(
                        "predictive punch confirmed by {} bytes in {:?}, {probes_sent} probes sent, acked: {confirmed}",
                        buf.len(),
                        start.elapsed()
                    );
                    return Ok(Some((
                        sockets[idx].clone(),
                        src,
                        if listen { Some(BytesMut::from(&buf[..])) } else { None },
                    )));
                }
            }
            _ = sleep_until(deadline) => {
                log::debug!(
                    "predictive punch timed out after {probes_sent} probes, acked: {confirmed}"
                );
                return Ok(None);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    #[test]
    fn window_from_sequential_samples() {
        let w = predict_port_window(&[40000, 40001]).unwrap();
        assert_eq!(*w.start(), 40001);
        assert_eq!(*w.end(), 40001 + WINDOW);
        let w = predict_port_window(&[40000, 40002]).unwrap();
        assert_eq!(*w.start(), 40002);
    }

    #[test]
    fn window_from_single_sample() {
        let w = predict_port_window(&[40000]).unwrap();
        assert_eq!(*w.start(), 40000);
    }

    #[test]
    fn no_window_without_samples() {
        assert!(predict_port_window(&[]).is_none());
        assert!(predict_port_window(&[0, -1]).is_none());
    }

    #[test]
    fn no_window_for_random_or_wrapping_samples() {
        assert!(predict_port_window(&[30000, 50000]).is_none());
        assert!(predict_port_window(&[65535, 2]).is_none());
    }

    #[tokio::test]
    async fn samples_the_observed_port() {
        use hbb_common::{
            protobuf::Message as _,
            rendezvous_proto::{rendezvous_message, RendezvousMessage, TestNatResponse},
        };
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
            assert!(matches!(
                msg.union,
                Some(rendezvous_message::Union::TestNatRequest(_))
            ));
            let mut out = RendezvousMessage::new();
            out.set_test_nat_response(TestNatResponse {
                port: 45678,
                ..Default::default()
            });
            server
                .send_to(&out.write_to_bytes().unwrap(), src)
                .await
                .unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(sample_udp_port(&client, server_addr, 1000).await, Some(45678));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn predictive_punch_over_loopback() {
        let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a_port = a.local_addr().unwrap().port();
        let b_port = b.local_addr().unwrap().port();
        let b_task = tokio::spawn(async move {
            punch_udp_predictive(
                vec![b],
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                a_port..=a_port,
                true,
            )
            .await
        });
        let a_res = punch_udp_predictive(
            vec![a],
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            b_port..=b_port,
            false,
        )
        .await
        .unwrap()
        .expect("connector confirms");
        a_res.0.send_to(b"data", a_res.1).await.unwrap();
        let b_res = b_task.await.unwrap().unwrap().expect("listener sees data");
        assert_eq!(b_res.2.as_deref(), Some(&b"data"[..]));
    }

    // --- NAT simulation: the same probe/ack exchange over modelled NATs ---

    const SERVER_IP: u32 = 0xC0000201;
    const NAT_A_IP: u32 = 0xC6336401;
    const NAT_B_IP: u32 = 0xC6336402;
    const SERVER_PORT: u16 = 21116;
    const W: u16 = 256;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mapping {
        Cone,
        Sequential,
        Random,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Filtering {
        EndpointIndependent,
        AddressDependent,
        AddressPortDependent,
    }

    struct Nat {
        mode: Mapping,
        filtering: Filtering,
        step: u32,
        next: u32,
        rng: u64,
        map: HashMap<(u8, u16, u32, u16), u16>,
        rev: HashMap<u16, (u8, u16, u32, u16)>,
    }

    impl Nat {
        fn new(mode: Mapping, filtering: Filtering, first: u32, step: u32) -> Self {
            Self {
                mode,
                filtering,
                step,
                next: first,
                rng: 0x1234_5678_9abc_def0,
                map: HashMap::new(),
                rev: HashMap::new(),
            }
        }

        fn external(&mut self, host: u8, local: u16, dest_ip: u32, dest_port: u16) -> u16 {
            let key = match self.mode {
                Mapping::Cone => (host, local, 0, 0),
                _ => (host, local, dest_ip, dest_port),
            };
            if let Some(port) = self.map.get(&key) {
                return *port;
            }
            let port = match self.mode {
                Mapping::Random => {
                    self.rng = self
                        .rng
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    ((self.rng >> 33) as u16) | 0x8000
                }
                _ => {
                    let port = self.next as u16;
                    self.next = self.next.wrapping_add(self.step);
                    port
                }
            };
            self.map.insert(key, port);
            self.rev.insert(port, key);
            port
        }

        fn allows(&self, ext: u16, src_ip: u32, src_port: u16) -> Option<(u8, u16)> {
            let (host, local, dest_ip, dest_port) = *self.rev.get(&ext)?;
            let ok = match self.filtering {
                Filtering::EndpointIndependent => true,
                Filtering::AddressDependent => src_ip == dest_ip,
                Filtering::AddressPortDependent => src_ip == dest_ip && src_port == dest_port,
            };
            ok.then_some((host, local))
        }
    }

    struct Packet {
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        data: Vec<u8>,
    }

    struct Peer {
        host: u8,
        nat: usize,
        sockets: Vec<u16>,
        samples: Vec<u16>,
        tid: u64,
        listen: bool,
        done: bool,
        sends: Vec<(usize, u16)>,
        pos: usize,
    }

    struct Sim {
        nats: Vec<Nat>,
        peers: Vec<Peer>,
        queue: VecDeque<Packet>,
        packets: u32,
    }

    impl Sim {
        fn nat_ip(idx: usize) -> u32 {
            [NAT_A_IP, NAT_B_IP][idx]
        }

        fn sample(&mut self, peer: usize) {
            let host = self.peers[peer].host;
            let nat = self.peers[peer].nat;
            let sockets = self.peers[peer].sockets.clone();
            let mut samples = Vec::new();
            for local in sockets {
                let port = self.nats[nat].external(host, local, SERVER_IP, SERVER_PORT);
                samples.push(port);
            }
            self.peers[peer].samples = samples;
        }

        fn outbound(&mut self, peer: usize, socket: usize, dst_ip: u32, dst_port: u16, data: Vec<u8>) {
            let host = self.peers[peer].host;
            let local = self.peers[peer].sockets[socket];
            let nat = self.peers[peer].nat;
            let ext = self.nats[nat].external(host, local, dst_ip, dst_port);
            self.queue.push_back(Packet {
                src_ip: Self::nat_ip(nat),
                src_port: ext,
                dst_ip,
                dst_port,
                data,
            });
        }

        fn route(&mut self, pkt: Packet) {
            self.packets += 1;
            let nat = if pkt.dst_ip == NAT_A_IP {
                0
            } else if pkt.dst_ip == NAT_B_IP {
                1
            } else {
                return;
            };
            if let Some((host, local)) = self.nats[nat].allows(pkt.dst_port, pkt.src_ip, pkt.src_port)
            {
                self.deliver(host, local, pkt);
            }
        }

        fn deliver(&mut self, host: u8, local: u16, pkt: Packet) {
            let Some(peer) = self.peers.iter().position(|p| p.host == host) else {
                return;
            };
            if let Some(peer_tid) = punch_tid(&pkt.data, &PUNCH_PROBE) {
                let socket = self.peers[peer]
                    .sockets
                    .iter()
                    .position(|s| *s == local)
                    .unwrap_or(0);
                let ack = punch_packet(&PUNCH_ACK, peer_tid);
                self.outbound(peer, socket, pkt.src_ip, pkt.src_port, ack.to_vec());
            } else if punch_tid(&pkt.data, &PUNCH_ACK) == Some(self.peers[peer].tid) {
                if !self.peers[peer].listen && !self.peers[peer].done {
                    self.peers[peer].done = true;
                    // the connector answers the ack with its first KCP packet
                    let socket = self.peers[peer]
                        .sockets
                        .iter()
                        .position(|s| *s == local)
                        .unwrap_or(0);
                    self.outbound(peer, socket, pkt.src_ip, pkt.src_port, b"syn".to_vec());
                }
            } else if !pkt.data.is_empty() {
                self.peers[peer].done = true;
            }
        }

        fn drain(&mut self) {
            while let Some(pkt) = self.queue.pop_front() {
                self.route(pkt);
            }
        }

        fn run(&mut self) -> bool {
            for peer in 0..self.peers.len() {
                self.sample(peer);
            }
            let samples_a: Vec<i32> = self.peers[0].samples.iter().map(|p| *p as i32).collect();
            let samples_b: Vec<i32> = self.peers[1].samples.iter().map(|p| *p as i32).collect();
            let Some(window_for_a) = predict_port_window(&samples_b) else {
                return false;
            };
            let Some(window_for_b) = predict_port_window(&samples_a) else {
                return false;
            };
            for (peer, window) in [(0, window_for_a), (1, window_for_b)] {
                let sockets = self.peers[peer].sockets.len();
                let mut sends = Vec::new();
                for tick in 0..W {
                    sends.push((tick as usize % sockets, *window.start() + tick));
                }
                self.peers[peer].sends = sends;
            }
            loop {
                let mut progressed = false;
                for peer in 0..self.peers.len() {
                    let (socket, port, send) = {
                        let p = &self.peers[peer];
                        if p.done || p.pos >= p.sends.len() {
                            (0, 0, false)
                        } else {
                            (p.sends[p.pos].0, p.sends[p.pos].1, true)
                        }
                    };
                    if send {
                        self.peers[peer].pos += 1;
                        let dst = Self::nat_ip(1 - peer);
                        self.outbound(peer, socket, dst, port, punch_packet(&PUNCH_PROBE, self.peers[peer].tid).to_vec());
                        progressed = true;
                    }
                }
                self.drain();
                if !progressed {
                    break;
                }
                if self.peers.iter().all(|p| p.done) || self.packets > 20_000 {
                    break;
                }
            }
            self.peers.iter().all(|p| p.done)
        }
    }

    fn scenario(a: (Mapping, Filtering), b: (Mapping, Filtering), step_a: u32, step_b: u32) -> bool {
        let mut sim = Sim {
            nats: vec![
                Nat::new(a.0, a.1, 40000, step_a),
                Nat::new(b.0, b.1, 50000, step_b),
            ],
            peers: vec![
                Peer {
                    host: 0,
                    nat: 0,
                    sockets: vec![40001, 40002],
                    samples: Vec::new(),
                    tid: 0xAAAA_0000_0000_0001,
                    listen: false,
                    done: false,
                    sends: Vec::new(),
                    pos: 0,
                },
                Peer {
                    host: 1,
                    nat: 1,
                    sockets: vec![50001, 50002],
                    samples: Vec::new(),
                    tid: 0xBBBB_0000_0000_0002,
                    listen: true,
                    done: false,
                    sends: Vec::new(),
                    pos: 0,
                },
            ],
            queue: VecDeque::new(),
            packets: 0,
        };
        sim.run()
    }

    #[test]
    fn sequential_address_dependent_traverses() {
        assert!(scenario(
            (Mapping::Sequential, Filtering::AddressDependent),
            (Mapping::Sequential, Filtering::AddressDependent),
            1,
            1,
        ));
    }

    #[test]
    fn sequential_step_two_address_dependent_traverses() {
        assert!(scenario(
            (Mapping::Sequential, Filtering::AddressDependent),
            (Mapping::Sequential, Filtering::AddressDependent),
            2,
            2,
        ));
    }

    #[test]
    fn cone_peer_traverses_symmetric_peer() {
        assert!(scenario(
            (Mapping::Cone, Filtering::EndpointIndependent),
            (Mapping::Sequential, Filtering::AddressDependent),
            1,
            1,
        ));
        assert!(scenario(
            (Mapping::Sequential, Filtering::AddressDependent),
            (Mapping::Cone, Filtering::EndpointIndependent),
            1,
            1,
        ));
    }

    #[test]
    fn random_mapping_has_no_window() {
        let mut nat = Nat::new(Mapping::Random, Filtering::AddressDependent, 0, 1);
        let a = nat.external(0, 40001, SERVER_IP, SERVER_PORT);
        let b = nat.external(0, 40002, SERVER_IP, SERVER_PORT);
        assert!(predict_port_window(&[a as i32, b as i32]).is_none());
    }

    #[test]
    fn sequential_address_port_dependent_is_best_effort() {
        // Documented limit: address-and-port-dependent filtering couples both
        // source-port choices, so the birthday search does not land here.
        assert!(!scenario(
            (Mapping::Sequential, Filtering::AddressPortDependent),
            (Mapping::Sequential, Filtering::AddressPortDependent),
            1,
            1,
        ));
    }

    #[test]
    fn one_random_side_defeats_prediction() {
        assert!(!scenario(
            (Mapping::Sequential, Filtering::AddressDependent),
            (Mapping::Random, Filtering::AddressDependent),
            1,
            1,
        ));
        assert!(!scenario(
            (Mapping::Random, Filtering::AddressDependent),
            (Mapping::Sequential, Filtering::AddressDependent),
            1,
            1,
        ));
    }
}
