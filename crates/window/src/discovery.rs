use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, task::JoinSet, time::Instant};

pub const DISCOVERY_PORT: u16 = 43827;
pub const PAIRING_PORT: u16 = 43828;
pub const WINDOW_PORT: u16 = 43829;
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 92, 71);
const MAGIC: &[u8; 8] = b"SPCDISC1";
const PACKET_LEN: usize = 27;
const MAX_INTERFACES: usize = 16;
const MAX_RESPONSES: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub address: SocketAddr,
    pub interface: Interface,
}

impl Interface {
    pub fn new(address: Ipv4Addr, mask: Ipv4Addr) -> Result<Self> {
        let bits = u32::from(mask);
        let host = !bits;
        ensure!(
            (address.is_private() || address.is_link_local() || address.is_loopback())
                && bits.count_ones() >= 8
                && host & host.wrapping_add(1) == 0,
            "unsupported local network interface"
        );
        Ok(Self { address, mask })
    }

    fn contains(self, peer: Ipv4Addr) -> bool {
        (peer.is_private() || peer.is_link_local() || peer.is_loopback())
            && u32::from(peer) & u32::from(self.mask)
                == u32::from(self.address) & u32::from(self.mask)
    }
}

fn packet(kind: u8, nonce: &[u8; 16], port: u16) -> [u8; PACKET_LEN] {
    let mut value = [0u8; PACKET_LEN];
    value[..8].copy_from_slice(MAGIC);
    value[8] = kind;
    value[9..25].copy_from_slice(nonce);
    value[25..].copy_from_slice(&port.to_be_bytes());
    value
}

fn parse(bytes: &[u8], kind: u8, nonce: Option<&[u8; 16]>) -> Option<([u8; 16], u16)> {
    if bytes.len() != PACKET_LEN || &bytes[..8] != MAGIC || bytes[8] != kind {
        return None;
    }
    let token: [u8; 16] = bytes[9..25].try_into().ok()?;
    if nonce.is_some_and(|expected| token != *expected) {
        return None;
    }
    Some((token, u16::from_be_bytes(bytes[25..27].try_into().ok()?)))
}

fn socket(interface: Interface, port: u16, listen: bool) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&SocketAddrV4::new(interface.address, port).into())?;
    socket.set_multicast_if_v4(&interface.address)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(interface.address.is_loopback())?;
    if listen {
        socket.join_multicast_v4(&GROUP, &interface.address)?;
    }
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

pub fn listener(interface: Interface) -> Result<UdpSocket> {
    socket(interface, DISCOVERY_PORT, true)
}

pub async fn respond(socket: UdpSocket, interface: Interface, deadline: Instant) -> Result<()> {
    let mut buffer = [0u8; PACKET_LEN + 1];
    let mut responses = 0;
    let mut invalid_packets = 0;
    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buffer) => received,
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
        };
        let (length, source) = match received {
            Ok(value) => value,
            Err(_) => {
                invalid_packets += 1;
                if invalid_packets >= 64 {
                    return Ok(());
                }
                continue;
            }
        };
        let SocketAddr::V4(source) = source else {
            continue;
        };
        if !interface.contains(*source.ip()) || source.port() == 0 {
            continue;
        }
        if let Some((nonce, 0)) = parse(&buffer[..length], 1, None) {
            socket
                .send_to(&packet(2, &nonce, PAIRING_PORT), source)
                .await?;
            responses += 1;
            if responses >= 64 {
                return Ok(());
            }
        }
    }
}

async fn scan_interface(interface: Interface, nonce: [u8; 16]) -> Result<Vec<Candidate>> {
    let socket = socket(interface, 0, false)?;
    let target = SocketAddrV4::new(GROUP, DISCOVERY_PORT);
    let query = packet(1, &nonce, 0);
    socket.send_to(&query, target).await?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let retry = Instant::now() + Duration::from_millis(500);
    let mut retried = false;
    let mut peers = Vec::new();
    let mut buffer = [0u8; PACKET_LEN + 1];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = received?;
                if let SocketAddr::V4(source) = source {
                    if interface.contains(*source.ip())
                        && parse(&buffer[..length], 2, Some(&nonce)) == Some((nonce, PAIRING_PORT))
                    {
                        let peer = Candidate {
                            address: SocketAddr::V4(SocketAddrV4::new(*source.ip(), PAIRING_PORT)),
                            interface,
                        };
                        if !peers.contains(&peer) {
                            peers.push(peer);
                            if peers.len() >= MAX_RESPONSES { break; }
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(retry), if !retried => {
                retried = true;
                socket.send_to(&query, target).await?;
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }
    Ok(peers)
}

pub async fn discover(interfaces: &[Interface]) -> Result<Vec<Candidate>> {
    ensure!(
        !interfaces.is_empty() && interfaces.len() <= MAX_INTERFACES,
        "no supported local network interface"
    );
    let mut nonce = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .context("secure random source is unavailable")?;
    let mut tasks = JoinSet::new();
    for interface in interfaces.iter().copied() {
        tasks.spawn(scan_interface(interface, nonce));
    }
    let mut peers = Vec::new();
    let mut successful = false;
    while let Some(result) = tasks.join_next().await {
        if let Ok(Ok(found)) = result {
            successful = true;
            for peer in found {
                if !peers.contains(&peer) && peers.len() < MAX_RESPONSES {
                    peers.push(peer);
                }
            }
        }
    }
    ensure!(successful, "local device discovery failed");
    Ok(peers)
}

#[cfg(windows)]
pub fn local_interfaces() -> Result<Vec<Interface>> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpAddrTable, MIB_IPADDRROW_XP, MIB_IPADDRTABLE, MIB_IPADDR_DELETED,
        MIB_IPADDR_DISCONNECTED, MIB_IPADDR_TRANSIENT,
    };

    let mut size = 0u32;
    let mut initial = MIB_IPADDRTABLE::default();
    let first = unsafe { GetIpAddrTable(Some(&mut initial), &mut size, false) };
    ensure!(
        first == 122 && (4..=64 * 1024).contains(&size),
        "cannot inspect local network interfaces"
    );
    let mut storage = vec![0u32; (size as usize).div_ceil(4)];
    let table = storage.as_mut_ptr().cast::<MIB_IPADDRTABLE>();
    let result = unsafe { GetIpAddrTable(Some(table), &mut size, false) };
    ensure!(result == 0, "local network interfaces changed; try again");
    // GetIpAddrTable writes aligned rows into the caller-owned buffer.
    let count = unsafe { (*table).dwNumEntries as usize };
    let offset = std::mem::offset_of!(MIB_IPADDRTABLE, table);
    ensure!(
        size as usize <= storage.len() * 4
            && count <= 256
            && offset + count * std::mem::size_of::<MIB_IPADDRROW_XP>() <= size as usize,
        "invalid local network interface table"
    );
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).table).cast::<MIB_IPADDRROW_XP>(),
            count,
        )
    };
    let mut interfaces = Vec::new();
    for row in rows {
        if u32::from(row.wType)
            & (MIB_IPADDR_DELETED | MIB_IPADDR_DISCONNECTED | MIB_IPADDR_TRANSIENT)
            != 0
        {
            continue;
        }
        let address = Ipv4Addr::from(row.dwAddr.to_ne_bytes());
        let mask = Ipv4Addr::from(row.dwMask.to_ne_bytes());
        if !address.is_loopback() {
            if let Ok(interface) = Interface::new(address, mask) {
                if !interfaces.contains(&interface) {
                    interfaces.push(interface);
                    ensure!(
                        interfaces.len() <= MAX_INTERFACES,
                        "too many local network interfaces"
                    );
                }
            }
        }
    }
    ensure!(
        !interfaces.is_empty(),
        "no private IPv4 network is available"
    );
    Ok(interfaces)
}

#[cfg(not(windows))]
pub fn local_interfaces() -> Result<Vec<Interface>> {
    anyhow::bail!("device discovery requires Windows")
}

pub fn peer_is_local(interface: Interface, address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => interface.contains(ip),
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_limits_peers_to_the_selected_private_subnet() {
        let interface = Interface::new(
            Ipv4Addr::new(192, 168, 17, 4),
            Ipv4Addr::new(255, 255, 255, 0),
        )
        .unwrap();
        assert!(peer_is_local(
            interface,
            "192.168.17.8:1000".parse().unwrap()
        ));
        assert!(!peer_is_local(
            interface,
            "192.168.18.8:1000".parse().unwrap()
        ));
        assert!(!peer_is_local(
            interface,
            "203.0.113.1:1000".parse().unwrap()
        ));
        assert!(Interface::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).is_err());
        assert!(Interface::new(
            Ipv4Addr::new(192, 168, 17, 4),
            Ipv4Addr::new(255, 0, 255, 0)
        )
        .is_err());
    }

    #[test]
    fn discovery_rejects_wrong_nonce_message_and_port() {
        let nonce = [7u8; 16];
        let response = packet(2, &nonce, PAIRING_PORT);
        assert_eq!(
            parse(&response, 2, Some(&nonce)),
            Some((nonce, PAIRING_PORT))
        );
        assert!(parse(&response, 1, Some(&nonce)).is_none());
        assert!(parse(&response, 2, Some(&[8u8; 16])).is_none());
        assert!(parse(&response[..PACKET_LEN - 1], 2, Some(&nonce)).is_none());
        assert_ne!(
            parse(&packet(2, &nonce, 7), 2, Some(&nonce)),
            Some((nonce, PAIRING_PORT))
        );
    }

    #[tokio::test]
    async fn responder_ignores_malformed_queries_and_preserves_request_nonce() {
        let interface = Interface::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0)).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder = tokio::spawn(respond(
            server,
            interface,
            Instant::now() + Duration::from_secs(1),
        ));
        client
            .send_to(b"not a discovery request", destination)
            .await
            .unwrap();
        let nonce = [7u8; 16];
        client
            .send_to(&packet(1, &nonce, 0), destination)
            .await
            .unwrap();
        let mut response = [0u8; PACKET_LEN + 1];
        let (length, _) =
            tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            parse(&response[..length], 2, Some(&nonce)),
            Some((nonce, PAIRING_PORT))
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut response))
                .await
                .is_err()
        );
        responder.abort();
    }

    #[tokio::test]
    async fn multicast_discovery_uses_the_selected_loopback_interface() {
        let interface = Interface::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0)).unwrap();
        let receiver = socket(interface, 0, true).unwrap();
        let target = SocketAddrV4::new(GROUP, receiver.local_addr().unwrap().port());
        let sender = socket(interface, 0, false).unwrap();
        let query = packet(1, &[7u8; 16], 0);
        sender.send_to(&query, target).await.unwrap();
        let mut buffer = [0u8; PACKET_LEN + 1];
        let received =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(received.0, query.len());
        assert_eq!(&buffer[..received.0], &query);
        assert!(received.1.ip().is_loopback());
    }

    #[tokio::test]
    async fn scan_discovers_an_opted_in_responder_on_loopback() {
        let interface = Interface::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0)).unwrap();
        let server = listener(interface).unwrap();
        let responder = tokio::spawn(respond(
            server,
            interface,
            Instant::now() + Duration::from_secs(4),
        ));
        let found = discover(&[interface]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].address.ip().is_loopback());
        assert_eq!(found[0].address.port(), PAIRING_PORT);
        responder.abort();
    }
}
