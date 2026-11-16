//! Bounded, interface-scoped unicast discovery; no subnet scans or multicast.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::os::fd::AsRawFd;
use std::{collections::BTreeSet, net::Ipv4Addr, time::Duration};
use tokio::net::UdpSocket;

const SERVICE: &str = "_remotepairing._tcp.local.";
pub const MAX_CANDIDATES: usize = 32;

/// A verified endpoint; interface names prevent cross-network stale-cache use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub interface: String,
}

/// An active LAN network eligible for local discovery.
#[derive(Clone, Debug)]
pub struct Network {
    pub interface: String,
    pub ip: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl Network {
    /// Accept only another unicast host on this physical local subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let address = u32::from(ip);
        let mask = u32::from(self.mask);
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_loopback()
            && ip != self.ip
            && address & mask == u32::from(self.ip) & mask
            && address & !mask != 0
            && address & !mask != !mask
    }
}

/// Read active IPv4 interfaces without changing routing or VPN state.
pub fn networks() -> Result<Vec<Network>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes an owned linked list; all inspected addresses
    // are family-checked, and freeifaddrs releases it once after traversal.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut cursor = head;
        let mut result = Vec::new();
        while !cursor.is_null() {
            let entry = &*cursor;
            if !entry.ifa_addr.is_null()
                && !entry.ifa_netmask.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET
                && entry.ifa_flags & libc::IFF_UP as u32 != 0
            {
                let interface = std::ffi::CStr::from_ptr(entry.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let address = &*(entry.ifa_addr.cast::<libc::sockaddr_in>());
                let mask = &*(entry.ifa_netmask.cast::<libc::sockaddr_in>());
                let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
                if (interface.starts_with("en")
                    || interface.starts_with("eth")
                    || interface.starts_with("wl"))
                    && (ip.is_private() || ip.is_link_local())
                {
                    result.push(Network {
                        interface,
                        ip,
                        mask: Ipv4Addr::from(u32::from_be(mask.sin_addr.s_addr)),
                    });
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(head);
        Ok(result)
    }
}

/// Parse only complete neighbors on an active local subnet, bounded and deduplicated.
pub fn neighbors(text: &str, networks: &[Network]) -> Vec<Endpoint> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for line in text.lines().filter(|line| !line.contains("incomplete")) {
        let Some((_, rest)) = line.split_once('(') else {
            continue;
        };
        let Some((ip, _)) = rest.split_once(')') else {
            continue;
        };
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let words: Vec<_> = line.split_whitespace().collect();
        let Some(interface) = words.windows(2).find(|w| w[0] == "on").map(|w| w[1]) else {
            continue;
        };
        if let Some(network) = networks
            .iter()
            .find(|n| n.interface == interface && n.contains(ip))
        {
            if seen.insert((ip, network.interface.clone())) {
                result.push(Endpoint {
                    ip,
                    port: 0,
                    interface: network.interface.clone(),
                });
                if result.len() == MAX_CANDIDATES {
                    break;
                }
            }
        }
    }
    result
}

/// Decode a DNS name with checked bounds and a strict compression jump budget.
fn name(packet: &[u8], start: usize) -> Result<(String, usize)> {
    let mut offset = start;
    let mut end = None;
    let mut labels = Vec::new();
    for _ in 0..128 {
        let length = *packet.get(offset).context("truncated DNS name")? as usize;
        offset += 1;
        if length == 0 {
            return Ok((format!("{}.", labels.join(".")), end.unwrap_or(offset)));
        }
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(offset).context("truncated DNS pointer")? as usize;
            end.get_or_insert(offset + 1);
            offset = ((length & 63) << 8) | next;
        } else {
            if length > 63 {
                bail!("invalid DNS label");
            }
            let bytes = packet
                .get(offset..offset + length)
                .context("truncated DNS label")?;
            labels.push(std::str::from_utf8(bytes)?.to_ascii_lowercase());
            offset += length;
            if labels.iter().map(String::len).sum::<usize>() + labels.len() > 255 {
                bail!("long DNS name");
            }
        }
    }
    bail!("DNS compression cycle")
}

/// Read a network-order integer without unchecked indexing.
fn word(packet: &[u8], offset: usize) -> Result<u16> {
    let bytes = packet
        .get(offset..offset + 2)
        .context("truncated DNS field")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// An untrusted service advertisement; never serialize its authentication tag.
pub struct Advertisement {
    pub port: u16,
    pub identifier: String,
    pub auth_tag: String,
}

/// Match PTR/SRV/TXT by owner instead of accepting unrelated additional records.
pub fn advertisement(packet: &[u8]) -> Result<Advertisement> {
    if packet.len() < 12 || word(packet, 2)? & 0x8000 == 0 {
        bail!("not a DNS reply");
    }
    let mut offset = 12;
    for _ in 0..word(packet, 4)? {
        offset = name(packet, offset)?.1 + 4;
    }
    let count = usize::from(word(packet, 6)?)
        + usize::from(word(packet, 8)?)
        + usize::from(word(packet, 10)?);
    if count > 128 {
        bail!("too many DNS records");
    }
    let mut records = Vec::new();
    let mut instance = None;
    for _ in 0..count {
        let (owner, next) = name(packet, offset)?;
        let kind = word(packet, next)?;
        let length = usize::from(word(packet, next + 8)?);
        offset = next + 10;
        let end = offset.checked_add(length).context("DNS length overflow")?;
        let data = packet.get(offset..end).context("truncated DNS record")?;
        if kind == 12 && owner == SERVICE {
            instance = Some(name(packet, offset)?.0);
        }
        records.push((owner, kind, data));
        offset = end;
    }
    let instance = instance.context("missing service PTR")?;
    let srv = records
        .iter()
        .find(|(owner, kind, _)| *owner == instance && *kind == 33)
        .context("missing SRV")?
        .2;
    let port = word(srv, 4)?;
    if port == 0 {
        bail!("zero service port");
    }
    let txt = records
        .iter()
        .find(|(owner, kind, _)| *owner == instance && *kind == 16)
        .context("missing TXT")?
        .2;
    let mut values = std::collections::HashMap::new();
    let mut offset = 0;
    while let Some(length) = txt.get(offset) {
        offset += 1;
        let end = offset + usize::from(*length);
        let value = std::str::from_utf8(txt.get(offset..end).context("truncated TXT")?)?;
        if let Some((key, value)) = value.split_once('=') {
            values.insert(key, value);
        }
        offset = end;
    }
    Ok(Advertisement {
        port,
        identifier: values
            .get("identifier")
            .context("missing identifier")?
            .to_string(),
        auth_tag: values
            .get("authTag")
            .context("missing authTag")?
            .to_string(),
    })
}

/// Query the exact neighbor by unicast, binding to the physical interface on macOS.
pub async fn query(endpoint: &Endpoint, network: &Network) -> Result<Advertisement> {
    let socket = UdpSocket::bind((network.ip, 0)).await?;
    bind_interface(socket.as_raw_fd(), &network.interface)?;
    let mut packet = vec![0xb1, 0x90, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in SERVICE.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    // An ephemeral source port requests a legacy unicast response (RFC 6762).
    packet.extend_from_slice(&[0, 0, 12, 0, 1]);
    socket.send_to(&packet, (endpoint.ip, 5353)).await?;
    let mut response = [0; 16384];
    tokio::time::timeout(Duration::from_millis(1200), async {
        loop {
            let (length, peer) = socket.recv_from(&mut response).await?;
            if peer.ip() != endpoint.ip || peer.port() != 5353 {
                continue;
            }
            if let Ok(answer) = advertisement(&response[..length]) {
                return Ok(answer);
            }
        }
    })
    .await?
}

/// Keep discovery and pairing sockets on the selected physical LAN, preserving VPN policy.
fn bind_interface(fd: std::os::fd::RawFd, name: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let interface = std::ffi::CString::new(name)?;
        // SAFETY: both socket fd and interface name remain valid for these calls.
        unsafe {
            let index = libc::if_nametoindex(interface.as_ptr());
            if index == 0
                || libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_BOUND_IF,
                    (&index as *const u32).cast(),
                    std::mem::size_of_val(&index) as libc::socklen_t,
                ) != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (fd, name);
    Ok(())
}

/// Open a service on the selected interface rather than a VPN's default route.
pub async fn connect(endpoint: &Endpoint, port: u16) -> Result<tokio::net::TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    bind_interface(socket.as_raw_fd(), &endpoint.interface)?;
    Ok(socket.connect((endpoint.ip, port).into()).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stale/cross-subnet and incomplete entries must not expand discovery scope.
    #[test]
    fn neighbors_are_bounded_local_and_complete() {
        let nets = [Network {
            interface: "en0".into(),
            ip: Ipv4Addr::new(192, 168, 2, 1),
            mask: Ipv4Addr::new(255, 255, 255, 0),
        }];
        let text = "? (192.168.2.2) at ab:cd on en0 ifscope\n? (192.168.2.2) at ab:cd on en0\n? (192.168.2.3) at (incomplete) on en0\n? (192.168.3.2) at ab on en0\n? (192.168.2.4) at ab on utun4";
        let found = neighbors(text, &nets);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].ip, Ipv4Addr::new(192, 168, 2, 2));
    }

    /// Corrupt DNS data must terminate safely rather than recurse or panic.
    #[test]
    fn dns_rejects_cycles_and_truncations() {
        assert!(name(&[0xc0, 0], 0).is_err());
        assert!(name(&[7, b'a'], 0).is_err());
        for length in 0..32 {
            assert!(advertisement(&vec![0; length]).is_err());
        }
    }

    /// Encode a literal DNS name for deterministic service response fixtures.
    fn encoded_name(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in value.trim_end_matches('.').split('.') {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0);
        bytes
    }

    /// PTR, SRV and TXT must belong to the same advertised service instance.
    #[test]
    fn service_records_are_matched_by_owner() -> Result<()> {
        let instance = "paired._remotepairing._tcp.local.";
        let mut bytes = vec![0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        let mut srv = vec![0, 0, 0, 0, 0xc0, 0];
        srv.extend(encoded_name("phone.local."));
        let mut txt = Vec::new();
        for field in ["identifier=example", "authTag=AAAAAAAA"] {
            txt.push(field.len() as u8);
            txt.extend(field.as_bytes());
        }
        for (owner, kind, data) in [
            (SERVICE, 12u16, encoded_name(instance)),
            (instance, 33, srv),
            (instance, 16, txt),
        ] {
            bytes.extend(encoded_name(owner));
            bytes.extend(kind.to_be_bytes());
            bytes.extend([0, 1, 0, 0, 0, 120]);
            bytes.extend((data.len() as u16).to_be_bytes());
            bytes.extend(data);
        }
        let answer = advertisement(&bytes)?;
        assert_eq!(answer.port, 49152);
        assert_eq!(answer.identifier, "example");
        for end in 0..bytes.len() {
            assert!(advertisement(&bytes[..end]).is_err());
        }
        let mut unrelated = bytes.clone();
        // Replace the TXT owner with another same-length instance name.
        let txt_owner = unrelated
            .windows(7)
            .rposition(|v| v == b"\x06paired")
            .context("fixture TXT owner")?;
        unrelated[txt_owner + 1..txt_owner + 7].copy_from_slice(b"others");
        assert!(advertisement(&unrelated).is_err());
        Ok(())
    }

    /// LAN masks and the candidate budget exclude broadcast, network and VPN addresses.
    #[test]
    fn neighbor_budget_and_host_boundaries() {
        let network = Network {
            interface: "en0".into(),
            ip: Ipv4Addr::new(192, 168, 1, 2),
            mask: Ipv4Addr::new(255, 255, 255, 0),
        };
        for tail in [0, 2, 255] {
            assert!(!network.contains(Ipv4Addr::new(192, 168, 1, tail)));
        }
        let text = (3..100)
            .map(|n| format!("? (192.168.1.{n}) at 01:02:03:04:05:06 on en0"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(neighbors(&text, &[network]).len(), MAX_CANDIDATES);
    }
}
