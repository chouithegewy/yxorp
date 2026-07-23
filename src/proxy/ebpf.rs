use aya::Ebpf;
use aya::programs::{Xdp, XdpFlags};
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::OnceLock;
use tracing::{info, warn};

static EBPF_STATE: OnceLock<Mutex<Option<Ebpf>>> = OnceLock::new();

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct QuicRoute {
    pub dst_ip: u32,   // big endian
    pub dst_port: u16, // big endian
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
}

unsafe impl aya::Pod for QuicRoute {}

/// Dynamically detect the interface to attach XDP to based on bind IP.
pub fn detect_interface(bind_ip: IpAddr) -> String {
    if bind_ip.is_loopback() {
        return "lo".to_string();
    }
    if let Ok(entries) = std::fs::read_dir("/sys/class/net/") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "lo" && !name.starts_with("veth") && !name.starts_with("br-") {
                return name;
            }
        }
    }
    "eth0".to_string()
}

/// Parse a MAC address string in 00:11:22:33:44:55 format.
fn parse_mac_address(content: &str) -> Option<[u8; 6]> {
    let cleaned = content.trim();
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() == 6 {
        let mut mac = [0u8; 6];
        for i in 0..6 {
            if let Ok(val) = u8::from_str_radix(parts[i], 16) {
                mac[i] = val;
            } else {
                return None;
            }
        }
        Some(mac)
    } else {
        None
    }
}

/// Parse the ARP table content to resolve the MAC address of the target IP.
fn parse_arp_table(content: &str, ip: IpAddr) -> Option<[u8; 6]> {
    let ip_str = ip.to_string();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0] == ip_str {
            let mac_str = fields[3];
            if let Some(mac) = parse_mac_address(mac_str) {
                return Some(mac);
            }
        }
    }
    None
}

/// Helper to get the local interface MAC address.
pub fn get_interface_mac(iface: &str) -> Option<[u8; 6]> {
    if iface == "lo" {
        return None;
    }
    if let Ok(content) = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface)) {
        if let Some(mac) = parse_mac_address(&content) {
            return Some(mac);
        }
    }
    None
}

/// Helper to get the MAC address of an IP from the ARP table.
pub fn get_arp_mac(ip: IpAddr) -> Option<[u8; 6]> {
    if ip.is_loopback() {
        return None;
    }
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        if let Some(mac) = parse_arp_table(&content, ip) {
            return Some(mac);
        }
    }
    None
}

/// Load the eBPF XDP program and attach it to the interface.
pub fn init_ebpf(iface: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // If already initialized, we do not re-initialize
    let state = EBPF_STATE.get_or_init(|| Mutex::new(None));
    let mut lock = state.lock().unwrap();
    if lock.is_some() {
        return Ok(());
    }

    info!(
        interface = iface,
        "loading eBPF program and attaching to XDP"
    );
    let mut bpf = Ebpf::load(include_bytes!(env!("EBPF_PROGRAM_PATH")))?;

    let program: &mut Xdp = bpf
        .program_mut("xdp_quic_route")
        .ok_or("program 'xdp_quic_route' not found")?
        .try_into()?;

    program.load()?;

    // Attach to the network interface. Fall back if link-exist error.
    match program.attach(iface, XdpFlags::default()) {
        Ok(_) => info!(interface = iface, "eBPF XDP program attached successfully"),
        Err(err) => {
            warn!(interface = iface, error = %err, "failed to attach XDP program; attempting fallback/ignoring if already attached");
        }
    }

    *lock = Some(bpf);
    Ok(())
}

/// Register a connection ID to its corresponding backend server in the eBPF map.
pub fn register_quic_route(
    cid: &[u8],
    route: QuicRoute,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(state) = EBPF_STATE.get() {
        if let Some(bpf) = state.lock().unwrap().as_mut() {
            let mut map: aya::maps::HashMap<_, [u8; 8], QuicRoute> = aya::maps::HashMap::try_from(
                bpf.map_mut("quic_cid_map")
                    .ok_or("quic_cid_map map not found")?,
            )?;

            let mut key = [0u8; 8];
            let len = cid.len().min(8);
            key[..len].copy_from_slice(&cid[..len]);

            map.insert(key, route, 0)?;
            info!(cid = ?key, dst_ip = ?IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(route.dst_ip))), dst_port = u16::from_be(route.dst_port), "registered fast-path eBPF QUIC route");
        }
    }
    Ok(())
}

/// Remove a connection ID from the eBPF map.
pub fn deregister_quic_route(cid: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(state) = EBPF_STATE.get() {
        if let Some(bpf) = state.lock().unwrap().as_mut() {
            let mut map: aya::maps::HashMap<_, [u8; 8], QuicRoute> = aya::maps::HashMap::try_from(
                bpf.map_mut("quic_cid_map")
                    .ok_or("quic_cid_map map not found")?,
            )?;

            let mut key = [0u8; 8];
            let len = cid.len().min(8);
            key[..len].copy_from_slice(&cid[..len]);

            let _ = map.remove(&key);
            info!(cid = ?key, "deregistered eBPF QUIC route");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_mac_address_valid() {
        let mac_str = "00:15:5d:01:02:03";
        assert_eq!(
            parse_mac_address(mac_str),
            Some([0x00, 0x15, 0x5d, 0x01, 0x02, 0x03])
        );

        let mac_str_newline = "00:15:5d:01:02:03\n";
        assert_eq!(
            parse_mac_address(mac_str_newline),
            Some([0x00, 0x15, 0x5d, 0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn test_parse_mac_address_invalid() {
        assert_eq!(parse_mac_address("invalid-mac"), None);
        assert_eq!(parse_mac_address("00:15:5d:01:02"), None);
        assert_eq!(parse_mac_address("00:15:5d:01:02:03:04"), None);
        assert_eq!(parse_mac_address("00:15:5d:01:02:zz"), None);
    }

    #[test]
    fn test_parse_arp_table_match() {
        let arp_content = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:15:5d:0a:0b:0c     *        eth0
10.0.0.5         0x1         0x2         00:11:22:33:44:55     *        eth0
";
        let target_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(
            parse_arp_table(arp_content, target_ip),
            Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        );

        let missing_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        assert_eq!(parse_arp_table(arp_content, missing_ip), None);
    }
}
