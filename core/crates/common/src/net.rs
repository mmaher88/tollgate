//! The addresses of this device's network interfaces.

use std::net::IpAddr;

/// Whether `ip` is assigned to one of this device's network interfaces now. A connection
/// whose source address is no longer assigned (Wi-Fi went away, the network changed) can
/// never deliver another byte. True when the list cannot be read, so callers keep what they
/// have.
pub fn is_local_address(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list it allocates to `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return true;
    }
    let mut found = false;
    let mut cursor = list;
    while !cursor.is_null() && !found {
        // SAFETY: every entry of the list is valid until freeifaddrs.
        let entry = unsafe { &*cursor };
        if !entry.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr whose family says which one it is.
            let family = i32::from(unsafe { (*entry.ifa_addr).sa_family });
            found = match ip {
                IpAddr::V4(v4) if family == libc::AF_INET => {
                    // SAFETY: an AF_INET address is a sockaddr_in.
                    let sin = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                    u32::from_be(sin.sin_addr.s_addr) == u32::from(v4)
                }
                IpAddr::V6(v6) if family == libc::AF_INET6 => {
                    // SAFETY: an AF_INET6 address is a sockaddr_in6.
                    let sin6 = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                    sin6.sin6_addr.s6_addr == v6.octets()
                }
                _ => false,
            };
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: `list` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(list) };
    found
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};

    use super::is_local_address;

    #[test]
    fn loopback_is_assigned() {
        assert!(is_local_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_local_address("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn unassigned_addresses_are_not() {
        assert!(!is_local_address("192.0.2.123".parse().unwrap()));
        assert!(!is_local_address("2001:db8::7".parse().unwrap()));
    }

    /// The source address the system picks for an outside destination, if there is a route.
    #[test]
    fn the_default_source_address_is_assigned() {
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
            return;
        };
        if socket.connect("192.0.2.1:9").is_err() {
            return;
        }
        let ip = socket.local_addr().unwrap().ip();
        assert!(is_local_address(ip), "{ip}");
    }
}
