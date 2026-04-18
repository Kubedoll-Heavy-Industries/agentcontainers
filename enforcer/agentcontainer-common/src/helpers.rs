//! no_std-compatible helper functions shared between BPF and userspace.

/// Convert u32 from network byte order to host byte order.
#[inline(always)]
pub fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

/// Convert u16 from network byte order to host byte order.
#[inline(always)]
pub fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

/// Check if an IPv4 address (network byte order) is loopback (127.0.0.0/8).
#[inline(always)]
pub fn is_loopback_v4(ip_nbo: u32) -> bool {
    (ntohl(ip_nbo) >> 24) == 127
}

/// Check if an IPv6 address (network byte order u32x4) is loopback (::1).
#[inline(always)]
pub fn is_loopback_v6(ip6: &[u32; 4]) -> bool {
    ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0 && ntohl(ip6[3]) == 1
}

/// Check if an IPv6 address is an IPv4-mapped address (::ffff:0:0/96).
#[inline(always)]
pub fn is_v4_mapped_v6(ip6: &[u32; 4]) -> bool {
    ip6[0] == 0 && ip6[1] == 0 && ntohl(ip6[2]) == 0x0000ffff
}

/// Extract the IPv4 address from an IPv4-mapped IPv6 address.
/// Returns the IPv4 address in network byte order.
#[inline(always)]
pub fn extract_v4_from_mapped(ip6: &[u32; 4]) -> u32 {
    ip6[3]
}
