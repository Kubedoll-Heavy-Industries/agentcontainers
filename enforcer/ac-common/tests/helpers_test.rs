use ac_common::helpers::*;

#[test]
fn test_ntohl_little_endian() {
    assert_eq!(ntohl(0x04030201u32), 0x01020304u32);
}

#[test]
fn test_is_loopback_v4() {
    let lo = 0x7f000001u32.to_be();
    assert!(is_loopback_v4(lo));
    let not_lo = 0x0a000001u32.to_be();
    assert!(!is_loopback_v4(not_lo));
    let lo_max = 0x7fffffffu32.to_be();
    assert!(is_loopback_v4(lo_max));
}

#[test]
fn test_is_loopback_v6() {
    let lo: [u32; 4] = [0, 0, 0, 1u32.to_be()];
    assert!(is_loopback_v6(&lo));
    let not_lo: [u32; 4] = [0, 0, 0, 2u32.to_be()];
    assert!(!is_loopback_v6(&not_lo));
    let unspec: [u32; 4] = [0, 0, 0, 0];
    assert!(!is_loopback_v6(&unspec));
}

#[test]
fn test_is_v4_mapped_v6() {
    let mapped: [u32; 4] = [0, 0, 0x0000ffffu32.to_be(), 0x0a000001u32.to_be()];
    assert!(is_v4_mapped_v6(&mapped));
    let not_mapped: [u32; 4] = [0, 0, 0, 1u32.to_be()];
    assert!(!is_v4_mapped_v6(&not_mapped));
}

#[test]
fn test_extract_v4_from_mapped() {
    let mapped: [u32; 4] = [0, 0, 0x0000ffffu32.to_be(), 0x0a000001u32.to_be()];
    assert_eq!(extract_v4_from_mapped(&mapped), 0x0a000001u32.to_be());
}
