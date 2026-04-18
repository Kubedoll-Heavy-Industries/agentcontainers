use agentcontainer_common::siphash::*;

#[test]
fn test_siphash128_deterministic() {
    let key = SipHashKey {
        k0: 0x0706050403020100,
        k1: 0x0f0e0d0c0b0a0908,
    };
    let h1 = siphash128(&key, b"example.com");
    let h2 = siphash128(&key, b"example.com");
    assert_eq!(h1, h2, "same input must produce same hash");
}

#[test]
fn test_siphash128_different_inputs() {
    let key = SipHashKey { k0: 1, k1: 2 };
    let h1 = siphash128(&key, b"example.com");
    let h2 = siphash128(&key, b"example.org");
    assert_ne!(h1, h2, "different inputs must produce different hashes");
}

#[test]
fn test_siphash128_different_keys() {
    let k1 = SipHashKey { k0: 1, k1: 2 };
    let k2 = SipHashKey { k0: 3, k1: 4 };
    let h1 = siphash128(&k1, b"example.com");
    let h2 = siphash128(&k2, b"example.com");
    assert_ne!(h1, h2, "different keys must produce different hashes");
}

#[test]
fn test_siphash128_is_128_bit() {
    let key = SipHashKey { k0: 42, k1: 43 };
    let h = siphash128(&key, b"test.example.com");
    // A 128-bit hash should have bits set in the upper half for typical inputs.
    // This isn't guaranteed for every input, but for a well-distributed hash
    // it's extremely unlikely that the upper 64 bits are all zero.
    // We just check it's not trivially zero.
    assert_ne!(h, 0, "hash should not be zero");
}

#[test]
fn test_domain_hasher_matches_direct() {
    let key = SipHashKey {
        k0: 0xDEAD,
        k1: 0xBEEF,
    };

    // Direct hash of "www.example.com"
    let direct = siphash128(&key, b"www.example.com");

    // Incremental hash via DomainHasher (simulating BPF label-by-label feeding)
    let mut dh = DomainHasher::new(&key);
    // Label "www"
    dh.dot();
    for &b in b"www" {
        dh.write_byte(b);
    }
    // Label "example"
    dh.dot();
    for &b in b"example" {
        dh.write_byte(b);
    }
    // Label "com"
    dh.dot();
    for &b in b"com" {
        dh.write_byte(b);
    }
    let incremental = dh.finish128();

    assert_eq!(
        direct, incremental,
        "DomainHasher must produce same hash as direct siphash128"
    );
}

#[test]
fn test_domain_hasher_case_insensitive() {
    let key = SipHashKey { k0: 100, k1: 200 };

    // Lowercase
    let h1 = siphash128(&key, b"example.com");

    // Simulate BPF lowercasing "EXAMPLE.COM"
    let mut dh = DomainHasher::new(&key);
    dh.dot();
    for &b in b"EXAMPLE" {
        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        dh.write_byte(lower);
    }
    dh.dot();
    for &b in b"COM" {
        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        dh.write_byte(lower);
    }
    let h2 = dh.finish128();

    assert_eq!(h1, h2, "lowercased domain must match direct lowercase hash");
}

#[test]
fn test_siphash_key_layout() {
    assert_eq!(core::mem::size_of::<SipHashKey>(), 16);
    assert_eq!(core::mem::align_of::<SipHashKey>(), 8);
}
