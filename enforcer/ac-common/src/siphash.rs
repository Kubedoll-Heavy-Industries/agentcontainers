//! SipHash-2-4 128-bit helpers for domain name hashing.
//!
//! Wraps the `siphasher` crate to provide a simple API for hashing
//! byte sequences with a shared key. Used in BPF programs (no_std)
//! and userspace (std) to produce matching 128-bit digests.

use core::hash::Hasher;
use siphasher::sip128::{Hasher128, SipHasher24};

/// Key material for SipHash-2-4. Two u64 values stored in a BPF array map
/// and shared between BPF programs and userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SipHashKey {
    pub k0: u64,
    pub k1: u64,
}

/// Hash a byte slice with SipHash-2-4, returning a 128-bit digest as u128.
#[inline]
pub fn siphash128(key: &SipHashKey, data: &[u8]) -> u128 {
    let mut hasher = SipHasher24::new_with_keys(key.k0, key.k1);
    hasher.write(data);
    hasher.finish128().as_u128()
}

/// Hash a byte slice, returning the digest as `[u8; 16]` in native byte order.
/// This is the format stored in `DnsEvent.domain_hash` and BPF map keys.
#[inline]
pub fn siphash128_bytes(key: &SipHashKey, data: &[u8]) -> [u8; 16] {
    siphash128(key, data).to_ne_bytes()
}

/// Hash a DNS domain name label-by-label from a packet, lowercasing ASCII
/// as we go. This is designed for BPF: it takes individual bytes fed one at
/// a time, building the canonical "label.label.label" form incrementally.
///
/// Usage:
/// ```ignore
/// let mut h = DomainHasher::new(key);
/// // For each label, feed the bytes lowercased, then call dot() between labels.
/// h.write_byte(b'w'); h.write_byte(b'w'); h.write_byte(b'w');
/// h.dot();
/// h.write_byte(b'e'); h.write_byte(b'x'); // ...
/// let hash = h.finish128();
/// ```
pub struct DomainHasher {
    inner: SipHasher24,
    has_label: bool,
}

impl DomainHasher {
    /// Create a new domain hasher with the given key.
    #[inline]
    pub fn new(key: &SipHashKey) -> Self {
        Self {
            inner: SipHasher24::new_with_keys(key.k0, key.k1),
            has_label: false,
        }
    }

    /// Feed a single byte (should already be lowercased).
    #[inline]
    pub fn write_byte(&mut self, b: u8) {
        self.inner.write_u8(b);
    }

    /// Insert a '.' separator between labels.
    #[inline]
    pub fn dot(&mut self) {
        if self.has_label {
            self.inner.write_u8(b'.');
        }
        self.has_label = true;
    }

    /// Finalize and return the 128-bit hash as u128.
    #[inline]
    pub fn finish128(&self) -> u128 {
        self.inner.finish128().as_u128()
    }

    /// Finalize and return the 128-bit hash as `[u8; 16]` in native byte order.
    #[inline]
    pub fn finish128_bytes(&self) -> [u8; 16] {
        self.finish128().to_ne_bytes()
    }
}
