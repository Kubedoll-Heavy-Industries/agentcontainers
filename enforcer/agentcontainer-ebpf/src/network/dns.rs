//! cgroup_skb/ingress hook for DNS response parsing.
//!
//! Intercepts inbound packets, identifies DNS responses (UDP port 53),
//! parses answer records, and emits events containing a SipHash-2-4 128-bit
//! digest of the domain name plus the resolved IP addresses.
//!
//! Only emits events for domains present in the TRACKED_DOMAINS map — all
//! other DNS traffic is silently ignored, minimizing ring buffer bandwidth.
//!
//! Security properties:
//! - Keyed SipHash-128: negligible collision risk (birthday bound ~2^64).
//!   Replaces the old FNV-1a 32-bit approach (M2 fix).
//! - Compression pointer depth limit of 8 jumps (H1 fix).
//! - Observation-only: always returns 1 (allow). Never blocks DNS traffic.

use core::hash::Hasher;
use siphasher::sip128::{Hasher128, SipHasher24};

use aya_ebpf::macros::cgroup_skb;
use aya_ebpf::programs::SkBuffContext;

use agentcontainer_common::events::{
    DnsEvent, EventType, DNS_CLASS_IN, DNS_FLAG_QR, DNS_HEADER_SIZE, DNS_PORT, DNS_TYPE_A,
    DNS_TYPE_AAAA, MAX_COMPRESSION_JUMPS,
};

use crate::maps::{DNS_EVENTS, SIPHASH_KEY, TRACKED_DOMAINS};

// ---------------------------------------------------------------------------
// IP protocol constants.
// ---------------------------------------------------------------------------
const IPPROTO_UDP: u8 = 17;
const IP_HEADER_MIN_SIZE: usize = 20;
const IP6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;

// Bounded loop limits for BPF verifier compliance.
const MAX_NAME_BYTES: usize = 255;
const MAX_LABEL_BYTES: usize = 63;
const MAX_QUESTIONS: usize = 4;
const MAX_ANSWERS: usize = 16;

// ---------------------------------------------------------------------------
// Safe packet access helpers.
// ---------------------------------------------------------------------------

#[inline(always)]
fn load_byte(ctx: &SkBuffContext, offset: usize) -> Option<u8> {
    ctx.load::<u8>(offset).ok()
}

#[inline(always)]
fn load_u16_be(ctx: &SkBuffContext, offset: usize) -> Option<u16> {
    let hi = ctx.load::<u8>(offset).ok()? as u16;
    let lo = ctx.load::<u8>(offset + 1).ok()? as u16;
    Some((hi << 8) | lo)
}

#[inline(always)]
fn load_u32_be(ctx: &SkBuffContext, offset: usize) -> Option<u32> {
    let b0 = ctx.load::<u8>(offset).ok()? as u32;
    let b1 = ctx.load::<u8>(offset + 1).ok()? as u32;
    let b2 = ctx.load::<u8>(offset + 2).ok()? as u32;
    let b3 = ctx.load::<u8>(offset + 3).ok()? as u32;
    Some((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

// ---------------------------------------------------------------------------
// DNS name hashing: walk a DNS name in the packet and incrementally feed
// lowercased bytes into a SipHash-2-4 hasher. No copy to a buffer needed.
//
// Returns (end_offset, hash) where:
//   - end_offset is past the name in the original packet
//   - hash is the 128-bit SipHash digest of the normalized domain
// ---------------------------------------------------------------------------

struct DnsHashResult {
    end_offset: usize,
    hash: [u8; 16],
}

#[inline(always)]
fn hash_dns_name(
    ctx: &SkBuffContext,
    start_offset: usize,
    pkt_len: usize,
    hasher: &mut SipHasher24,
) -> Option<DnsHashResult> {
    let mut offset = start_offset;
    let mut end_offset: usize = 0;
    let mut first_label = true;
    let mut jumps: u32 = 0;

    for _i in 0..MAX_NAME_BYTES {
        if offset >= pkt_len {
            return None;
        }

        let label_len = load_byte(ctx, offset)?;

        if label_len == 0 {
            if end_offset == 0 {
                end_offset = offset + 1;
            }
            break;
        }

        // Compression pointer (top 2 bits = 0b11).
        if (label_len & 0xC0) == 0xC0 {
            let low = load_byte(ctx, offset + 1)?;
            if end_offset == 0 {
                end_offset = offset + 2;
            }
            offset = ((label_len as usize & 0x3F) << 8) | (low as usize);
            jumps += 1;
            if jumps > MAX_COMPRESSION_JUMPS {
                return None; // H1 fix
            }
            continue;
        }

        let len = label_len as usize;
        if len > MAX_LABEL_BYTES {
            return None;
        }

        // Insert '.' between labels.
        if !first_label {
            hasher.write_u8(b'.');
        }
        first_label = false;

        offset += 1;

        // Feed label bytes into hasher, lowercasing ASCII.
        for j in 0..MAX_LABEL_BYTES {
            if j >= len {
                break;
            }
            let ch = load_byte(ctx, offset + j)?;
            let lower = if ch >= b'A' && ch <= b'Z' {
                ch + 32
            } else {
                ch
            };
            hasher.write_u8(lower);
        }
        offset += len;
    }

    if end_offset == 0 {
        return None;
    }

    let hash = hasher.finish128().as_u128().to_ne_bytes();
    Some(DnsHashResult { end_offset, hash })
}

/// Skip a DNS name without hashing. Used for subsequent questions and
/// answer name fields where we already have the domain hash from the
/// first question.
#[inline(always)]
fn skip_dns_name(ctx: &SkBuffContext, start_offset: usize, pkt_len: usize) -> Option<usize> {
    let mut offset = start_offset;
    let mut end_offset: usize = 0;

    for _i in 0..MAX_NAME_BYTES {
        if offset >= pkt_len {
            return None;
        }

        let label_len = load_byte(ctx, offset)?;

        if label_len == 0 {
            if end_offset == 0 {
                end_offset = offset + 1;
            }
            break;
        }

        if (label_len & 0xC0) == 0xC0 {
            if end_offset == 0 {
                end_offset = offset + 2;
            }
            break;
        }

        let len = label_len as usize;
        if len > MAX_LABEL_BYTES {
            return None;
        }
        offset += 1 + len;
    }

    if end_offset == 0 {
        return None;
    }

    Some(end_offset)
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

#[cgroup_skb(ingress)]
pub fn ac_dns_ingress(ctx: SkBuffContext) -> i32 {
    match try_parse_dns(&ctx) {
        Ok(_) => 1,  // Always allow
        Err(_) => 1, // Always allow — DNS ingress is observation only
    }
}

#[inline(always)]
fn try_parse_dns(ctx: &SkBuffContext) -> Result<(), ()> {
    let pkt_len = ctx.len() as usize;

    // Load SipHash key from BPF map. If not set, skip DNS processing.
    let key = unsafe { SIPHASH_KEY.get(0).ok_or(())? };

    // Determine IP version from the first nibble.
    let ver_byte = load_byte(ctx, 0).ok_or(())?;
    let ip_version = (ver_byte >> 4) & 0xF;

    let udp_offset: usize;

    if ip_version == 4 {
        if pkt_len < IP_HEADER_MIN_SIZE + UDP_HEADER_SIZE + DNS_HEADER_SIZE {
            return Err(());
        }
        let ihl = ((ver_byte & 0x0F) as usize) * 4;
        if ihl < IP_HEADER_MIN_SIZE || ihl > 60 {
            return Err(());
        }
        let ip_proto = load_byte(ctx, 9).ok_or(())?;
        if ip_proto != IPPROTO_UDP {
            return Err(());
        }
        udp_offset = ihl;
    } else if ip_version == 6 {
        if pkt_len < IP6_HEADER_SIZE + UDP_HEADER_SIZE + DNS_HEADER_SIZE {
            return Err(());
        }
        let ip_proto = load_byte(ctx, 6).ok_or(())?;
        if ip_proto != IPPROTO_UDP {
            return Err(());
        }
        udp_offset = IP6_HEADER_SIZE;
    } else {
        return Err(());
    }

    // Check source port == 53 (DNS response).
    let src_port = load_u16_be(ctx, udp_offset).ok_or(())?;
    if src_port != DNS_PORT {
        return Err(());
    }

    let dns_offset = udp_offset + UDP_HEADER_SIZE;

    // DNS header: flags, qdcount, ancount.
    let flags = load_u16_be(ctx, dns_offset + 2).ok_or(())?;
    if (flags & DNS_FLAG_QR) == 0 {
        return Err(()); // Not a response
    }

    let qdcount = load_u16_be(ctx, dns_offset + 4).ok_or(())?;
    let ancount = load_u16_be(ctx, dns_offset + 6).ok_or(())?;

    let mut pos = dns_offset + DNS_HEADER_SIZE;

    // Hash the first question's domain name with SipHash-2-4 128-bit.
    let question_name_offset = pos;
    let mut hasher = SipHasher24::new_with_keys(key.k0, key.k1);
    let hash_result = hash_dns_name(ctx, question_name_offset, pkt_len, &mut hasher).ok_or(())?;
    let domain_hash: [u8; 16] = hash_result.hash;

    // Skip past QTYPE + QCLASS for the first question.
    pos = hash_result.end_offset + 4;

    // Skip remaining questions (if any).
    for q in 1..MAX_QUESTIONS {
        if q >= qdcount as usize {
            break;
        }
        let name_end = skip_dns_name(ctx, pos, pkt_len).ok_or(())?;
        pos = name_end + 4;
    }

    // Check if this domain is one we're tracking. If not, skip entirely —
    // no ring buffer event, no wasted bandwidth.
    let tracked = unsafe { TRACKED_DOMAINS.get(&domain_hash) };
    if tracked.is_none() {
        return Ok(()); // Not a tracked domain, silently ignore
    }

    // Parse answer section for A and AAAA records.
    for a in 0..MAX_ANSWERS {
        if a >= ancount as usize {
            break;
        }
        if pos >= pkt_len {
            break;
        }

        let name_end = skip_dns_name(ctx, pos, pkt_len).ok_or(())?;
        pos = name_end;

        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes.
        let rtype = load_u16_be(ctx, pos).ok_or(())?;
        let rclass = load_u16_be(ctx, pos + 2).ok_or(())?;
        let ttl = load_u32_be(ctx, pos + 4).ok_or(())?;
        let rdlength = load_u16_be(ctx, pos + 8).ok_or(())?;
        pos += 10;

        if rclass != DNS_CLASS_IN {
            pos += rdlength as usize;
            continue;
        }

        if rtype == DNS_TYPE_A && rdlength == 4 {
            if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
                let ev = entry.as_mut_ptr();
                unsafe {
                    zero_dns_event(ev);
                    (*ev).event_type = EventType::DnsResponse as u32;
                    (*ev).ttl = ttl;
                    (*ev).record_type = DNS_TYPE_A as u8;
                    (*ev).domain_hash = domain_hash;

                    let mut ok = true;
                    for k in 0..4 {
                        if let Some(b) = load_byte(ctx, pos + k) {
                            (*ev).addr_v4[k] = b;
                        } else {
                            ok = false;
                            break;
                        }
                    }

                    if !ok {
                        entry.discard(0);
                    } else {
                        entry.submit(0);
                    }
                }
            }
        } else if rtype == DNS_TYPE_AAAA && rdlength == 16 {
            if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEvent>(0) {
                let ev = entry.as_mut_ptr();
                unsafe {
                    zero_dns_event(ev);
                    (*ev).event_type = EventType::DnsResponse as u32;
                    (*ev).ttl = ttl;
                    (*ev).record_type = DNS_TYPE_AAAA as u8;
                    (*ev).domain_hash = domain_hash;

                    let mut ok = true;
                    for k in 0..16 {
                        if let Some(b) = load_byte(ctx, pos + k) {
                            (*ev).addr_v6[k] = b;
                        } else {
                            ok = false;
                            break;
                        }
                    }

                    if !ok {
                        entry.discard(0);
                    } else {
                        entry.submit(0);
                    }
                }
            }
        }

        pos += rdlength as usize;
    }

    Ok(())
}

/// Zero-initialize a DnsEvent at a raw pointer (ring buffer memory).
#[inline(always)]
unsafe fn zero_dns_event(ev: *mut DnsEvent) {
    (*ev).timestamp_ns = 0;
    (*ev).pid = 0;
    (*ev).uid = 0;
    (*ev).event_type = 0;
    (*ev).ttl = 0;
    (*ev).domain_hash = [0u8; 16];
    (*ev).record_type = 0;
    (*ev)._pad = [0; 3];
    for i in 0..4 {
        (*ev).addr_v4[i] = 0;
    }
    for i in 0..16 {
        (*ev).addr_v6[i] = 0;
    }
}
