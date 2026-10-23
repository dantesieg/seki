//! QUIC Initial packet decryption (RFC 9001 / RFC 9369) and SNI extraction.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub const V1: u32 = 1;
pub const V2: u32 = 0x6b33_43cf;

const SALT_V1: [u8; 20] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];
const SALT_V2: [u8; 20] = [0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9];

pub fn read_varint(b: &[u8], p: &mut usize) -> Option<u64> {
    let first = *b.get(*p)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*p..*p + len)?;
    let mut v = (first & 0x3f) as u64;
    for &x in &bytes[1..] {
        v = (v << 8) | x as u64;
    }
    *p += len;
    Some(v)
}

/// Long header type bits that mean Initial for this version.
pub fn is_initial(first: u8, version: u32) -> bool {
    let t = (first >> 4) & 3;
    match version {
        V1 => t == 0,
        V2 => t == 1,
        _ => false,
    }
}

fn expand_label(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    hk.expand(&info, out).expect("valid hkdf length");
}

struct Keys {
    aead: Aes128Gcm,
    iv: [u8; 12],
    hp: Aes128,
}

fn client_keys(version: u32, dcid: &[u8]) -> Keys {
    let (salt, pfx) = if version == V2 { (&SALT_V2, "quicv2 ") } else { (&SALT_V1, "quic ") };
    let (_, initial) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, "client in", &mut secret);
    let hk = Hkdf::<Sha256>::from_prk(&secret).expect("prk length");
    let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand_label(&hk, &format!("{pfx}key"), &mut key);
    expand_label(&hk, &format!("{pfx}iv"), &mut iv);
    expand_label(&hk, &format!("{pfx}hp"), &mut hp);
    Keys { aead: Aes128Gcm::new(&Array(key)), iv, hp: Aes128::new(&Array(hp)) }
}

/// Decrypt every client Initial packet in a datagram (coalesced packets
/// supported) and feed CRYPTO frame data into `crypto`.
pub fn collect_crypto(dgram: &[u8], crypto: &mut CryptoBuf) -> bool {
    let mut off = 0;
    let mut any = false;
    while off < dgram.len() {
        match decrypt_one(&dgram[off..], crypto) {
            Some((used, ok)) => {
                any |= ok;
                off += used;
            }
            None => break,
        }
    }
    any
}

/// Returns (bytes consumed, decrypted ok).
fn decrypt_one(pkt: &[u8], crypto: &mut CryptoBuf) -> Option<(usize, bool)> {
    let first = *pkt.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(pkt.get(1..5)?.try_into().ok()?);
    let mut p = 5;
    let dl = *pkt.get(p)? as usize;
    let dcid = pkt.get(p + 1..p + 1 + dl)?;
    p += 1 + dl;
    let sl = *pkt.get(p)? as usize;
    p += 1 + sl;
    let initial = is_initial(first, version);
    if initial {
        let tl = read_varint(pkt, &mut p)? as usize;
        p += tl;
    }
    let len = read_varint(pkt, &mut p)? as usize;
    let pn_off = p;
    let end = pn_off.checked_add(len)?;
    if end > pkt.len() {
        return None;
    }
    if !initial || len < 20 {
        return Some((end, false));
    }
    let keys = client_keys(version, dcid);
    let mut mask = Array::<u8, _>::default();
    mask.copy_from_slice(&pkt[pn_off + 4..pn_off + 20]);
    keys.hp.encrypt_block(&mut mask);
    let mut hdr = pkt[..pn_off + 4].to_vec();
    hdr[0] ^= mask[0] & 0x0f;
    let pn_len = (hdr[0] & 3) as usize + 1;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        hdr[pn_off + i] ^= mask[1 + i];
        pn = (pn << 8) | hdr[pn_off + i] as u64;
    }
    hdr.truncate(pn_off + pn_len);
    let mut nonce = keys.iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let mut payload = pkt[pn_off + pn_len..end].to_vec();
    if keys.aead.decrypt_in_place(&Nonce::from(nonce), &hdr, &mut payload).is_err() {
        return Some((end, false));
    }
    parse_frames(&payload, crypto);
    Some((end, true))
}

fn parse_frames(b: &[u8], crypto: &mut CryptoBuf) {
    let mut p = 0;
    while p < b.len() {
        let Some(t) = read_varint(b, &mut p) else { return };
        match t {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                let mut f = || -> Option<()> {
                    read_varint(b, &mut p)?;
                    read_varint(b, &mut p)?;
                    let n = read_varint(b, &mut p)?;
                    read_varint(b, &mut p)?;
                    for _ in 0..n {
                        read_varint(b, &mut p)?;
                        read_varint(b, &mut p)?;
                    }
                    if t == 0x03 {
                        for _ in 0..3 {
                            read_varint(b, &mut p)?;
                        }
                    }
                    Some(())
                };
                if f().is_none() {
                    return;
                }
            }
            0x06 => {
                let (Some(o), Some(l)) = (read_varint(b, &mut p), read_varint(b, &mut p)) else { return };
                let Some(d) = b.get(p..p + l as usize) else { return };
                crypto.add(o as usize, d);
                p += l as usize;
            }
            _ => return,
        }
    }
}

/// Reassembles CRYPTO stream bytes (out-of-order fragments allowed).
#[derive(Default)]
pub struct CryptoBuf {
    data: Vec<u8>,
    have: Vec<bool>,
}

const MAX_CRYPTO: usize = 16 * 1024;

impl CryptoBuf {
    fn add(&mut self, off: usize, d: &[u8]) {
        let end = off + d.len();
        if end > MAX_CRYPTO {
            return;
        }
        if self.data.len() < end {
            self.data.resize(end, 0);
            self.have.resize(end, false);
        }
        self.data[off..end].copy_from_slice(d);
        self.have[off..end].iter_mut().for_each(|h| *h = true);
    }

    fn contiguous(&self) -> &[u8] {
        let n = self.have.iter().position(|h| !h).unwrap_or(self.have.len());
        &self.data[..n]
    }

    /// Ok(Some(sni)), Ok(None) = ClientHello without SNI, Err(()) = need more.
    pub fn sni(&self) -> Result<Option<String>, ()> {
        parse_client_hello(self.contiguous())
    }
}

fn parse_client_hello(b: &[u8]) -> Result<Option<String>, ()> {
    let u16at = |p: usize| -> Result<usize, ()> { Ok(u16::from_be_bytes(b.get(p..p + 2).ok_or(())?.try_into().unwrap()) as usize) };
    if *b.first().ok_or(())? != 1 {
        return Ok(None);
    }
    let mut p = 4 + 2 + 32;
    p += 1 + *b.get(p).ok_or(())? as usize;
    p += 2 + u16at(p)?;
    p += 1 + *b.get(p).ok_or(())? as usize;
    let ext_end = p + 2 + u16at(p)?;
    p += 2;
    while p + 4 <= ext_end {
        let ty = u16at(p)?;
        let len = u16at(p + 2)?;
        p += 4;
        if ty == 0 {
            let mut q = p + 2;
            while q + 3 <= p + len {
                let nt = *b.get(q).ok_or(())?;
                let nl = u16at(q + 1)?;
                let name = b.get(q + 3..q + 3 + nl).ok_or(())?;
                if nt == 0 {
                    return Ok(std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase()));
                }
                q += 3 + nl;
            }
            return Ok(None);
        }
        p += len;
    }
    if p >= ext_end && b.len() >= ext_end { Ok(None) } else { Err(()) }
}
