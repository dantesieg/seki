//! Routable QUIC connection IDs, following draft-ietf-quic-load-balancers
//! ("QUIC-LB"), encrypted mode.
//!
//! Byte format of a CID (length = 1 + server_id_len + nonce_len, at most 20):
//!
//! ```text
//! byte 0 : CCC LLLLL   C = config id (0..=6, 7 means unroutable)
//!                      L = CID length - 1 (self-describing length)
//! 1..    : AES-128 encryption of (server_id || nonce)
//! ```
//!
//! When `server_id_len + nonce_len == 16` the plaintext is one AES block
//! (single-pass ECB). Otherwise (shorter) a four-pass Feistel network built on
//! AES-128-ECB is used, as specified in the draft. The nonce must be unique per
//! CID (random or counter); it should be at least 4 bytes.
//!
//! The generator is stateless: any replica holding the same [`Config`] can
//! encode and decode. Stateless-reset tokens are derived with
//! [`reset_token`] = HMAC-SHA256(reset_secret, cid)[..16].

use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};

pub const MAX_CID_LEN: usize = 20;
/// Config id reserved for unroutable CIDs.
pub const UNROUTABLE: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bad lengths or config id.
    InvalidConfig,
    /// Server id or nonce length does not match the config.
    BadLength,
    /// CID is not routable under this config.
    NotRoutable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::InvalidConfig => "invalid seki-cid config",
            Error::BadLength => "server id or nonce length mismatch",
            Error::NotRoutable => "connection id not routable",
        })
    }
}
impl std::error::Error for Error {}

/// One routing configuration, shared by the router and all backends.
#[derive(Clone)]
pub struct Config {
    config_id: u8,
    server_id_len: usize,
    nonce_len: usize,
    cipher: Aes128,
}

impl Config {
    /// `config_id` 0..=6; `server_id_len` >= 1; `nonce_len` >= 4;
    /// `server_id_len + nonce_len` <= 16 (one AES block).
    pub fn new(config_id: u8, server_id_len: usize, nonce_len: usize, key: &[u8; 16]) -> Result<Self, Error> {
        if config_id >= UNROUTABLE || server_id_len == 0 || nonce_len < 4 || server_id_len + nonce_len > 16 {
            return Err(Error::InvalidConfig);
        }
        Ok(Config { config_id, server_id_len, nonce_len, cipher: Aes128::new(&Array(*key)) })
    }

    pub fn config_id(&self) -> u8 { self.config_id }
    pub fn server_id_len(&self) -> usize { self.server_id_len }
    pub fn nonce_len(&self) -> usize { self.nonce_len }
    /// Total CID length in bytes.
    pub fn cid_len(&self) -> usize { 1 + self.server_id_len + self.nonce_len }

    /// Build a CID for `server_id` with the given unique `nonce`.
    /// Returns the CID in a fixed buffer; use `&out[..cfg.cid_len()]`.
    pub fn encode(&self, server_id: &[u8], nonce: &[u8]) -> Result<[u8; MAX_CID_LEN], Error> {
        if server_id.len() != self.server_id_len || nonce.len() != self.nonce_len {
            return Err(Error::BadLength);
        }
        let len = self.cid_len();
        let mut out = [0u8; MAX_CID_LEN];
        out[0] = (self.config_id << 5) | (len as u8 - 1);
        let pt_len = len - 1;
        out[1..1 + self.server_id_len].copy_from_slice(server_id);
        out[1 + self.server_id_len..len].copy_from_slice(nonce);
        if pt_len == 16 {
            let mut b = Array::<u8, _>::default();
            b.copy_from_slice(&out[1..17]);
            self.cipher.encrypt_block(&mut b);
            out[1..17].copy_from_slice(&b);
        } else {
            self.feistel(&mut out[1..len], true);
        }
        Ok(out)
    }

    /// Server id encoded as a big-endian integer (convenience).
    pub fn encode_u64(&self, server_id: u64, nonce: &[u8]) -> Result<[u8; MAX_CID_LEN], Error> {
        let be = server_id.to_be_bytes();
        if self.server_id_len < 8 && server_id >> (8 * self.server_id_len) != 0 {
            return Err(Error::BadLength);
        }
        let sid = if self.server_id_len >= 8 { &be[..] } else { &be[8 - self.server_id_len..] };
        if sid.len() != self.server_id_len {
            return Err(Error::BadLength);
        }
        self.encode(sid, nonce)
    }

    /// Decode the server id from a CID (or from the start of a short-header
    /// DCID field; extra trailing bytes are ignored). Returns the server id
    /// bytes in a fixed buffer, valid for `server_id_len` bytes.
    pub fn decode(&self, cid: &[u8]) -> Result<[u8; 16], Error> {
        let len = self.cid_len();
        if cid.len() < len || cid[0] >> 5 != self.config_id || (cid[0] & 0x1f) as usize != len - 1 {
            return Err(Error::NotRoutable);
        }
        let mut buf = [0u8; 16];
        let pt_len = len - 1;
        buf[..pt_len].copy_from_slice(&cid[1..len]);
        if pt_len == 16 {
            let mut b = Array(buf);
            self.cipher.decrypt_block(&mut b);
            buf = b.0;
        } else {
            self.feistel(&mut buf[..pt_len], false);
        }
        let mut sid = [0u8; 16];
        sid[..self.server_id_len].copy_from_slice(&buf[..self.server_id_len]);
        Ok(sid)
    }

    /// Decode the server id as a big-endian integer (server_id_len <= 8).
    pub fn decode_u64(&self, cid: &[u8]) -> Result<u64, Error> {
        let sid = self.decode(cid)?;
        let n = self.server_id_len.min(8);
        Ok(sid[..n].iter().fold(0u64, |a, &b| (a << 8) | b as u64))
    }

    fn aes(&self, half: &[u8], pt_len: usize, pass: u8) -> [u8; 16] {
        // expand(): half || zero padding || plaintext_len || pass
        let mut b = Array::<u8, _>::default();
        b[..half.len()].copy_from_slice(half);
        b[14] = pt_len as u8;
        b[15] = pass;
        self.cipher.encrypt_block(&mut b);
        b.0
    }

    /// Four-pass Feistel over `data` (< 16 bytes), per QUIC-LB.
    fn feistel(&self, data: &mut [u8], encrypt: bool) {
        let n = data.len();
        let h = n.div_ceil(2);
        let odd = n % 2 == 1;
        let mut left = [0u8; 8];
        let mut right = [0u8; 8];
        left[..h].copy_from_slice(&data[..h]);
        right[..h].copy_from_slice(&data[n - h..]);
        if odd {
            left[h - 1] &= 0xf0;
            right[0] &= 0x0f;
        }
        let mask_l = |x: &mut [u8; 8]| if odd { x[h - 1] &= 0xf0 };
        let mask_r = |x: &mut [u8; 8]| if odd { x[0] &= 0x0f };
        let xor = |dst: &mut [u8; 8], src: &[u8; 8], pass: u8, is_right: bool| {
            let e = self.aes(&src[..h], n, pass);
            let mut t = [0u8; 8];
            t[..h].copy_from_slice(&e[..h]);
            if is_right { mask_r(&mut t) } else { mask_l(&mut t) }
            for i in 0..h { dst[i] ^= t[i]; }
        };
        if encrypt {
            xor(&mut right, &left, 1, true);
            xor(&mut left, &right, 2, false);
            xor(&mut right, &left, 3, true);
            xor(&mut left, &right, 4, false);
        } else {
            xor(&mut left, &right, 4, false);
            xor(&mut right, &left, 3, true);
            xor(&mut left, &right, 2, false);
            xor(&mut right, &left, 1, true);
        }
        data[..h].copy_from_slice(&left[..h]);
        if odd {
            data[h - 1] = left[h - 1] | right[0];
            data[h..].copy_from_slice(&right[1..h]);
        } else {
            data[h..].copy_from_slice(&right[..h]);
        }
    }
}

/// Stateless-reset token for a CID: HMAC-SHA256(reset_secret, cid)[..16].
pub fn reset_token(reset_secret: &[u8], cid: &[u8]) -> [u8; 16] {
    let mut m = <Hmac<sha2::Sha256> as hmac::KeyInit>::new_from_slice(reset_secret).expect("hmac accepts any key length");
    m.update(cid);
    let out = m.finalize().into_bytes();
    let mut t = [0u8; 16];
    t.copy_from_slice(&out[..16]);
    t
}

/// Parse a 32-hex-character key (whitespace trimmed).
pub fn parse_key_hex(s: &str) -> Result<[u8; 16], Error> {
    let s = s.trim();
    if s.len() != 32 {
        return Err(Error::InvalidConfig);
    }
    let mut k = [0u8; 16];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| Error::InvalidConfig)?;
    }
    Ok(k)
}
