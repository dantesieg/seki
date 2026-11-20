//! Initial marks: a keyed tag hidden in the client-chosen Destination
//! Connection ID of a QUIC Initial, so a router can tell its own clients from
//! probes before any server-issued CID exists.
//!
//! ```text
//! dcid[0..4]  random nonce
//! dcid[4..8]  AES-128(key, "SKMK" || nonce || be64(unix_secs / 60))[..4]
//! dcid[8..]   random (optional; total DCID length 8..=20)
//! ```
//!
//! The DCID still looks uniformly random. A tag is valid for the current
//! minute and one minute either side (clock skew). It does not stop replay of a
//! captured Initial on its own: the router must also remember accepted DCIDs
//! for [`REPLAY_WINDOW_SECS`] and reject one seen from another client address.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

/// Bytes of the DCID the mark occupies (minimum DCID length).
pub const MARK_LEN: usize = 8;
/// How long a mark can be accepted: buckets b-1..=b+1 of 60 s.
pub const REPLAY_WINDOW_SECS: u64 = 180;

#[derive(Clone)]
pub struct MarkKey(Aes128);

impl MarkKey {
    /// Use a key separate from the CID key.
    pub fn new(key: &[u8; 16]) -> Self {
        MarkKey(Aes128::new(&Array(*key)))
    }

    fn tag(&self, nonce: &[u8], bucket: u64) -> [u8; 4] {
        let mut b = Array::<u8, _>::default();
        b[..4].copy_from_slice(b"SKMK");
        b[4..8].copy_from_slice(nonce);
        b[8..].copy_from_slice(&bucket.to_be_bytes());
        self.0.encrypt_block(&mut b);
        [b[0], b[1], b[2], b[3]]
    }

    /// Write a mark into `dcid[..MARK_LEN]` using `dcid[..4]` as the nonce
    /// (fill the whole DCID with random bytes first). `dcid` must be 8..=20 bytes.
    pub fn stamp(&self, dcid: &mut [u8], unix_secs: u64) {
        assert!((MARK_LEN..=crate::MAX_CID_LEN).contains(&dcid.len()), "dcid must be 8..=20 bytes");
        let t = self.tag(&dcid[..4], unix_secs / 60);
        dcid[4..8].copy_from_slice(&t);
    }

    /// True if `dcid` carries a mark valid at `unix_secs` (±1 minute).
    pub fn check(&self, dcid: &[u8], unix_secs: u64) -> bool {
        if !(MARK_LEN..=crate::MAX_CID_LEN).contains(&dcid.len()) {
            return false;
        }
        let b = unix_secs / 60;
        let mut ok = 0u8;
        for bucket in [b.saturating_sub(1), b, b + 1] {
            let t = self.tag(&dcid[..4], bucket);
            ok |= (t.iter().zip(&dcid[4..8]).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0) as u8;
        }
        ok == 1
    }
}

