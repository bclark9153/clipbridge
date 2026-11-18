//! Authenticated, encrypted framing over TCP.
//!
//! Both sides share a passphrase, stretched into a 32-byte key with
//! PBKDF2-HMAC-SHA256. On connect, each side sends a magic tag and 32 random
//! bytes. Per-direction session keys are derived from the stretched key plus
//! both random values, so keys never repeat across connections. Frames are
//! ChaCha20-Poly1305 sealed with a per-direction counter nonce. A wrong
//! passphrase shows up as a failure to open the first frame.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Protocol tag. Bumped whenever old and new versions can't talk to each other.
pub const MAGIC: &[u8; 4] = b"CBR2";
/// Absolute ceiling on a single frame, whatever the configured limit.
pub const MAX_FRAME: usize = 1024 * 1024 * 1024;
/// Frame limit until the peer has proved it knows the key. The first frame is
/// always the small Hello, so a stranger can't make us allocate much memory.
pub const HELLO_FRAME_LIMIT: usize = 4 * 1024;

const PSK_SALT: &[u8] = b"clipbridge-v2-psk";
const PSK_ITERATIONS: u32 = 600_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Listener,
    Connector,
}

pub struct Sealer {
    cipher: ChaCha20Poly1305,
    counter: u64,
}
pub struct Opener {
    cipher: ChaCha20Poly1305,
    counter: u64,
    max_frame: usize,
}

fn nonce(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

impl Sealer {
    pub fn write_frame(&mut self, w: &mut impl Write, plaintext: &[u8]) -> io::Result<()> {
        let ct = self
            .cipher
            .encrypt(&nonce(self.counter), plaintext)
            .map_err(|_| io::Error::other("encrypt failed"))?;
        self.counter += 1;
        w.write_all(&(ct.len() as u32).to_be_bytes())?;
        w.write_all(&ct)?;
        w.flush()
    }
}

impl Opener {
    /// Change the largest frame this side accepts (never above `MAX_FRAME`).
    pub fn set_max_frame(&mut self, n: usize) {
        self.max_frame = n.min(MAX_FRAME);
    }

    pub fn read_frame(&mut self, r: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > self.max_frame {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large ({len} bytes, limit {})", self.max_frame),
            ));
        }
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct)?;
        let pt = self.cipher.decrypt(&nonce(self.counter), ct.as_slice()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "could not decrypt frame: the two machines have different keys (pair again with --pair)",
            )
        })?;
        self.counter += 1;
        Ok(pt)
    }
}

/// Stretch the passphrase into the pre-shared key. Deliberately slow (it runs
/// once at startup) so a recorded handshake can't be brute-forced cheaply.
pub fn psk_from_passphrase(pass: &str) -> [u8; 32] {
    pbkdf2_sha256(pass.as_bytes(), PSK_SALT, PSK_ITERATIONS)
}

/// HMAC-SHA256 (RFC 2104) with the padded key already absorbed, so each use
/// only hashes the message.
pub(crate) struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 64];
        if key.len() > block.len() {
            block[..32].copy_from_slice(Sha256::digest(key).as_slice());
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= block[i];
            opad[i] ^= block[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        let mut outer = Sha256::new();
        outer.update(opad);
        Hmac { inner, outer }
    }

    pub(crate) fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        for p in parts {
            inner.update(*p);
        }
        let mut outer = self.outer.clone();
        outer.update(inner.finalize());
        outer.finalize().into()
    }
}

/// PBKDF2 (RFC 8018) with HMAC-SHA256, producing a single 32-byte block.
fn pbkdf2_sha256(pass: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let prf = Hmac::new(pass);
    let block_index = 1u32.to_be_bytes();
    let mut u = prf.mac(&[salt, &block_index[..]]);
    let mut out = u;
    for _ in 1..iterations {
        u = prf.mac(&[&u[..]]);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= *x;
        }
    }
    out
}

fn derive(psk: &[u8; 32], c_rand: &[u8], s_rand: &[u8], dir: &[u8]) -> ChaCha20Poly1305 {
    let mut h = Sha256::new();
    h.update(psk);
    h.update(c_rand);
    h.update(s_rand);
    h.update(dir);
    let k: [u8; 32] = h.finalize().into();
    ChaCha20Poly1305::new(Key::from_slice(&k))
}

pub fn handshake(stream: &mut TcpStream, role: Role, psk: &[u8; 32]) -> io::Result<(Sealer, Opener)> {
    let mut mine = [0u8; 32];
    getrandom::getrandom(&mut mine).map_err(|e| io::Error::other(e.to_string()))?;
    let mut hello = Vec::with_capacity(36);
    hello.extend_from_slice(MAGIC);
    hello.extend_from_slice(&mine);
    stream.write_all(&hello)?;

    let mut theirs = [0u8; 36];
    stream.read_exact(&mut theirs)?;
    if &theirs[..4] != MAGIC {
        let msg = if &theirs[..4] == crate::pair::MAGIC {
            "peer wants to pair, but this machine already has a key (start it with --pair to pair again)"
        } else {
            "peer is not ClipBridge v2 (both machines must run the same version)"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
    }
    let theirs = &theirs[4..];

    let (c_rand, s_rand): (&[u8], &[u8]) = match role {
        Role::Connector => (&mine, theirs),
        Role::Listener => (theirs, &mine),
    };
    let c2s = derive(psk, c_rand, s_rand, b"c2s");
    let s2c = derive(psk, c_rand, s_rand, b"s2c");
    let (tx, rx) = match role {
        Role::Connector => (c2s, s2c),
        Role::Listener => (s2c, c2s),
    };
    Ok((
        Sealer { cipher: tx, counter: 0 },
        Opener { cipher: rx, counter: 0, max_frame: HELLO_FRAME_LIMIT },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn pair(key_a: &str, key_b: &str) -> (io::Result<Vec<u8>>, io::Result<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let pa = psk_from_passphrase(key_a);
        let pb = psk_from_passphrase(key_b);
        let t = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let (mut tx, mut rx) = handshake(&mut s, Role::Listener, &pa).unwrap();
            tx.write_frame(&mut s, b"from-listener").unwrap();
            rx.read_frame(&mut s)
        });
        let mut s = TcpStream::connect(addr).unwrap();
        let (mut tx, mut rx) = handshake(&mut s, Role::Connector, &pb).unwrap();
        tx.write_frame(&mut s, b"from-connector").unwrap();
        let got = rx.read_frame(&mut s);
        (got, t.join().unwrap())
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn matching_keys_talk() {
        let (a, b) = pair("correct horse", "correct horse");
        assert_eq!(a.unwrap(), b"from-listener");
        assert_eq!(b.unwrap(), b"from-connector");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (a, b) = pair("correct horse", "battery staple");
        assert!(a.is_err() && b.is_err());
    }

    #[test]
    fn hmac_matches_rfc4231() {
        // Test case 2: short key.
        let mac = Hmac::new(b"Jefe").mac(&[&b"what do ya want for nothing?"[..]]);
        assert_eq!(mac.to_vec(), hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        // Test case 6: a key longer than the block size is hashed first.
        let key = [0xaau8; 131];
        let mac = Hmac::new(&key).mac(&[&b"Test Using Larger Than Block-Size Key - Hash Key First"[..]]);
        assert_eq!(mac.to_vec(), hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }

    #[test]
    fn pbkdf2_matches_known_vectors() {
        assert_eq!(
            pbkdf2_sha256(b"password", b"salt", 1).to_vec(),
            hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        );
        assert_eq!(
            pbkdf2_sha256(b"password", b"salt", 4096).to_vec(),
            hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
    }

    #[test]
    fn psk_is_deterministic_and_key_dependent() {
        let a = psk_from_passphrase("correct horse battery");
        assert_eq!(a, psk_from_passphrase("correct horse battery"));
        assert_ne!(a, psk_from_passphrase("correct horse batterz"));
    }

    #[test]
    fn oversized_frame_is_refused_before_allocating() {
        let mut o = Opener {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&[7u8; 32])),
            counter: 0,
            max_frame: HELLO_FRAME_LIMIT,
        };
        let mut input: &[u8] = &(512u32 * 1024 * 1024).to_be_bytes();
        let err = o.read_frame(&mut input).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
