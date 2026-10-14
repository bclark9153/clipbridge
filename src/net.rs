//! Authenticated, encrypted framing over TCP.
//!
//! Both sides share a passphrase. On connect, each side sends a magic tag and
//! 32 random bytes. Per-direction session keys are derived from the passphrase
//! plus both random values, so keys never repeat across connections. Frames are
//! ChaCha20-Poly1305 sealed with a per-direction counter nonce. A wrong
//! passphrase shows up as a failure to open the first frame.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::TcpStream;

const MAGIC: &[u8; 4] = b"CBR1";
/// Hard ceiling on a single frame, to bound memory from a misbehaving peer.
pub const MAX_FRAME: usize = 1024 * 1024 * 1024;

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
    pub fn read_frame(&mut self, r: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut ct = vec![0u8; len];
        r.read_exact(&mut ct)?;
        let pt = self.cipher.decrypt(&nonce(self.counter), ct.as_slice()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "could not decrypt frame (passphrase mismatch?)",
            )
        })?;
        self.counter += 1;
        Ok(pt)
    }
}

pub fn psk_from_passphrase(pass: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"clipbridge-v1-psk");
    h.update(pass.as_bytes());
    h.finalize().into()
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
        return Err(io::Error::new(io::ErrorKind::InvalidData, "peer is not ClipBridge v1"));
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
    Ok((Sealer { cipher: tx, counter: 0 }, Opener { cipher: rx, counter: 0 }))
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
}
