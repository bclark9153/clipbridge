//! One-time pairing with a short code shown on the listening machine.
//!
//! The code is only six digits, so it must never be usable offline: the two
//! sides run SPAKE2 (a password-authenticated key exchange, Ed25519 group) with
//! the code as the password. A wrong guess only shows up as a failed key
//! confirmation, one guess per connection, and the listener picks a new code
//! after every failure. From the agreed key both sides derive the long-term
//! key that the normal sessions then use, and store it locally.
//!
//! Wire layout (plaintext, before any session exists):
//!   client -> server:  "CBP1", u8 len, SPAKE2 message A
//!   server -> client:  "CBP1", u8 len, SPAKE2 message B
//!   client -> server:  32-byte confirmation
//!   server -> client:  32-byte confirmation (nothing, and close, if the code was wrong)

use crate::net::Hmac;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{self, Read, Write};
use std::net::TcpStream;

pub const MAGIC: &[u8; 4] = b"CBP1";
const ID_CLIENT: &[u8] = b"clipbridge-pair-client";
const ID_SERVER: &[u8] = b"clipbridge-pair-server";
pub const CODE_DIGITS: usize = 6;

/// A fresh random six-digit code, as digits only.
pub fn new_code() -> String {
    loop {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).expect("random");
        let n = u32::from_be_bytes(b);
        // Reject the top of the range so every code is equally likely.
        if n < 4_000_000_000 {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

/// "483 912" for display.
pub fn pretty(code: &str) -> String {
    if code.len() == CODE_DIGITS {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

/// Keep only the digits of what the user typed ("483 912", "483-912" ...).
pub fn normalize(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_digit()).collect()
}

struct Keys {
    confirm_client: [u8; 32],
    confirm_server: [u8; 32],
    long_term: [u8; 32],
}

impl Keys {
    fn derive(shared: &[u8]) -> Keys {
        let prf = Hmac::new(shared);
        Keys {
            confirm_client: prf.mac(&[b"confirm-client"]),
            confirm_server: prf.mac(&[b"confirm-server"]),
            long_term: prf.mac(&[b"long-term-key"]),
        }
    }
}

fn write_msg(w: &mut impl Write, msg: &[u8]) -> io::Result<()> {
    let len = u8::try_from(msg.len()).map_err(|_| io::Error::other("pairing message too long"))?;
    w.write_all(&[len])?;
    w.write_all(msg)?;
    w.flush()
}

fn read_msg(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 1];
    r.read_exact(&mut len)?;
    let mut msg = vec![0u8; len[0] as usize];
    r.read_exact(&mut msg)?;
    Ok(msg)
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn wrong_code() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "wrong pairing code")
}

/// Pair as the machine that typed the code. Returns the long-term key.
pub fn client(stream: &mut TcpStream, code: &str) -> io::Result<[u8; 32]> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_a(
        &Password::new(code.as_bytes()),
        &Identity::new(ID_CLIENT),
        &Identity::new(ID_SERVER),
    );
    stream.write_all(MAGIC)?;
    write_msg(stream, &outbound)?;

    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        let msg = if &magic == crate::net::MAGIC {
            "the other machine is already paired; restart it with `clipbridge listen --pair` to pair again"
        } else {
            "the other machine did not answer a pairing request"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
    }
    let inbound = read_msg(stream)?;
    let shared = state.finish(&inbound).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad pairing message"))?;
    let keys = Keys::derive(&shared);

    stream.write_all(&keys.confirm_client)?;
    stream.flush()?;
    let mut theirs = [0u8; 32];
    match stream.read_exact(&mut theirs) {
        Ok(()) => {}
        // The server hangs up without answering when the code was wrong.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::ConnectionReset => {
            return Err(wrong_code());
        }
        Err(e) => return Err(e),
    }
    if !constant_time_eq(&theirs, &keys.confirm_server) {
        return Err(wrong_code());
    }
    Ok(keys.long_term)
}

/// Pair as the machine showing the code. Reads the peer's first bytes itself:
/// a peer that opens a normal session instead gets a `ConnectionRefused` error
/// here, and a wrong code is `PermissionDenied`.
pub fn server(stream: &mut TcpStream, code: &str) -> io::Result<[u8; 32]> {
    let mut magic = [0u8; 4];
    stream.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "peer tried to open a session, but this machine isn't paired yet",
        ));
    }
    let inbound = read_msg(stream)?;
    let (state, outbound) = Spake2::<Ed25519Group>::start_b(
        &Password::new(code.as_bytes()),
        &Identity::new(ID_CLIENT),
        &Identity::new(ID_SERVER),
    );
    stream.write_all(MAGIC)?;
    write_msg(stream, &outbound)?;
    let shared = state.finish(&inbound).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad pairing message"))?;
    let keys = Keys::derive(&shared);

    let mut theirs = [0u8; 32];
    stream.read_exact(&mut theirs)?;
    if !constant_time_eq(&theirs, &keys.confirm_client) {
        // Say nothing: the caller closes the connection and shows a new code.
        return Err(wrong_code());
    }
    stream.write_all(&keys.confirm_server)?;
    stream.flush()?;
    Ok(keys.long_term)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn pair_with(code_server: &str, code_client: &str) -> (io::Result<[u8; 32]>, io::Result<[u8; 32]>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let cs = code_server.to_string();
        let t = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            server(&mut s, &cs)
        });
        let mut s = TcpStream::connect(addr).unwrap();
        let got = client(&mut s, code_client);
        drop(s);
        (got, t.join().unwrap())
    }

    #[test]
    fn same_code_agrees_on_a_key() {
        let (c, s) = pair_with("483912", "483912");
        let c = c.unwrap();
        assert_eq!(c, s.unwrap());
        assert_ne!(c, [0u8; 32]);
    }

    #[test]
    fn wrong_code_is_rejected_on_both_sides() {
        let (c, s) = pair_with("483912", "483913");
        assert_eq!(s.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(c.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn codes_are_six_digits_and_random() {
        let a = new_code();
        let b = new_code();
        assert_eq!(a.len(), 6);
        assert!(a.chars().all(|c| c.is_ascii_digit()));
        assert!(a != b || new_code() != a);
        assert_eq!(normalize(" 483-912 "), "483912");
        assert_eq!(pretty("483912"), "483 912");
    }
}
