//! ClipBridge — two-way clipboard sync (text, screenshots/images, files) between
//! two machines, designed to run alongside a remote-desktop app like Jump Desktop.
//!
//!   Mac:      clipbridge listen  --key-file ~/.config/clipbridge/key
//!   Windows:  clipbridge connect <mac-host> --key-file %LOCALAPPDATA%\ClipBridge\key.txt

mod clip;
mod net;
mod proto;

use clap::{Parser, Subcommand};
use proto::{Content, Message};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_PORT: u16 = 47800;
const PING_EVERY: Duration = Duration::from_secs(15);
const PEER_TIMEOUT: Duration = Duration::from_secs(45);
/// How long a new connection gets to complete the handshake and say Hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Listener connections allowed to be unauthenticated (pre-Hello) at once.
const MAX_PENDING: usize = 8;
const MIN_KEY_CHARS: usize = 12;
const MB: usize = 1024 * 1024;

// ---------- logging ----------

static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

pub fn log_line(msg: String) {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let line = format!(
        "{:02}:{:02}:{:02}Z  {msg}\n",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    );
    let _ = io::stderr().write_all(line.as_bytes());
    if let Some(f) = LOG_FILE.get()
        && let Ok(mut f) = f.lock() {
            let _ = f.write_all(line.as_bytes());
        }
}

#[macro_export]
macro_rules! log {
    ($($t:tt)*) => { $crate::log_line(format!($($t)*)) };
}

// ---------- CLI ----------

#[derive(Parser)]
#[command(name = "clipbridge", version, about = "Two-way clipboard sync: text, screenshots and files")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Shared passphrase (same on both machines). Can also be set via CLIPBRIDGE_KEY.
    /// Prefer --key-file: a key on the command line is visible to other processes.
    #[arg(long, env = "CLIPBRIDGE_KEY", global = true, hide_env_values = true)]
    key: Option<String>,

    /// Read the shared passphrase from this file (trailing whitespace is ignored).
    /// Can also be set via CLIPBRIDGE_KEY_FILE.
    #[arg(long, env = "CLIPBRIDGE_KEY_FILE", global = true)]
    key_file: Option<PathBuf>,

    /// Name shown to the other side (defaults to the hostname).
    #[arg(long, global = true)]
    name: Option<String>,

    /// Also append log output to this file.
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    /// Where received files are saved (default: ~/ClipBridge Received).
    #[arg(long, global = true)]
    receive_dir: Option<PathBuf>,

    /// Largest total size of copied files to sync, in MB.
    #[arg(long, default_value_t = 200, global = true)]
    max_mb: usize,

    /// Clipboard check interval in milliseconds.
    #[arg(long, default_value_t = 250, global = true)]
    poll_ms: u64,

    /// Windows: detach from the console window so it can run hidden at logon.
    #[arg(long, global = true)]
    background: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Wait for the other machine to connect (run this on the Mac).
    Listen {
        /// Address to listen on.
        #[arg(default_value_t = format!("0.0.0.0:{DEFAULT_PORT}"))]
        bind: String,
    },
    /// Connect to the listening machine (run this on Windows). Reconnects automatically.
    Connect {
        /// Host or host:port of the listener, e.g. my-mac or 100.64.1.5:47800
        addr: String,
    },
    /// Print a random passphrase to use as --key.
    Genkey,
}

// ---------- shared state ----------

struct Shared {
    clip: Mutex<clip::Clip>,
    /// Hash of the content most recently sent or applied; stops echo loops.
    last_hash: Mutex<Option<[u8; 32]>>,
    /// OS change counter produced by our own write of remote content.
    own_change: Mutex<Option<u64>>,
    /// Outgoing queue of the active session (newest authenticated session wins).
    out: Mutex<Option<(u64, Sender<Message>)>>,
    next_id: AtomicU64,
    name: String,
    psk: [u8; 32],
    /// Largest frame sent or accepted once the peer has authenticated.
    max_frame: usize,
}

fn main() {
    let cli = Cli::parse();

    if let Cmd::Genkey = cli.cmd {
        let mut b = [0u8; 18];
        getrandom::getrandom(&mut b).expect("random");
        let key: String = b.iter().map(|x| format!("{x:02x}")).collect();
        println!("{key}");
        return;
    }

    if let Some(path) = &cli.log {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => {
                let _ = LOG_FILE.set(Mutex::new(f));
            }
            Err(e) => eprintln!("can't open log file {}: {e}", path.display()),
        }
    }

    let key = match load_key(&cli) {
        Ok(k) => k,
        Err(e) => {
            log!("{e}");
            std::process::exit(2);
        }
    };

    // Detach only after the checks above, so their errors still reach the console.
    if cli.background {
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Console::FreeConsole();
        }
    }

    let receive_dir = cli.receive_dir.clone().unwrap_or_else(default_receive_dir);
    let clip = match clip::Clip::new(receive_dir.clone(), cli.max_mb.saturating_mul(MB)) {
        Ok(c) => c,
        Err(e) => {
            log!("cannot open the clipboard: {e}");
            std::process::exit(1);
        }
    };

    let shared = Arc::new(Shared {
        clip: Mutex::new(clip),
        last_hash: Mutex::new(None),
        own_change: Mutex::new(None),
        out: Mutex::new(None),
        next_id: AtomicU64::new(1),
        // Kept short so the Hello always fits under net::HELLO_FRAME_LIMIT.
        name: cli.name.clone().unwrap_or_else(hostname).chars().take(200).collect(),
        psk: net::psk_from_passphrase(&key),
        max_frame: frame_limit(cli.max_mb),
    });

    log!("ClipBridge {} as \"{}\"; received files go to {}", env!("CARGO_PKG_VERSION"), shared.name, receive_dir.display());

    {
        let s = shared.clone();
        let poll = Duration::from_millis(cli.poll_ms.max(50));
        thread::spawn(move || watch_clipboard(s, poll));
    }

    match cli.cmd {
        Cmd::Listen { bind } => listen(&bind, shared),
        Cmd::Connect { addr } => connect_loop(&addr, shared),
        Cmd::Genkey => unreachable!(),
    }
}

/// The passphrase from --key or --key-file (or their environment variables).
fn load_key(cli: &Cli) -> Result<String, String> {
    let key_arg = cli.key.as_deref().filter(|k| !k.is_empty());
    let key_file = cli.key_file.as_deref().filter(|p| !p.as_os_str().is_empty());
    let key = match (key_arg, key_file) {
        (Some(_), Some(_)) => {
            return Err("Use either --key or --key-file, not both (check the CLIPBRIDGE_KEY and \
                        CLIPBRIDGE_KEY_FILE environment variables too)."
                .into());
        }
        (Some(k), None) => k.to_string(),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("can't read key file {}: {e}", path.display()))?;
            raw.trim_start_matches('\u{feff}').trim_end().to_string()
        }
        (None, None) => {
            return Err("A shared passphrase is required: --key-file <path> or --key <secret> \
                        (or CLIPBRIDGE_KEY_FILE / CLIPBRIDGE_KEY).\nGenerate one with: clipbridge genkey"
                .into());
        }
    };
    if key.chars().count() < MIN_KEY_CHARS {
        return Err(format!(
            "The passphrase must be at least {MIN_KEY_CHARS} characters. Generate a strong one with: clipbridge genkey"
        ));
    }
    Ok(key)
}

/// Frame size limit after authentication: room for --max-mb of files, or a
/// large screenshot (at least 256 MB), plus 1 MB for framing and names.
fn frame_limit(max_mb: usize) -> usize {
    max_mb.max(256).saturating_mul(MB).saturating_add(MB).min(net::MAX_FRAME)
}

fn default_receive_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join("ClipBridge Received")
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "clipbridge".into())
}

// ---------- local clipboard watcher ----------

fn watch_clipboard(shared: Arc<Shared>, poll: Duration) {
    let has_counter = clip::change_count().is_some();
    let mut last_seen = clip::change_count();
    // Baseline: whatever is on the clipboard at startup is not "new".
    if let Some(c) = shared.clip.lock().unwrap().read(true) {
        *shared.last_hash.lock().unwrap() = Some(c.hash());
    }
    let poll = if has_counter { poll } else { poll.max(Duration::from_secs(1)) };

    loop {
        thread::sleep(poll);
        let now = clip::change_count();
        if has_counter {
            if now == last_seen {
                continue;
            }
            last_seen = now;
            if now.is_some() && *shared.own_change.lock().unwrap() == now {
                continue; // this change was us applying remote content
            }
        }

        let content = shared.clip.lock().unwrap().read(has_counter);
        let Some(content) = content else { continue };
        let h = content.hash();
        {
            let mut last = shared.last_hash.lock().unwrap();
            if *last == Some(h) {
                continue;
            }
            *last = Some(h);
        }
        let desc = content.describe();
        match shared.out.lock().unwrap().as_ref() {
            Some((_, tx)) => {
                log!("→ sending {desc}");
                let _ = tx.send(Message::Clip(content));
            }
            None => log!("copied {desc} (no peer connected)"),
        }
    }
}

fn apply_remote(shared: &Shared, content: Content) {
    let desc = content.describe();
    *shared.last_hash.lock().unwrap() = Some(content.hash());
    let mut clip = shared.clip.lock().unwrap();
    match clip.write(&content) {
        Ok(()) => {
            *shared.own_change.lock().unwrap() = clip::change_count();
            log!("← received {desc}");
        }
        Err(e) => log!("← received {desc} but couldn't put it on the clipboard: {e}"),
    }
}

// ---------- networking ----------

fn listen(bind: &str, shared: Arc<Shared>) {
    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            log!("can't listen on {bind}: {e}");
            std::process::exit(1);
        }
    };
    log!("listening on {bind}");
    let pending = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                let Some(slot) = PendingSlot::acquire(&pending) else {
                    log!("{peer}: rejected, too many connections are still authenticating");
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                let s = shared.clone();
                thread::spawn(move || {
                    match run_session(stream, net::Role::Listener, &s, Some(slot)) {
                        Ok(()) => log!("{peer} disconnected"),
                        Err(e) => log!("{peer}: {e}"),
                    }
                });
            }
            Err(e) => log!("accept failed: {e}"),
        }
    }
}

/// Marks a listener connection that hasn't authenticated yet. Capping these
/// stops strangers from tying up threads; the slot is released on drop.
struct PendingSlot(Arc<AtomicUsize>);

impl PendingSlot {
    fn acquire(count: &Arc<AtomicUsize>) -> Option<PendingSlot> {
        if count.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING {
            count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(PendingSlot(count.clone()))
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn connect_loop(addr: &str, shared: Arc<Shared>) {
    let addr = if addr.contains(':') && !addr.ends_with(']') {
        addr.to_string()
    } else {
        format!("{addr}:{DEFAULT_PORT}")
    };
    let mut backoff = Duration::from_secs(2);
    loop {
        let started = Instant::now();
        let result = (|| -> io::Result<()> {
            let sa = addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::other("could not resolve address"))?;
            let stream = TcpStream::connect_timeout(&sa, Duration::from_secs(5))?;
            run_session(stream, net::Role::Connector, &shared, None)
        })();
        match result {
            Ok(()) => log!("disconnected from {addr}"),
            Err(e) => log!("{addr}: {e}"),
        }
        if started.elapsed() > Duration::from_secs(30) {
            backoff = Duration::from_secs(2);
        }
        log!("retrying in {}s", backoff.as_secs());
        thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// `pending` is the listener's unauthenticated-connection slot, released once
/// the peer's Hello has been verified.
fn run_session(
    mut stream: TcpStream,
    role: net::Role,
    shared: &Arc<Shared>,
    mut pending: Option<PendingSlot>,
) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
    let (mut sealer, mut opener) = net::handshake(&mut stream, role, &shared.psk)?;

    let (tx, rx) = mpsc::channel::<Message>();
    tx.send(Message::Hello { name: shared.name.clone() }).ok();

    let mut wstream = stream.try_clone()?;
    let max_frame = shared.max_frame;
    let writer = thread::spawn(move || {
        loop {
            let msg = match rx.recv_timeout(PING_EVERY) {
                Ok(m) => m,
                Err(RecvTimeoutError::Timeout) => Message::Ping,
                Err(RecvTimeoutError::Disconnected) => break,
            };
            let bytes = match msg.encode() {
                Ok(b) => b,
                Err(e) => {
                    log!("couldn't encode outgoing clipboard: {e}");
                    continue;
                }
            };
            if bytes.len() + 64 > max_frame {
                log!(
                    "clipboard item too large to send ({}, limit {}; raise --max-mb on both machines)",
                    proto::human_bytes(bytes.len()),
                    proto::human_bytes(max_frame)
                );
                continue;
            }
            if sealer.write_frame(&mut wstream, &bytes).is_err() {
                break;
            }
        }
        let _ = wstream.shutdown(Shutdown::Both);
    });

    // The first frame must be the peer's Hello; only then does this session take
    // over (so a client with the wrong key can't knock out a good connection).
    // Until it decrypts, the opener only accepts a tiny frame.
    let first = Message::decode(&opener.read_frame(&mut stream)?)?;
    let Message::Hello { name: peer_name } = first else {
        return Err(proto::bad("peer did not say hello"));
    };
    drop(pending.take());
    opener.set_max_frame(shared.max_frame);
    stream.set_read_timeout(Some(PEER_TIMEOUT))?;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    // Replacing the old sender drops it, which stops the old session's writer.
    *shared.out.lock().unwrap() = Some((id, tx));
    log!("connected to \"{peer_name}\" ({peer_addr})");

    let result = (|| -> io::Result<()> {
        loop {
            let frame = opener.read_frame(&mut stream)?;
            match Message::decode(&frame)? {
                Message::Ping | Message::Hello { .. } => {}
                Message::Clip(content) => apply_remote(shared, content),
            }
        }
    })();

    {
        let mut out = shared.out.lock().unwrap();
        if matches!(out.as_ref(), Some((cur, _)) if *cur == id) {
            *out = None;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    let _ = writer.join();
    match result {
        Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::NotConnected) => Ok(()),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            Err(io::Error::new(e.kind(), "peer stopped responding"))
        }
        other => other,
    }
}
