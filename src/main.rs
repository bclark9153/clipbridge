//! ClipBridge — two-way clipboard sync (text, rich text, screenshots/images, files) between
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
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
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
    if let Some(f) = LOG_FILE.get() {
        let _ = lock(f).write_all(line.as_bytes());
    }
}

#[macro_export]
macro_rules! log {
    ($($t:tt)*) => { $crate::log_line(format!($($t)*)) };
}

/// Lock a mutex, carrying on if another thread panicked while holding it: the
/// state behind these locks stays usable, and one failed clipboard operation
/// shouldn't take the watcher or the sessions down with it.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------- CLI ----------

#[derive(Parser)]
#[command(name = "clipbridge", version, about = "Two-way clipboard sync: text, rich text, screenshots and files")]
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

    /// Sync plain text only: don't send or apply HTML formatting.
    #[arg(long, global = true)]
    plain_text: bool,

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
        /// Host or host:port of the listener, e.g. my-mac, 100.64.1.5:47800 or
        /// [fd7a:115c::5]:47800 (put IPv6 addresses in brackets when adding a port).
        addr: String,
    },
    /// Print a random passphrase to use as --key.
    Genkey,
}

// ---------- shared state ----------

struct Shared {
    clip: Mutex<clip::Clip>,
    /// The content most recently sent or applied; stops echo loops.
    last: Mutex<Seen>,
    /// OS change counter produced by our own write of remote content.
    own_change: Mutex<Option<u64>>,
    /// Outbox of the active session (newest authenticated session wins).
    out: Mutex<Option<(u64, Arc<Outbox>)>>,
    next_id: AtomicU64,
    name: String,
    psk: [u8; 32],
    /// Largest frame sent or accepted once the peer has authenticated.
    max_frame: usize,
    /// --plain-text: formatting from the peer is dropped too.
    plain_text: bool,
}

/// Hashes of the content most recently sent or applied.
#[derive(Default)]
struct Seen {
    hash: Option<[u8; 32]>,
    /// For rich text, the hash of its plain-text version. A remote-desktop app
    /// that syncs text by itself (Jump Desktop does) can put that text on the
    /// clipboard, or echo it back, and it must not replace the formatted original.
    plain: Option<[u8; 32]>,
}

impl Seen {
    fn is_duplicate(&self, h: &[u8; 32]) -> bool {
        self.hash.as_ref() == Some(h) || self.plain.as_ref() == Some(h)
    }

    fn remember(&mut self, content: &Content, h: [u8; 32]) {
        self.hash = Some(h);
        self.plain = content.plain_hash();
    }
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
    let clip = match clip::Clip::new(receive_dir.clone(), cli.max_mb.saturating_mul(MB), !cli.plain_text) {
        Ok(c) => c,
        Err(e) => {
            log!("cannot open the clipboard: {e}");
            std::process::exit(1);
        }
    };

    let shared = Arc::new(Shared {
        clip: Mutex::new(clip),
        last: Mutex::new(Seen::default()),
        own_change: Mutex::new(None),
        out: Mutex::new(None),
        next_id: AtomicU64::new(1),
        // Kept short so the Hello always fits under net::HELLO_FRAME_LIMIT.
        name: cli.name.clone().unwrap_or_else(hostname).chars().take(200).collect(),
        psk: net::psk_from_passphrase(&key),
        max_frame: frame_limit(cli.max_mb),
        plain_text: cli.plain_text,
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
    let has_counter = clip::HAS_COUNTER;
    let mut last_seen = clip::change_count();
    // Baseline: whatever is on the clipboard at startup is not "new". Copied
    // files are only noted by path, never loaded, just to compute this.
    let baseline = lock(&shared.clip).read_baseline();
    if let Some(c) = baseline {
        let h = c.hash();
        lock(&shared.last).remember(&c, h);
    }
    let poll = if has_counter { poll } else { poll.max(Duration::from_secs(1)) };

    loop {
        thread::sleep(poll);
        if has_counter {
            // None: the counter can't be read right now (Windows reports 0 when
            // access is denied). Don't treat that as a change; check again later.
            let Some(now) = clip::change_count() else { continue };
            if last_seen == Some(now) {
                continue;
            }
            last_seen = Some(now);
            if *lock(&shared.own_change) == Some(now) {
                continue; // this change was us applying remote content
            }
        }

        let content = lock(&shared.clip).read(has_counter);
        let Some(content) = content else { continue };
        let h = content.hash();
        {
            let mut last = lock(&shared.last);
            if last.is_duplicate(&h) {
                continue;
            }
            last.remember(&content, h);
        }
        let desc = content.describe();
        let outbox = lock(&shared.out).as_ref().map(|(_, o)| o.clone());
        match outbox {
            Some(o) => {
                log!("→ sending {desc}");
                if o.put(content) {
                    log!("(dropped an older clipboard item that hadn't been sent yet)");
                }
            }
            None => log!("copied {desc} (no peer connected)"),
        }
    }
}

fn apply_remote(shared: &Shared, content: Content) {
    let content = if shared.plain_text { content.into_plain() } else { content };
    let desc = content.describe();
    let h = content.hash();
    {
        let mut last = lock(&shared.last);
        // Already what we last sent or applied (or the plain text of it, e.g.
        // echoed back by a remote-desktop app's own text sync): rewriting it
        // could only lose formats, so leave the clipboard alone.
        if last.is_duplicate(&h) {
            log!("← received {desc} (duplicate, clipboard left as is)");
            return;
        }
        last.remember(&content, h);
    }
    let mut clip = lock(&shared.clip);
    match clip.write(&content) {
        Ok(()) => {
            *lock(&shared.own_change) = clip::change_count();
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

/// What a session's writer thread sends next. It holds at most one clipboard
/// item: a newer copy replaces an older one that hasn't gone out yet, so a slow
/// link never builds up a backlog of stale (and possibly large) items.
struct Outbox {
    state: Mutex<OutboxState>,
    ready: Condvar,
}

#[derive(Default)]
struct OutboxState {
    pending: Option<Content>,
    closed: bool,
}

enum Next {
    Clip(Content),
    /// Nothing to send for a while: time for a keep-alive ping.
    Idle,
    Closed,
}

impl Outbox {
    fn new() -> Self {
        Outbox { state: Mutex::new(OutboxState::default()), ready: Condvar::new() }
    }

    /// Queue `content` to send. Returns true if it replaced an unsent older item.
    fn put(&self, content: Content) -> bool {
        let replaced = lock(&self.state).pending.replace(content).is_some();
        self.ready.notify_all();
        replaced
    }

    fn close(&self) {
        lock(&self.state).closed = true;
        self.ready.notify_all();
    }

    /// Wait up to `timeout` for an item to send.
    fn next(&self, timeout: Duration) -> Next {
        let deadline = Instant::now() + timeout;
        let mut state = lock(&self.state);
        loop {
            if state.closed {
                return Next::Closed;
            }
            if let Some(content) = state.pending.take() {
                return Next::Clip(content);
            }
            let now = Instant::now();
            if now >= deadline {
                return Next::Idle;
            }
            state = match self.ready.wait_timeout(state, deadline - now) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }
}

fn connect_loop(addr: &str, shared: Arc<Shared>) {
    let addr = if addr.parse::<Ipv6Addr>().is_ok() {
        format!("[{addr}]:{DEFAULT_PORT}") // bare IPv6 address, no port
    } else if addr.contains(':') && !addr.ends_with(']') {
        addr.to_string()
    } else {
        format!("{addr}:{DEFAULT_PORT}")
    };
    let mut backoff = Duration::from_secs(2);
    loop {
        let started = Instant::now();
        let result = (|| -> io::Result<()> {
            let stream = connect_any(&addr)?;
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

/// Try every address the name resolves to (IPv6 and IPv4), so one that refuses
/// or times out doesn't hide one that works.
fn connect_any(addr: &str) -> io::Result<TcpStream> {
    let mut last_err = None;
    for sa in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(io::Error::new(e.kind(), format!("{sa}: {e}"))),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("could not resolve address")))
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

    let outbox = Arc::new(Outbox::new());
    let mut wstream = stream.try_clone()?;
    let max_frame = shared.max_frame;
    let writer_box = outbox.clone();
    let mut hello = Some(Message::Hello { name: shared.name.clone() });
    let writer = thread::spawn(move || {
        loop {
            let msg = match hello.take() {
                Some(m) => m,
                None => match writer_box.next(PING_EVERY) {
                    Next::Clip(c) => Message::Clip(c),
                    Next::Idle => Message::Ping,
                    Next::Closed => break,
                },
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

    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let result = (|| -> io::Result<()> {
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
        let previous = lock(&shared.out).replace((id, outbox.clone()));
        if let Some((_, old)) = previous {
            old.close(); // stops the old session's writer, which ends that session
        }
        log!("connected to \"{peer_name}\" ({peer_addr})");

        loop {
            let frame = opener.read_frame(&mut stream)?;
            match Message::decode(&frame)? {
                Message::Ping | Message::Hello { .. } => {}
                Message::Clip(content) => apply_remote(shared, content),
            }
        }
    })();

    {
        let mut out = lock(&shared.out);
        if matches!(out.as_ref(), Some((cur, _)) if *cur == id) {
            *out = None;
        }
    }
    outbox.close();
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
