//! ClipBridge — two-way clipboard sync (text, rich text, screenshots/images, files) between
//! two machines, designed to run alongside a remote-desktop app like Jump Desktop.
//!
//!   Mac:      clipbridge listen             (shows a pairing code the first time)
//!   Windows:  clipbridge connect <mac-host>  (asks for that code the first time)

mod clip;
mod net;
mod pair;
mod proto;

use clap::{Parser, Subcommand};
use proto::{Content, Message};
use std::fs::OpenOptions;
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
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
/// How long each step of a pairing exchange may take.
const PAIR_TIMEOUT: Duration = Duration::from_secs(60);
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

    /// Shared passphrase (same on both machines). Normally not needed: pairing with
    /// a code stores a key automatically. Can also be set via CLIPBRIDGE_KEY.
    #[arg(long, env = "CLIPBRIDGE_KEY", global = true, hide_env_values = true)]
    key: Option<String>,

    /// Read the shared passphrase from this file instead of the one saved by pairing.
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
    /// Wait for the other machine to connect (run this on the Mac). The first time
    /// it shows a pairing code to enter on the other machine.
    Listen {
        /// Address to listen on.
        #[arg(default_value_t = format!("0.0.0.0:{DEFAULT_PORT}"))]
        bind: String,
        /// Show a new pairing code even though a key is already stored (replaces it).
        #[arg(long)]
        pair: bool,
    },
    /// Connect to the listening machine (run this on Windows). Reconnects automatically.
    /// The first time it asks for the pairing code shown by the listener.
    Connect {
        /// Host or host:port of the listener, e.g. my-mac.local, 100.64.1.5:47800 or
        /// [fd7a:115c::5]:47800 (put IPv6 addresses in brackets when adding a port).
        addr: String,
        /// The pairing code shown on the listener, instead of being asked for it.
        #[arg(long)]
        code: Option<String>,
        /// Pair again even though a key is already stored (replaces it).
        #[arg(long)]
        pair: bool,
    },
    /// Pair with the listening machine using the code it shows, save the key, and exit.
    /// (`connect` does the same the first time; this one is for scripts and installers.)
    Pair {
        /// Host or host:port of the listener.
        addr: String,
        /// The pairing code shown on the listener, instead of being asked for it.
        #[arg(long)]
        code: Option<String>,
    },
    /// Print a random passphrase to use as --key (only for manual setups without pairing).
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

    if let Cmd::Pair { addr, code } = &cli.cmd {
        match pair_connector(&full_addr(addr), code.clone(), &key_path(&cli)) {
            Ok(_) => {
                log!("done. From now on just run: clipbridge connect {addr}");
                return;
            }
            Err(e) => {
                log!("{e}");
                std::process::exit(2);
            }
        }
    }

    // Kept short so the Hello always fits under net::HELLO_FRAME_LIMIT.
    let name: String = cli.name.clone().unwrap_or_else(hostname).chars().take(200).collect();

    // The key: given explicitly, saved by an earlier pairing, or made now by pairing.
    let key_path = key_path(&cli);
    let configured = match load_key(&cli, &key_path) {
        Ok(k) => k,
        Err(e) => {
            log!("{e}");
            std::process::exit(2);
        }
    };
    let (key, listener) = match &cli.cmd {
        Cmd::Listen { bind, pair } => {
            let listener = match TcpListener::bind(bind.as_str()) {
                Ok(l) => l,
                Err(e) => {
                    log!("can't listen on {bind}: {e}");
                    std::process::exit(1);
                }
            };
            log!("listening on {bind}");
            let key = match (configured, *pair) {
                (Some(k), false) => k,
                _ => pair_listener(&listener, &name, &key_path),
            };
            (key, Some(listener))
        }
        Cmd::Connect { addr, code, pair } => {
            let key = match (configured, *pair) {
                (Some(k), false) => k,
                _ => match pair_connector(&full_addr(addr), code.clone(), &key_path) {
                    Ok(k) => k,
                    Err(e) => {
                        log!("{e}");
                        std::process::exit(2);
                    }
                },
            };
            (key, None)
        }
        Cmd::Genkey | Cmd::Pair { .. } => unreachable!(),
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
        name,
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
        Cmd::Listen { .. } => listen(listener.expect("bound above"), shared),
        Cmd::Connect { addr, .. } => connect_loop(&addr, shared),
        Cmd::Genkey | Cmd::Pair { .. } => unreachable!(),
    }
}

/// Where the key lives: --key-file (or CLIPBRIDGE_KEY_FILE), else the default
/// location. Pairing saves the key there when the file doesn't exist yet.
fn key_path(cli: &Cli) -> PathBuf {
    cli.key_file.clone().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(default_key_path)
}

/// The passphrase from --key (or CLIPBRIDGE_KEY), else the key file; None when
/// there is no key yet and pairing is needed.
fn load_key(cli: &Cli, key_path: &Path) -> Result<Option<String>, String> {
    let key_arg = cli.key.as_deref().filter(|k| !k.is_empty());
    let key_file_given = cli.key_file.as_deref().is_some_and(|p| !p.as_os_str().is_empty());
    let key = match key_arg {
        Some(_) if key_file_given => {
            return Err("Use either --key or --key-file, not both (check the CLIPBRIDGE_KEY and \
                        CLIPBRIDGE_KEY_FILE environment variables too)."
                .into());
        }
        Some(k) => k.to_string(),
        None => {
            if !key_path.is_file() {
                return Ok(None);
            }
            read_key_file(key_path)?
        }
    };
    if key.chars().count() < MIN_KEY_CHARS {
        return Err(format!(
            "The passphrase must be at least {MIN_KEY_CHARS} characters. Generate a strong one with: clipbridge genkey"
        ));
    }
    Ok(Some(key))
}

fn read_key_file(path: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("can't read key file {}: {e}", path.display()))?;
    Ok(raw.trim_start_matches('\u{feff}').trim_end().to_string())
}

/// Where pairing keeps the key: %LOCALAPPDATA%\ClipBridge\key.txt on Windows,
/// ~/.config/clipbridge/key elsewhere.
fn default_key_path() -> PathBuf {
    #[cfg(windows)]
    if let Some(d) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(d).join("ClipBridge").join("key.txt");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    home.join(".config").join("clipbridge").join("key")
}

/// Save a pairing key so that only this user can read it.
fn store_key(path: &Path, key: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(dir) = path.parent() {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(key.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, key)?;
        // Drop inherited permissions and leave exactly this user and SYSTEM.
        let user = std::env::var("USERNAME").unwrap_or_default();
        let me = match std::env::var("USERDOMAIN") {
            Ok(d) if !d.is_empty() => format!("{d}\\{user}"),
            _ => user,
        };
        let ok = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{me}:(F)"))
            .arg("*S-1-5-18:(F)")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            log!("warning: couldn't restrict who can read {}", path.display());
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn save_pairing(path: &Path, key: &str) {
    match store_key(path, key) {
        Ok(()) => log!("pairing key saved to {}", path.display()),
        Err(e) => log!(
            "warning: couldn't save the pairing key to {} ({e}); you'll have to pair again next start",
            path.display()
        ),
    }
}

fn show_code(code: &str, name: &str) {
    log!("");
    log!("    Pairing code for \"{name}\":   {}", pair::pretty(code));
    log!("");
    log!("On the other machine run `clipbridge connect <this machine>` and enter the code.");
}

/// Show a pairing code and accept attempts until one succeeds. Returns the new key.
fn pair_listener(listener: &TcpListener, name: &str, key_path: &Path) -> String {
    let mut code = pair::new_code();
    log!("not paired yet; waiting for the other machine");
    show_code(&code, name);
    loop {
        let (mut stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                log!("accept failed: {e}");
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(PAIR_TIMEOUT));
        let _ = stream.set_write_timeout(Some(PAIR_TIMEOUT));
        let result = pair::server(&mut stream, &code);
        let _ = stream.shutdown(Shutdown::Both);
        match result {
            Ok(ltk) => {
                let key = hex(&ltk);
                save_pairing(key_path, &key);
                log!("paired with {peer}");
                return key;
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                log!("{peer}: wrong pairing code; here is a new one");
                thread::sleep(Duration::from_secs(2));
                code = pair::new_code();
                show_code(&code, name);
            }
            Err(e) => {
                log!("{peer}: {e}");
                show_code(&code, name);
            }
        }
    }
}

/// Ask for the code shown on `addr` and pair with it. Returns the new key.
fn pair_connector(addr: &str, code: Option<String>, key_path: &Path) -> Result<String, String> {
    let interactive = io::stdin().is_terminal();
    if code.is_none() && !interactive {
        return Err(format!(
            "not paired yet. Open a terminal and run:  clipbridge connect {addr}\n\
             then enter the pairing code shown by `clipbridge listen` on the other machine."
        ));
    }
    log!("not paired yet; pairing with {addr}");
    for _ in 0..5 {
        let typed = match &code {
            Some(c) => c.clone(),
            None => {
                eprint!("Enter the pairing code shown on the other machine: ");
                let _ = io::stderr().flush();
                let mut line = String::new();
                io::stdin().lock().read_line(&mut line).map_err(|e| format!("couldn't read the code: {e}"))?;
                if line.is_empty() {
                    return Err("no code entered".into());
                }
                line
            }
        };
        let digits = pair::normalize(&typed);
        if digits.len() != pair::CODE_DIGITS {
            eprintln!("The code is {} digits.", pair::CODE_DIGITS);
            if code.is_some() {
                return Err("--code must be the 6-digit pairing code".into());
            }
            continue;
        }
        let mut stream = connect_any(addr).map_err(|e| format!("can't reach {addr}: {e}"))?;
        let _ = stream.set_read_timeout(Some(PAIR_TIMEOUT));
        let _ = stream.set_write_timeout(Some(PAIR_TIMEOUT));
        let result = pair::client(&mut stream, &digits);
        let _ = stream.shutdown(Shutdown::Both);
        match result {
            Ok(ltk) => {
                let key = hex(&ltk);
                save_pairing(key_path, &key);
                log!("paired with {addr}");
                return Ok(key);
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("Wrong code. The other machine now shows a new one.");
                if code.is_some() {
                    return Err("the pairing code was rejected".into());
                }
            }
            Err(e) => return Err(format!("pairing with {addr} failed: {e}")),
        }
    }
    Err("too many wrong codes; start again".into())
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
        if content.is_file_url_list() {
            // Another tool's text version of a file copy (Jump Desktop's clipboard
            // sharing does this). Put the real files back if we have them, so a
            // paste still gets files whichever tool wrote last.
            let restored = {
                let mut clip = lock(&shared.clip);
                let n = clip.restore_files();
                if n.is_some() {
                    *lock(&shared.own_change) = clip::change_count();
                }
                n
            };
            match restored {
                Some(n) => log!("another tool replaced the copied files with file:// links; put the {n} file(s) back"),
                None => log!("ignoring a list of file:// links on the clipboard (another tool's text version of a file copy)"),
            }
            continue;
        }
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
    if content.is_file_url_list() {
        log!("← ignored a list of file:// links (they point at the other machine's disk)");
        return;
    }
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

fn listen(listener: TcpListener, shared: Arc<Shared>) {
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

/// `host`, `host:port`, a bare IPv6 address or `[v6]:port` as a `host:port` string.
fn full_addr(addr: &str) -> String {
    if addr.parse::<Ipv6Addr>().is_ok() {
        format!("[{addr}]:{DEFAULT_PORT}") // bare IPv6 address, no port
    } else if addr.contains(':') && !addr.ends_with(']') {
        addr.to_string()
    } else {
        format!("{addr}:{DEFAULT_PORT}")
    }
}

fn connect_loop(addr: &str, shared: Arc<Shared>) {
    let addr = full_addr(addr);
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
