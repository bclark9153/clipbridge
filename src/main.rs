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
use std::collections::HashMap;
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
    /// Connect to one or more listening machines (run this on Windows). Reconnects
    /// automatically. Asks for the pairing code of each machine not paired yet.
    /// With several machines, a copy on any of them reaches all the others.
    Connect {
        /// Host or host:port of each listener, e.g. my-mac.local, 100.64.1.5:47800 or
        /// [fd7a:115c::5]:47800 (put IPv6 addresses in brackets when adding a port).
        #[arg(required = true, num_args = 1..)]
        addrs: Vec<String>,
        /// The pairing code shown on the listener, instead of being asked for it
        /// (only when a single machine needs pairing).
        #[arg(long)]
        code: Option<String>,
        /// Pair again with every listed machine even if keys are stored (replaces them).
        #[arg(long)]
        pair: bool,
    },
    /// Pair with each listed machine that isn't paired yet, save the keys, and exit.
    /// (`connect` does the same; this one is for scripts and installers.)
    Pair {
        /// Host or host:port of each listener.
        #[arg(required = true, num_args = 1..)]
        addrs: Vec<String>,
        /// The pairing code shown on the listener, instead of being asked for it
        /// (only when a single machine needs pairing).
        #[arg(long)]
        code: Option<String>,
        /// Pair again even with machines that already have a stored key.
        #[arg(long)]
        force: bool,
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
    /// Outboxes of the active sessions by peer slot, with the session id. A
    /// listener has one slot (the newest authenticated session wins); a
    /// connector has one per machine it connects to.
    out: Mutex<HashMap<usize, (u64, Arc<Outbox>)>>,
    next_id: AtomicU64,
    name: String,
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

    if let Cmd::Pair { addrs, code, force } = &cli.cmd {
        let peers = match pair_peers(&cli, addrs, code.clone(), *force) {
            Ok(p) => p,
            Err(e) => {
                log!("{e}");
                std::process::exit(2);
            }
        };
        if peers.iter().all(|(_, key)| key.is_some()) {
            log!("done. From now on just run: clipbridge connect {}", addrs.join(" "));
            return;
        }
        std::process::exit(2);
    }

    // Kept short so the Hello always fits under net::HELLO_FRAME_LIMIT.
    let name: String = cli.name.clone().unwrap_or_else(hostname).chars().take(200).collect();

    // Keys: given explicitly, saved by an earlier pairing, or made now by pairing.
    let role = match &cli.cmd {
        Cmd::Listen { bind, pair } => {
            let key_path = key_path(&cli);
            let configured = match load_key(&cli, &key_path) {
                Ok(k) => k,
                Err(e) => {
                    log!("{e}");
                    std::process::exit(2);
                }
            };
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
            Role::Listen(listener, net::psk_from_passphrase(&key))
        }
        Cmd::Connect { addrs, code, pair } => {
            let peers = match pair_peers(&cli, addrs, code.clone(), *pair) {
                Ok(p) => p,
                Err(e) => {
                    log!("{e}");
                    std::process::exit(2);
                }
            };
            let ready: Vec<(String, [u8; 32])> = peers
                .into_iter()
                .filter_map(|(addr, key)| key.map(|k| (addr, net::psk_from_passphrase(&k))))
                .collect();
            if ready.is_empty() {
                std::process::exit(2);
            }
            Role::Connect(ready)
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
        out: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        name,
        max_frame: frame_limit(cli.max_mb),
        plain_text: cli.plain_text,
    });

    log!("ClipBridge {} as \"{}\"; received files go to {}", env!("CARGO_PKG_VERSION"), shared.name, receive_dir.display());

    {
        let s = shared.clone();
        let poll = Duration::from_millis(cli.poll_ms.max(50));
        thread::spawn(move || watch_clipboard(s, poll));
    }

    match role {
        Role::Listen(listener, psk) => listen(listener, shared, psk),
        Role::Connect(peers) => {
            if peers.len() > 1 {
                log!("connecting to {} machines; a copy on any of them reaches all the others", peers.len());
            }
            let threads: Vec<_> = peers
                .into_iter()
                .enumerate()
                .map(|(slot, (addr, psk))| {
                    let s = shared.clone();
                    thread::spawn(move || connect_loop(&addr, s, slot, psk))
                })
                .collect();
            for t in threads {
                let _ = t.join();
            }
        }
    }
}

/// What this process does once keys are settled.
enum Role {
    Listen(TcpListener, [u8; 32]),
    /// Each machine to connect to, as `host:port`, with its stretched key.
    Connect(Vec<(String, [u8; 32])>),
}

/// The key for each machine in `addrs` (as `host:port`), pairing with the ones
/// that have none yet (or all of them, with `force`). A machine that still has
/// no key afterwards, because pairing needs a terminal, gets `None`.
fn pair_peers(
    cli: &Cli,
    addrs: &[String],
    code: Option<String>,
    force: bool,
) -> Result<Vec<(String, Option<String>)>, String> {
    let mut peers = Vec::new();
    for addr in addrs {
        let addr = full_addr(addr);
        let (path, key) = peer_key(cli, &addr, addrs.len() == 1)?;
        peers.push((addr, path, if force { None } else { key }));
    }
    let unpaired = peers.iter().filter(|(_, _, key)| key.is_none()).count();
    if code.is_some() && unpaired > 1 {
        return Err("--code works when a single machine needs pairing; leave it out to be asked for each code".into());
    }
    let mut out = Vec::new();
    for (addr, path, key) in peers {
        let key = match key {
            Some(k) => Some(k),
            None => match pair_connector(&addr, code.clone(), &path) {
                Ok(k) => Some(k),
                Err(e) => {
                    log!("{addr}: {e}");
                    None
                }
            },
        };
        out.push((addr, key));
    }
    Ok(out)
}

/// Where the key for `addr` (a `host:port`) lives, and the key if there is one.
/// `--key` and `--key-file` give every machine the same key (a manual setup).
/// Otherwise each machine has its own file in the keys folder. With a single
/// machine, a key saved by an older version in the single key file is moved
/// into the keys folder, so upgrading keeps the pairing.
fn peer_key(cli: &Cli, addr: &str, single: bool) -> Result<(PathBuf, Option<String>), String> {
    let explicit = cli.key.as_deref().is_some_and(|k| !k.is_empty())
        || cli.key_file.as_deref().is_some_and(|p| !p.as_os_str().is_empty());
    if explicit {
        let path = key_path(cli);
        let key = load_key(cli, &path)?;
        if key.is_none() && !single {
            return Err(format!(
                "{} doesn't exist. With several machines, leave out --key-file so each gets its own key.",
                path.display()
            ));
        }
        return Ok((path, key));
    }
    let path = peer_key_path(addr);
    if !path.is_file() && single {
        let legacy = default_key_path();
        if legacy.is_file() {
            let moved = path.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok())
                && std::fs::rename(&legacy, &path).is_ok();
            if moved {
                log!("moved the pairing key for {addr} to {}", path.display());
            } else {
                return Ok((path, Some(checked_key(read_key_file(&legacy)?)?)));
            }
        }
    }
    if !path.is_file() {
        return Ok((path, None));
    }
    Ok((path.clone(), Some(checked_key(read_key_file(&path)?)?)))
}

/// The key file for one machine: keys\<host>_<port>.key next to the default key file.
fn peer_key_path(addr: &str) -> PathBuf {
    let safe: String = addr
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c.to_ascii_lowercase() } else { '_' })
        .collect();
    let dir = default_key_path().parent().map(Path::to_path_buf).unwrap_or_else(std::env::temp_dir);
    dir.join("keys").join(format!("{safe}.key"))
}

fn checked_key(key: String) -> Result<String, String> {
    if key.chars().count() < MIN_KEY_CHARS {
        return Err(format!(
            "The passphrase must be at least {MIN_KEY_CHARS} characters. Generate a strong one with: clipbridge genkey"
        ));
    }
    Ok(key)
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
    Ok(Some(checked_key(key)?))
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
                eprint!("Enter the pairing code shown on {addr}: ");
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
        match broadcast(&shared, content, None) {
            0 => log!("copied {desc} (no peer connected)"),
            1 => log!("→ sending {desc}"),
            n => log!("→ sending {desc} to {n} machines"),
        }
    }
}

/// Queue `content` for every connected peer except the one in slot `except`.
/// Returns how many peers it was queued for.
fn broadcast(shared: &Shared, content: Content, except: Option<usize>) -> usize {
    let outboxes: Vec<Arc<Outbox>> = lock(&shared.out)
        .iter()
        .filter(|(slot, _)| Some(**slot) != except)
        .map(|(_, (_, o))| o.clone())
        .collect();
    let n = outboxes.len();
    let mut content = Some(content);
    for (i, o) in outboxes.into_iter().enumerate() {
        // Only clone for all but the last peer: file batches can be large.
        let item = if i + 1 == n { content.take() } else { content.clone() };
        if let Some(item) = item
            && o.put(item)
        {
            log!("(dropped an older clipboard item that hadn't been sent yet)");
        }
    }
    n
}

/// `from` is the slot of the peer that sent it; on a machine connected to
/// several peers, the content is passed on to all the others.
fn apply_remote(shared: &Shared, content: Content, from: usize) {
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
    {
        let mut clip = lock(&shared.clip);
        match clip.write(&content) {
            Ok(()) => {
                *lock(&shared.own_change) = clip::change_count();
                log!("← received {desc}");
            }
            Err(e) => log!("← received {desc} but couldn't put it on the clipboard: {e}"),
        }
    }
    let n = broadcast(shared, content, Some(from));
    if n > 0 {
        log!("→ passed it on to {n} other machine(s)");
    }
}

// ---------- networking ----------

fn listen(listener: TcpListener, shared: Arc<Shared>, psk: [u8; 32]) {
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
                    // Slot 0: a listener serves one peer at a time, newest wins.
                    match run_session(stream, net::Role::Listener, &s, 0, &psk, Some(slot)) {
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

/// Keep a session to `addr` (a `host:port`) open, reconnecting as needed.
fn connect_loop(addr: &str, shared: Arc<Shared>, slot: usize, psk: [u8; 32]) {
    let mut backoff = Duration::from_secs(2);
    loop {
        let started = Instant::now();
        let result = (|| -> io::Result<()> {
            let stream = connect_any(addr)?;
            run_session(stream, net::Role::Connector, &shared, slot, &psk, None)
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

/// `slot` identifies the peer in `Shared::out`; `pending` is the listener's
/// unauthenticated-connection slot, released once the peer's Hello is verified.
fn run_session(
    mut stream: TcpStream,
    role: net::Role,
    shared: &Arc<Shared>,
    slot: usize,
    psk: &[u8; 32],
    mut pending: Option<PendingSlot>,
) -> io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
    let (mut sealer, mut opener) = net::handshake(&mut stream, role, psk)?;

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
        let previous = lock(&shared.out).insert(slot, (id, outbox.clone()));
        if let Some((_, old)) = previous {
            old.close(); // stops the old session's writer, which ends that session
        }
        log!("connected to \"{peer_name}\" ({peer_addr})");

        loop {
            let frame = opener.read_frame(&mut stream)?;
            match Message::decode(&frame)? {
                Message::Ping | Message::Hello { .. } => {}
                Message::Clip(content) => apply_remote(shared, content, slot),
            }
        }
    })();

    {
        let mut out = lock(&shared.out);
        if matches!(out.get(&slot), Some((cur, _)) if *cur == id) {
            out.remove(&slot);
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
