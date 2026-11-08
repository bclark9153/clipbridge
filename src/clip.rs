//! Native clipboard access plus a cheap "did the clipboard change?" counter.
//!
//! arboard does the format work: on macOS it reads screenshots (TIFF/PNG) and
//! writes NSImage; on Windows it reads CF_DIBV5/PNG and writes both CF_DIBV5 and
//! the registered "PNG" format, so Paint, Teams, Outlook and browsers all accept
//! a paste. File copies map to NSURLs on macOS and CF_HDROP on Windows.
//!
//! Text travels with LF line endings and is converted to CRLF when written on
//! Windows, so the same text hashes the same on both sides.

use crate::log;
use crate::proto::{human_bytes, Content};
use arboard::{Clipboard, ImageData};
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long after a file copy or receive the files may be put back on the
/// clipboard if another sync tool overwrites them with links.
const RESTORE_WINDOW: Duration = Duration::from_secs(60);

/// Whether this platform has an OS clipboard change counter (see `change_count`).
pub const HAS_COUNTER: bool = cfg!(any(windows, target_os = "macos"));

/// Returns a counter the OS bumps on every clipboard change, if the platform has one.
/// Polling this is nearly free, so we only read actual content when it moves.
#[cfg(windows)]
pub fn change_count() -> Option<u64> {
    // 0 means the window station has no clipboard access right now.
    match unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() } {
        0 => None,
        n => Some(n as u64),
    }
}

#[cfg(target_os = "macos")]
pub fn change_count() -> Option<u64> {
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};
    unsafe {
        let pb: *mut AnyObject = msg_send![class!(NSPasteboard), generalPasteboard];
        if pb.is_null() {
            return None;
        }
        let n: isize = msg_send![pb, changeCount];
        Some(n as u64)
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn change_count() -> Option<u64> {
    None
}

/// Normalize line endings to LF (the form text is hashed and sent in).
fn to_lf(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// Line endings the local OS expects on the clipboard.
#[cfg(windows)]
fn to_native(s: &str) -> String {
    to_lf(s).replace('\n', "\r\n")
}

#[cfg(not(windows))]
fn to_native(s: &str) -> String {
    to_lf(s)
}

pub struct Clip {
    cb: Clipboard,
    receive_dir: PathBuf,
    max_file_bytes: usize,
    /// Read HTML alongside text (off with --plain-text).
    rich: bool,
    /// The files most recently copied here or received from the peer.
    last_paths: Vec<PathBuf>,
    paths_at: Option<Instant>,
    paths_received: bool,
    /// Times `restore_files` has put `last_paths` back since they were noted.
    restores: u32,
}

impl Clip {
    pub fn new(receive_dir: PathBuf, max_file_bytes: usize, rich: bool) -> Result<Self, arboard::Error> {
        Ok(Self {
            cb: Clipboard::new()?,
            receive_dir,
            max_file_bytes,
            rich,
            last_paths: Vec::new(),
            paths_at: None,
            paths_received: false,
            restores: 0,
        })
    }

    /// Read the current clipboard. `fresh` is true when the OS change counter
    /// says something new was copied; without a counter (Linux) we skip
    /// re-reading the same file list on every poll.
    pub fn read(&mut self, fresh: bool) -> Option<Content> {
        if let Some(paths) = self.file_list() {
            if !fresh && paths == self.last_paths {
                return None;
            }
            self.note_paths(paths.clone(), false);
            return self.read_files(&paths);
        }
        // `last_paths` is kept: if this text turns out to be another tool's
        // link list for those files, `restore_files` puts them back.
        self.read_text_or_image()
    }

    /// Like `read`, for the startup baseline: a copied file list is only
    /// remembered by path, never loaded, so it costs nothing however large it is.
    pub fn read_baseline(&mut self) -> Option<Content> {
        if let Some(paths) = self.file_list() {
            self.note_paths(paths, false);
            return None;
        }
        // `last_paths` is kept: if this text turns out to be another tool's
        // link list for those files, `restore_files` puts them back.
        self.read_text_or_image()
    }

    fn file_list(&mut self) -> Option<Vec<PathBuf>> {
        match self.cb.get().file_list() {
            Ok(paths) if !paths.is_empty() => Some(paths),
            _ => None,
        }
    }

    fn note_paths(&mut self, paths: Vec<PathBuf>, received: bool) {
        self.last_paths = paths;
        self.paths_at = Some(Instant::now());
        self.paths_received = received;
        self.restores = 0;
    }

    /// Put the last copied or received files back on the clipboard after another
    /// sync tool (Jump Desktop's clipboard sharing) replaced them with a text
    /// list of links. The receiving side may do this twice and the copying side
    /// once, within a minute of the copy: that is enough for the machine where
    /// the paste happens to end up with the files, without the two tools
    /// ping-ponging forever. Returns how many files were put back.
    pub fn restore_files(&mut self) -> Option<usize> {
        let noted_at = self.paths_at?;
        let limit = if self.paths_received { 2 } else { 1 };
        if self.last_paths.is_empty()
            || noted_at.elapsed() > RESTORE_WINDOW
            || self.restores >= limit
            || !self.last_paths.iter().all(|p| p.exists())
        {
            return None;
        }
        self.restores += 1;
        let _ = self.cb.clear(); // drop the link text rather than sit next to it
        match self.cb.set().file_list(&self.last_paths) {
            Ok(()) => Some(self.last_paths.len()),
            Err(e) => {
                log!("couldn't put the copied files back on the clipboard: {e}");
                None
            }
        }
    }

    /// Text (with its HTML version, if the copying app provided one), else an image.
    fn read_text_or_image(&mut self) -> Option<Content> {
        if let Ok(t) = self.cb.get_text()
            && !t.is_empty() {
                let text = to_lf(&t);
                if self.rich
                    && let Ok(html) = self.cb.get().html()
                    && !html.is_empty()
                    && html != text {
                        return Some(Content::Rich { text, html });
                    }
                return Some(Content::Text(text));
            }
        if let Ok(img) = self.cb.get_image()
            && img.width > 0 && img.height > 0 {
                return Some(Content::Image {
                    width: img.width as u32,
                    height: img.height as u32,
                    rgba: img.bytes.into_owned(),
                });
            }
        // HTML with no plain-text version (some scripts and clipboard tools do
        // this). Checked after images so a copied browser image, which also
        // carries an <img> snippet, still syncs as a picture.
        if self.rich
            && let Ok(html) = self.cb.get().html()
            && !html.is_empty() {
                return Some(Content::Rich { text: String::new(), html });
            }
        None
    }

    fn read_files(&self, paths: &[PathBuf]) -> Option<Content> {
        let mut files = Vec::new();
        let mut total = 0usize;
        for p in paths {
            let meta = match fs::metadata(p) {
                Ok(m) => m,
                Err(e) => {
                    log!("skipping {}: {e}", p.display());
                    continue;
                }
            };
            if !meta.is_file() {
                log!("skipping folder {} (folders aren't synced yet)", p.display());
                continue;
            }
            total += meta.len() as usize;
            if total > self.max_file_bytes {
                log!(
                    "copied files exceed the {} limit; not syncing (raise --max-mb)",
                    human_bytes(self.max_file_bytes)
                );
                return None;
            }
            match fs::read(p) {
                Ok(data) => {
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file".into());
                    files.push((name, data));
                }
                Err(e) => log!("skipping {}: {e}", p.display()),
            }
        }
        if files.is_empty() { None } else { Some(Content::Files(files)) }
    }

    pub fn write(&mut self, content: &Content) -> Result<(), String> {
        match content {
            Content::Text(t) => self.cb.set_text(to_native(t)).map_err(|e| e.to_string()),
            Content::Rich { text, html } => {
                // HTML plus the plain-text version for apps that only take text.
                // arboard adds the CF_HTML header on Windows and uses public.html on macOS.
                let alt = to_native(text);
                let result = self.cb.set().html(html.as_str(), (!alt.is_empty()).then_some(alt.as_str()));
                if let Err(e) = result {
                    if alt.is_empty() {
                        return Err(e.to_string());
                    }
                    log!("couldn't put formatted text on the clipboard ({e}); using plain text");
                    return self.cb.set_text(alt).map_err(|e| e.to_string());
                }
                Ok(())
            }
            Content::Image { width, height, rgba } => self
                .cb
                .set_image(ImageData {
                    width: *width as usize,
                    height: *height as usize,
                    bytes: Cow::Borrowed(rgba),
                })
                .map_err(|e| e.to_string()),
            Content::Files(files) => {
                let paths = self.save_files(files).map_err(|e| e.to_string())?;
                self.note_paths(paths.clone(), true);
                // On Windows arboard adds CF_HDROP next to whatever is already
                // there; clear first so text apps don't paste the old text.
                let _ = self.cb.clear();
                self.cb.set().file_list(&paths).map_err(|e| e.to_string())
            }
        }
    }

    /// Received files land in their own batch folder, then go on the clipboard
    /// as real files, so Finder/Explorer paste works like a local copy.
    fn save_files(&self, files: &[(String, Vec<u8>)]) -> std::io::Result<Vec<PathBuf>> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let dir = self.receive_dir.join(format!("batch-{stamp}"));
        fs::create_dir_all(&dir)?;
        let mut out = Vec::new();
        for (i, (name, data)) in files.iter().enumerate() {
            let safe = Path::new(name)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .filter(|n| !n.is_empty() && n != "." && n != "..")
                .unwrap_or_else(|| format!("file-{i}"));
            let mut path = dir.join(&safe);
            if path.exists() {
                path = dir.join(format!("{i}-{safe}"));
            }
            fs::write(&path, data)?;
            out.push(path);
        }
        Ok(out)
    }
}
