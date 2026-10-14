//! Native clipboard access plus a cheap "did the clipboard change?" counter.
//!
//! arboard does the format work: on macOS it reads screenshots (TIFF/PNG) and
//! writes NSImage; on Windows it reads CF_DIBV5/PNG and writes both CF_DIBV5 and
//! the registered "PNG" format, so Paint, Teams, Outlook and browsers all accept
//! a paste. File copies map to NSURLs on macOS and CF_HDROP on Windows.

use crate::log;
use crate::proto::{human_bytes, Content};
use arboard::{Clipboard, ImageData};
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns a counter the OS bumps on every clipboard change, if the platform has one.
/// Polling this is nearly free, so we only read actual content when it moves.
#[cfg(windows)]
pub fn change_count() -> Option<u64> {
    Some(unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() } as u64)
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

pub struct Clip {
    cb: Clipboard,
    receive_dir: PathBuf,
    max_file_bytes: usize,
    last_paths: Vec<PathBuf>,
}

impl Clip {
    pub fn new(receive_dir: PathBuf, max_file_bytes: usize) -> Result<Self, arboard::Error> {
        Ok(Self { cb: Clipboard::new()?, receive_dir, max_file_bytes, last_paths: Vec::new() })
    }

    /// Read the current clipboard. `fresh` is true when the OS change counter
    /// says something new was copied; without a counter (Linux) we skip
    /// re-reading the same file list on every poll.
    pub fn read(&mut self, fresh: bool) -> Option<Content> {
        if let Ok(paths) = self.cb.get().file_list()
            && !paths.is_empty() {
                if !fresh && paths == self.last_paths {
                    return None;
                }
                self.last_paths = paths.clone();
                return self.read_files(&paths);
            }
        self.last_paths.clear();
        if let Ok(t) = self.cb.get_text()
            && !t.is_empty() {
                return Some(Content::Text(t));
            }
        if let Ok(img) = self.cb.get_image()
            && img.width > 0 && img.height > 0 {
                return Some(Content::Image {
                    width: img.width as u32,
                    height: img.height as u32,
                    rgba: img.bytes.into_owned(),
                });
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
            Content::Text(t) => self.cb.set_text(t.as_str()).map_err(|e| e.to_string()),
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
                self.last_paths = paths.clone();
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
