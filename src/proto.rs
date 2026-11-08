//! Wire messages and content hashing.
//!
//! Every message is a single plaintext buffer (encrypted by `net`), laid out as
//! one kind byte followed by a kind-specific body. Integers are big-endian.

use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read};

/// Clipboard content in a platform-neutral form.
#[derive(Clone, Debug, PartialEq)]
pub enum Content {
    Text(String),
    /// Formatted text: HTML plus the plain-text version for apps that can't take HTML.
    Rich { text: String, html: String },
    /// Raw RGBA8 pixels, normalized so macOS TIFF and Windows DIB both map here.
    Image { width: u32, height: u32, rgba: Vec<u8> },
    /// Copied files: (file name, contents).
    Files(Vec<(String, Vec<u8>)>),
}

impl Content {
    /// Stable hash of the *content*, used to stop the two sides echoing the same
    /// clipboard back and forth.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        match self {
            Content::Text(t) => return text_hash(t),
            Content::Rich { text, html } => {
                h.update(b"r");
                h.update((text.len() as u64).to_be_bytes());
                h.update(text.as_bytes());
                h.update(html.as_bytes());
            }
            Content::Image { width, height, rgba } => {
                h.update(b"i");
                h.update(width.to_be_bytes());
                h.update(height.to_be_bytes());
                h.update(rgba);
            }
            Content::Files(files) => {
                h.update(b"f");
                for (name, data) in files {
                    h.update((name.len() as u64).to_be_bytes());
                    h.update(name.as_bytes());
                    h.update((data.len() as u64).to_be_bytes());
                    h.update(data);
                }
            }
        }
        h.finalize().into()
    }

    /// For rich text, the hash its plain-text version would have on its own.
    /// Lets the sync recognise a text-only echo of formatted content.
    pub fn plain_hash(&self) -> Option<[u8; 32]> {
        match self {
            Content::Rich { text, .. } => Some(text_hash(text)),
            _ => None,
        }
    }

    /// Drop formatting: rich text becomes its plain-text version.
    pub fn into_plain(self) -> Content {
        match self {
            Content::Rich { text, .. } => Content::Text(text),
            other => other,
        }
    }

    /// True for text that is nothing but `file://` links, one per line. That is
    /// how a remote-desktop app's own clipboard sharing (Jump Desktop does this)
    /// passes on a file copy, since it can only carry text. The links point at
    /// the other machine's disk, so they are useless here and must neither be
    /// echoed back nor allowed to replace the real files.
    pub fn is_file_url_list(&self) -> bool {
        let text = match self {
            Content::Text(t) => t,
            Content::Rich { text, .. } => text,
            _ => return false,
        };
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let Some(first) = lines.next() else { return false };
        is_file_url(first) && lines.all(is_file_url)
    }

    pub fn describe(&self) -> String {
        match self {
            Content::Text(t) => format!("text ({} chars)", t.chars().count()),
            Content::Rich { text, html } => {
                // HTML-only items have no plain text; count the HTML instead.
                let shown = if text.is_empty() { html } else { text };
                format!("rich text ({} chars)", shown.chars().count())
            }
            Content::Image { width, height, .. } => format!("image {width}x{height}"),
            Content::Files(f) => {
                let total: usize = f.iter().map(|(_, d)| d.len()).sum();
                format!("{} file(s), {}", f.len(), human_bytes(total))
            }
        }
    }
}

fn is_file_url(line: &str) -> bool {
    line.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("file://"))
}

fn text_hash(t: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"t");
    h.update(t.as_bytes());
    h.finalize().into()
}

#[derive(Debug, PartialEq)]
pub enum Message {
    Hello { name: String },
    Ping,
    Clip(Content),
}

const K_HELLO: u8 = 0;
const K_PING: u8 = 1;
const K_TEXT: u8 = 2;
const K_IMAGE_PNG: u8 = 3;
const K_FILES: u8 = 4;
const K_RICH: u8 = 5;

impl Message {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Message::Hello { name } => {
                out.push(K_HELLO);
                out.extend_from_slice(name.as_bytes());
            }
            Message::Ping => out.push(K_PING),
            Message::Clip(Content::Text(t)) => {
                out.push(K_TEXT);
                out.extend_from_slice(t.as_bytes());
            }
            Message::Clip(Content::Rich { text, html }) => {
                // u32 text length, text, then the HTML up to the end.
                out.push(K_RICH);
                let t = text.as_bytes();
                let tlen = u32::try_from(t.len()).map_err(|_| bad("text too long"))?;
                out.extend_from_slice(&tlen.to_be_bytes());
                out.extend_from_slice(t);
                out.extend_from_slice(html.as_bytes());
            }
            Message::Clip(Content::Image { width, height, rgba }) => {
                // PNG on the wire: lossless and typically 5-20x smaller than raw RGBA.
                out.push(K_IMAGE_PNG);
                let img = image::RgbaImage::from_raw(*width, *height, rgba.clone())
                    .ok_or_else(|| bad("image buffer size mismatch"))?;
                let mut png = Cursor::new(Vec::new());
                img.write_to(&mut png, image::ImageFormat::Png)
                    .map_err(|e| bad(&format!("png encode: {e}")))?;
                out.extend_from_slice(&png.into_inner());
            }
            Message::Clip(Content::Files(files)) => {
                out.push(K_FILES);
                out.extend_from_slice(&(files.len() as u32).to_be_bytes());
                for (name, data) in files {
                    let n = name.as_bytes();
                    if n.len() > u16::MAX as usize {
                        return Err(bad("file name too long"));
                    }
                    out.extend_from_slice(&(n.len() as u16).to_be_bytes());
                    out.extend_from_slice(n);
                    out.extend_from_slice(&(data.len() as u64).to_be_bytes());
                    out.extend_from_slice(data);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> io::Result<Message> {
        let (&kind, body) = buf.split_first().ok_or_else(|| bad("empty message"))?;
        Ok(match kind {
            K_HELLO => Message::Hello { name: utf8(body)? },
            K_PING => Message::Ping,
            K_TEXT => Message::Clip(Content::Text(utf8(body)?)),
            K_RICH => {
                let mut c = Cursor::new(body);
                let tlen = read_u32(&mut c)? as usize;
                let text = utf8(&take(&mut c, tlen)?)?;
                let html = utf8(&body[c.position() as usize..])?;
                Message::Clip(Content::Rich { text, html })
            }
            K_IMAGE_PNG => {
                let img = image::load_from_memory_with_format(body, image::ImageFormat::Png)
                    .map_err(|e| bad(&format!("png decode: {e}")))?
                    .to_rgba8();
                let (width, height) = img.dimensions();
                Message::Clip(Content::Image { width, height, rgba: img.into_raw() })
            }
            K_FILES => {
                let mut c = Cursor::new(body);
                let count = read_u32(&mut c)? as usize;
                let mut files = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    let nlen = read_u16(&mut c)? as usize;
                    let name = utf8(&take(&mut c, nlen)?)?;
                    let dlen = read_u64(&mut c)? as usize;
                    files.push((name, take(&mut c, dlen)?));
                }
                Message::Clip(Content::Files(files))
            }
            k => return Err(bad(&format!("unknown message kind {k}"))),
        })
    }
}

fn take(c: &mut Cursor<&[u8]>, n: usize) -> io::Result<Vec<u8>> {
    let remaining = c.get_ref().len() - c.position() as usize;
    if n > remaining {
        return Err(bad("truncated message"));
    }
    let mut v = vec![0; n];
    c.read_exact(&mut v)?;
    Ok(v)
}
fn read_u16(c: &mut Cursor<&[u8]>) -> io::Result<u16> {
    Ok(u16::from_be_bytes(take(c, 2)?.try_into().unwrap()))
}
fn read_u32(c: &mut Cursor<&[u8]>) -> io::Result<u32> {
    Ok(u32::from_be_bytes(take(c, 4)?.try_into().unwrap()))
}
fn read_u64(c: &mut Cursor<&[u8]>) -> io::Result<u64> {
    Ok(u64::from_be_bytes(take(c, 8)?.try_into().unwrap()))
}
fn utf8(b: &[u8]) -> io::Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| bad("invalid utf-8"))
}
pub fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub fn human_bytes(n: usize) -> String {
    let n = n as f64;
    if n < 1024.0 {
        format!("{n} B")
    } else if n < 1024.0 * 1024.0 {
        format!("{:.1} KB", n / 1024.0)
    } else {
        format!("{:.1} MB", n / 1024.0 / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_kinds() {
        let rgba: Vec<u8> = (0..(7 * 5 * 4)).map(|i| (i * 37 % 256) as u8).collect();
        let msgs = vec![
            Message::Hello { name: "mac-studio".into() },
            Message::Ping,
            Message::Clip(Content::Text("héllo 👋\r\nworld".into())),
            Message::Clip(Content::Rich {
                text: "bold 👋\nnext".into(),
                html: "<b>bold</b> 👋<br>next".into(),
            }),
            Message::Clip(Content::Rich { text: String::new(), html: "<p></p>".into() }),
            Message::Clip(Content::Image { width: 7, height: 5, rgba }),
            Message::Clip(Content::Files(vec![
                ("a.txt".into(), b"abc".to_vec()),
                ("empty.bin".into(), vec![]),
            ])),
        ];
        for m in msgs {
            let enc = m.encode().unwrap();
            assert_eq!(Message::decode(&enc).unwrap(), m);
        }
    }

    #[test]
    fn rich_hash_covers_text_and_html() {
        let rich = |t: &str, h: &str| Content::Rich { text: t.into(), html: h.into() };
        let a = rich("hi", "<b>hi</b>");
        assert_ne!(a.hash(), rich("hi", "<i>hi</i>").hash());
        assert_ne!(a.hash(), rich("ho", "<b>hi</b>").hash());
        // The text/html boundary is part of the hash.
        assert_ne!(rich("ab", "c").hash(), rich("a", "bc").hash());
        assert_ne!(a.hash(), Content::Text("hi".into()).hash());
        assert_eq!(a.plain_hash(), Some(Content::Text("hi".into()).hash()));
        assert_eq!(a.into_plain(), Content::Text("hi".into()));
    }

    #[test]
    fn file_url_lists_are_recognised() {
        let t = |s: &str| Content::Text(s.into());
        assert!(t("file:///C:/Users/Brian/Downloads/deck.pptx").is_file_url_list());
        assert!(t("file:///C:/a.pptx\r\nFILE:///C:/b.pdf\r\n").is_file_url_list());
        assert!(Content::Rich { text: "file:///tmp/x".into(), html: "<a>x</a>".into() }.is_file_url_list());
        assert!(!t("see file:///C:/a.pptx for details").is_file_url_list());
        assert!(!t("file:///C:/a.pptx\nand a note").is_file_url_list());
        assert!(!t("").is_file_url_list());
        assert!(!t("héllo").is_file_url_list());
        assert!(!Content::Files(vec![("file://x".into(), vec![])]).is_file_url_list());
    }

    #[test]
    fn rejects_truncated_rich() {
        let m = Message::Clip(Content::Rich { text: "hello".into(), html: "<p>hello</p>".into() });
        let enc = m.encode().unwrap();
        // Cut inside the text: the declared length no longer fits.
        assert!(Message::decode(&enc[..1 + 4 + 3]).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let m = Message::Clip(Content::Files(vec![("x".into(), vec![1, 2, 3])]));
        let enc = m.encode().unwrap();
        assert!(Message::decode(&enc[..enc.len() - 1]).is_err());
    }
}
