//! Test helper (Linux/X11): set or read the clipboard from a script.
use arboard::{Clipboard, ImageData};
use std::{borrow::Cow, env, thread, time::Duration};
fn main() {
    let a: Vec<String> = env::args().collect();
    let mut cb = Clipboard::new().unwrap();
    match a[1].as_str() {
        "set-text" => { cb.set_text(a[2].clone()).unwrap(); thread::sleep(Duration::from_secs(4)); }
        "set-image" => {
            let (w, h) = (640usize, 400usize);
            let bytes: Vec<u8> = (0..w*h).flat_map(|i| [(i % 251) as u8, (i / w % 256) as u8, 90, 255]).collect();
            cb.set_image(ImageData { width: w, height: h, bytes: Cow::Owned(bytes) }).unwrap();
            thread::sleep(Duration::from_secs(4));
        }
        "set-files" => { cb.set().file_list(&a[2..]).unwrap(); thread::sleep(Duration::from_secs(4)); }
        "get" => {
            if let Ok(f) = cb.get().file_list() { if !f.is_empty() { println!("files {:?}", f); return; } }
            if let Ok(t) = cb.get_text() { println!("text {t:?}"); return; }
            if let Ok(i) = cb.get_image() { println!("image {}x{} sum={}", i.width, i.height, i.bytes.iter().map(|&b| b as u64).sum::<u64>()); return; }
            println!("empty");
        }
        _ => {}
    }
}
