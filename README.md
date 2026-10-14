# ClipBridge

Two-way clipboard sync between your Windows PC and your Mac, built to run alongside
Jump Desktop. Jump handles the screen; ClipBridge makes copy/paste work in both
directions:

| Copy this… | …paste it on the other side as |
|---|---|
| Text | Text |
| A screenshot (`⌃⇧⌘4` on Mac, `Win+Shift+S` on Windows) or any copied image | A real image: paste into Slack, Teams, Outlook, Paint, Preview, browsers |
| Files from Finder / Explorer | Real files: paste into Explorer / Finder (saved under `~/ClipBridge Received`) |

## Why it exists

- **Jump Desktop (Fluid)** syncs only text between Windows and Mac. Images never
  reach the other clipboard.
- **Synergy** only syncs when the cursor crosses between screens, which never happens
  inside a remote-desktop window. Its Mac-to-Windows screenshots also often fail to
  paste because of a TIFF vs DIB format mismatch.

ClipBridge watches the OS clipboard-change counter on each side: `NSPasteboard.changeCount`
on macOS and `GetClipboardSequenceNumber` on Windows. It converts images to plain RGBA,
sends them as PNG, and writes them back natively. On Windows that means writing both
`CF_DIBV5` and `PNG`, so every app accepts the paste.

## Quick start

1. **Build** (once per machine, needs [Rust](https://rustup.rs)):
   ```
   cargo build --release
   ```
   Binary: `target/release/clipbridge` (Mac) or `target\release\clipbridge.exe` (Windows).
   Or push this folder to a GitHub repo and download both builds from the **Actions** tab.

2. **Make a shared key** on either machine:
   ```
   clipbridge genkey
   ```
   Keys must be at least 12 characters. Save the key in a file that only you can read
   and pass it with `--key-file`, so it never shows up in the process list:
   - Mac: `~/.config/clipbridge/key`, then `chmod 600 ~/.config/clipbridge/key`
   - Windows: `%LOCALAPPDATA%\ClipBridge\key.txt` (the startup script below creates it
     with access limited to your account)

   `--key <key>` (or the `CLIPBRIDGE_KEY` environment variable) also works for a quick test.

3. **On the Mac** (listens on TCP 47800):
   ```
   clipbridge listen --key-file ~/.config/clipbridge/key
   ```
   Allow incoming connections if the macOS firewall asks. If macOS asks whether
   ClipBridge may access pasted content from other apps, choose **Allow**.

4. **On Windows:**
   ```
   clipbridge connect <mac-hostname-or-ip> --key-file %LOCALAPPDATA%\ClipBridge\key.txt
   ```
   Both windows should log `connected to "<other machine>"`. Copy something and you'll
   see `→ sending …` on one side and `← received …` on the other.

## Run automatically

**Mac:** copy `clipbridge` to `/usr/local/bin` and put your key in
`~/.config/clipbridge/key` (readable only by you):
```
mkdir -p ~/.config/clipbridge
(umask 077; nano ~/.config/clipbridge/key)     # paste the key, save
chmod 600 ~/.config/clipbridge/key
```
In `install/macos/com.simplebit.clipbridge.plist`, replace `REPLACE_WITH_USER` with your
user name (launchd doesn't expand `~`), then:
```
cp install/macos/com.simplebit.clipbridge.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.simplebit.clipbridge.plist
```
The log is at `/tmp/clipbridge.log`. Alternatively you can set the key through an
`EnvironmentVariables` entry for `CLIPBRIDGE_KEY` in the plist instead of `--key-file`,
but then the key sits in the plist in plain text.

**Windows:** put `clipbridge.exe` next to the script, then in PowerShell:
```
.\install\windows\install-startup.ps1 -MacHost my-mac -Key <key>
```
This saves the key to `%LOCALAPPDATA%\ClipBridge\key.txt` (access limited to your
account and SYSTEM) and registers a logon task that runs hidden with `--key-file` and
keeps reconnecting. A console window may flash briefly at logon. The log is at
`%LOCALAPPDATA%\ClipBridge\clipbridge.log`.

## Networking

The Windows side connects out to the Mac. On the same LAN, use the Mac's hostname or IP.
When you're remote, run it over **Tailscale** (or your VPN) and connect to the Mac's
tailnet name. Don't port-forward 47800 to the internet.

The address can be a name, an IPv4 address, or an IPv6 address; add a port with
`host:port`, and put IPv6 addresses in brackets when you do, e.g.
`clipbridge connect [fd7a:115c:a1e0::5]:47800`. If a name resolves to several
addresses (IPv6 and IPv4), each one is tried in turn.

Traffic is encrypted and authenticated with ChaCha20-Poly1305. Your passphrase is
stretched with PBKDF2-HMAC-SHA256 (600,000 rounds, once at startup), and
per-session keys are derived from it plus fresh randomness from both sides. A client
with the wrong key is rejected and can't disrupt the existing connection. Until a peer
has proved it knows the key, the listener only accepts a tiny first message and at most
8 such connections at once. To limit exposure, bind the Mac to a single interface,
e.g. `clipbridge listen 100.x.y.z:47800`.

## Options

```
--key-file <path>     read the shared passphrase from a file (or set CLIPBRIDGE_KEY_FILE)
--key <secret>        shared passphrase (or set CLIPBRIDGE_KEY); use one of the two
--name <name>         name shown to the other side (default: hostname)
--log <file>          also append the log to a file
--receive-dir <dir>   where received files go (default: ~/ClipBridge Received)
--max-mb <n>          max total size of copied files to sync (default 200)
--poll-ms <n>         clipboard check interval (default 250)
--background          Windows: detach from the console window
```

## Notes and limits (v0.1)

- **Only one item type syncs per copy, chosen in this order: files, then text, then image.**
  So copying a spreadsheet range sends its text, not a picture of it.
- **Folders are skipped.** Only files are copied. Zip a folder first if you need it.
- **Received files pile up.** They accumulate in `ClipBridge Received`; clear it out occasionally.
- **Rich text and HTML formatting are not carried over yet.** Only plain text syncs.
- **Both machines must run the same protocol version.** v0.2 changed the key derivation,
  so a v0.1 peer is refused with "peer is not ClipBridge v2".
- **It's a 1:1 bridge.** If a second machine connects with the right key, it replaces
  the current connection.

## Layout

```
src/main.rs   CLI, clipboard watcher, sessions, reconnect
src/clip.rs   native clipboard read/write + OS change counters
src/proto.rs  message format (text / PNG image / files) and content hashing
src/net.rs    handshake, key derivation, encrypted framing
```
