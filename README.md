# ClipBridge

Two-way clipboard sync between your Windows PC and your Mac, built to run alongside
Jump Desktop. Jump handles the screen; ClipBridge makes copy/paste work in both
directions:

| Copy this… | …paste it on the other side as |
|---|---|
| Text | Text |
| Formatted text (from a browser, Word, Outlook, Pages, VS Code…) | Formatted text: bold, links, lists and tables paste as HTML, with a plain-text version for apps that only take text |
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

1. **Get the binary** for each machine from the **Actions** tab of this repo (every push
   builds Windows, Apple Silicon and Intel Mac versions), or build it yourself with
   [Rust](https://rustup.rs): `cargo build --release`.

2. **On the Mac**, run it. It listens on TCP 47800 and, since it has no key yet, shows a
   pairing code:
   ```
   clipbridge listen
   ```
   ```
   Pairing code for "Brians-MBP":   483 912
   ```
   Allow incoming connections if the macOS firewall asks. If macOS asks whether
   ClipBridge may access pasted content from other apps, choose **Allow**.

3. **On Windows**, connect to the Mac and type the code when asked:
   ```
   clipbridge connect brians-mbp.local
   ```
   The Mac's name is in System Settings → General → Sharing, under "Local hostname";
   on the same network it is reachable as that name plus `.local`.

   Both sides log `paired` and then `connected to "<other machine>"`. Copy something
   and you'll see `→ sending …` on one side and `← received …` on the other.

4. **If you can, turn off clipboard sharing in Jump Desktop** (or whichever remote-desktop
   app you use) for this connection; ClipBridge replaces it. Some Jump clients have no
   such setting, so ClipBridge also copes with it: Jump can only carry text and turns a
   file copy into a list of `file:///C:/...` links, which can land on top of the real
   files. ClipBridge never syncs such lists, and when one overwrites files it just copied
   or received, it puts the files back, so a paste gets real files.

That's it. The key agreed during pairing is saved on both machines and used from then on:

- Mac: `~/.config/clipbridge/key`
- Windows: `%LOCALAPPDATA%\ClipBridge\key.txt`

Both files are readable only by your account. To pair with a different machine later,
run `clipbridge listen --pair` on the Mac (and `clipbridge connect <mac> --pair` on
Windows): a fresh code replaces the stored key.

## Run automatically

**Mac:** copy `clipbridge` to `/usr/local/bin`, pair once as above, then:
```
cp install/macos/com.simplebit.clipbridge.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.simplebit.clipbridge.plist
```
The log is at `/tmp/clipbridge.log`. While the agent runs, you can't pair in a terminal
at the same time (the port is taken); pair first, or stop the agent with
`launchctl bootout gui/$(id -u)/com.simplebit.clipbridge`.

**Windows:** put `clipbridge.exe` next to the script, make sure the Mac is showing a
pairing code if you haven't paired yet, then in PowerShell:
```
.\install\windows\install-startup.ps1 -MacHost brians-mbp.local
```
It pairs if needed (you type the code), then registers a logon task that runs hidden and
keeps reconnecting. A console window may flash briefly at logon. The log is at
`%LOCALAPPDATA%\ClipBridge\clipbridge.log`.

## Networking

The Windows side connects out to the Mac. On the same LAN, use the Mac's `.local` name
or its IP. When you're remote, run it over **Tailscale** (or your VPN) and connect to the
Mac's tailnet name. Don't port-forward 47800 to the internet.

The address can be a name, an IPv4 address, or an IPv6 address; add a port with
`host:port`, and put IPv6 addresses in brackets when you do, e.g.
`clipbridge connect [fd7a:115c:a1e0::5]:47800`. If a name resolves to several
addresses (IPv6 and IPv4), each one is tried in turn.

## Security

Pairing runs SPAKE2, a password-authenticated key exchange, with the six-digit code as
the password. The code never crosses the network and can't be brute-forced from a
recording: a wrong guess only shows up as a failed connection, and the Mac then shows a
new code, so an attacker gets one guess per code. Each pairing produces a fresh 256-bit
key that both sides store.

Sessions are encrypted and authenticated with ChaCha20-Poly1305. Per-session keys are
derived from the stored key (stretched with PBKDF2-HMAC-SHA256) plus fresh randomness
from both sides. A client with the wrong key is rejected and can't disrupt the existing
connection. Until a peer has proved it knows the key, the listener only accepts a tiny
first message and at most 8 such connections at once. To limit exposure, bind the Mac to
a single interface, e.g. `clipbridge listen 100.x.y.z:47800`.

If you'd rather manage the key yourself, `clipbridge genkey` prints a passphrase to use
with `--key-file <path>` or `--key <secret>` on both machines; then no pairing happens.

## Options

```
clipbridge listen [bind] [--pair]
clipbridge connect <host> [--code 483912] [--pair]
clipbridge pair <host> [--code 483912]     pair and exit (used by the Windows installer)

--key-file <path>     where the key is kept (default: the paths above; or CLIPBRIDGE_KEY_FILE)
--key <secret>        use this passphrase instead of a stored key (or CLIPBRIDGE_KEY)
--name <name>         name shown to the other side (default: hostname)
--log <file>          also append the log to a file
--receive-dir <dir>   where received files go (default: ~/ClipBridge Received)
--max-mb <n>          max total size of copied files to sync (default 200)
--poll-ms <n>         clipboard check interval (default 250)
--plain-text          sync plain text only; don't carry HTML formatting over
--background          Windows: detach from the console window
```

## Notes and limits (v0.3)

- **Only one item type syncs per copy, chosen in this order: files, then text (with its
  HTML formatting, if the app provided any), then image.** So copying a spreadsheet range
  sends its text and HTML table, not a picture of it.
- **Formatting travels as HTML.** RTF-only content (some older apps) arrives as plain
  text. Use `--plain-text` if you'd rather never carry formatting over.
- **Folders are skipped.** Only files are copied. Zip a folder first if you need it.
- **Received files pile up.** They accumulate in `ClipBridge Received`; clear it out occasionally.
- **Both machines must run the same version.** v0.2 changed the key derivation and v0.3
  added pairing; older peers are refused with a message saying so.
- **It's a 1:1 bridge.** If a second machine connects with the right key, it replaces
  the current connection, and pairing again replaces the stored key.

## Layout

```
src/main.rs   CLI, key storage, pairing flow, clipboard watcher, sessions, reconnect
src/pair.rs   SPAKE2 pairing with a six-digit code
src/clip.rs   native clipboard read/write + OS change counters
src/proto.rs  message format (text / rich text / PNG image / files) and content hashing
src/net.rs    handshake, key derivation, encrypted framing
```
