<img src="assets/icon.svg" width="64" height="64" alt="ClipCascade Lite icon">

# ClipCascade Lite

English | [日本語](README.ja.md)

[![CI](https://github.com/GoodLight999/clipcascade-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/GoodLight999/clipcascade-lite/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GoodLight999/clipcascade-lite)](https://github.com/GoodLight999/clipcascade-lite/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

An ultra-lightweight Windows desktop client built with **Rust** and native **Win32 API**, protocol-compatible with [ClipCascade](https://github.com/Sathvik-Rao/ClipCascade) servers. It automatically detects and switches between **P2P (WebRTC)** and **P2S (STOMP relay)** modes.

> **Disclaimer**: This is an **unofficial**, independent third-party client. It is not affiliated with or endorsed by the official ClipCascade project or its author.

## Features

- **Native Rust + Win32 GUI**: Single standalone executable with minimal memory and CPU footprint.
- **Full ClipCascade Protocol Compatibility**:
  - Automatic **P2P** (WebRTC DataChannel) and **P2S** (STOMP over WebSocket) mode detection.
  - Supports both **CCB1 binary framing** and legacy JSON format.
  - Optional **end-to-end encryption** (AES-256-GCM + PBKDF2-HMAC-SHA256) matching the official clients.
  - Bidirectional sync for **text**, **images**, and **multiple files** (received files are saved per transfer and placed on the Windows clipboard for direct paste in Explorer).
- **Fast P2P Auto-Recovery**: Detects stalled or failed WebRTC handshakes quickly and automatically retries or rejoins signaling.
- **Seamless Everyday Use**:
  - Stores credentials securely in **Windows Credential Manager** (scoped per server URL and username).
  - **Auto-connect on launch** when server URL, username, and a saved password are present.
  - System tray minimization, pause/resume, manual send, in-session **sync history** preview (text & image), and **diagnostic/debug logs**.
  - Custom PEM CA certificate support for self-hosted servers.

## Installation

### Download a Prebuilt Binary

1. Download `clipcascade-lite-windows-x86_64.exe` from [GitHub Releases](https://github.com/GoodLight999/clipcascade-lite/releases).
2. Place it in any folder and run it (no installer required).

### Build from Source

Requires the [Rust toolchain](https://rustup.rs/) on Windows:

```powershell
cargo build --release --locked
```

The compiled executable will be at `target\release\clipcascade-lite.exe`.

## Usage

1. Launch `clipcascade-lite.exe` and enter your ClipCascade server URL, username, and password.
2. Match your encryption settings (E2E encryption toggle, salt, PBKDF2 hash rounds) with your other devices (such as the official Android app).
3. Click **保存** (Save) and **接続** (Connect).
   - With **パスワードを保存** (Remember password) enabled, the password is saved in Windows Credential Manager upon successful login, and subsequent launches will connect automatically.
   - If you prefer reusing an existing official ClipCascade desktop session without entering a password, you can set the optional `CLIPCASCADE_OFFICIAL_DATA` environment variable to the path of the official client's `DATA` file.
4. Once connected (peer count ≥ 1 in P2P mode, or relay connected in P2S mode), copying text, images, or files syncs automatically.

> Note: The desktop GUI is currently localized in Japanese.

## Settings & Logs

- **Settings**: `%LOCALAPPDATA%\ClipCascade Lite\settings.json`
- **Credentials**: Windows Credential Manager (`ClipCascade Lite/<sha256>`)
- **Logs**: `%LOCALAPPDATA%\ClipCascade Lite\logs\`
  - `diagnostic.log` (+ `diagnostic.previous.log`, ~512 KiB rotation): user-facing connection & transfer log (also shown in the **診断ログ** tab, latest 300 entries).
  - `debug.log` (+ `debug.previous.log`, ~1 MiB rotation): detailed signaling/WebRTC state transitions for troubleshooting. Passwords, keys, public IPs, and clipboard contents are never written to logs.
- **Sync History**: Held in memory only (up to 60 items / 16 MiB) and cleared on exit.
- **Transfer Limit**: Default 32 MiB, configurable up to 256 MiB (server limits also apply in P2S mode).

## Testing

Run the unit and local P2P loopback tests:

```powershell
cargo test --release --locked
```

Optional isolated interop tests (against a local loopback official ClipCascade server on `127.0.0.1:18765` and the official Android app) are marked `#[ignore]` and require explicit opt-in environment variables (`CLIPCASCADE_ANDROID_INTEROP=1`, `CLIPCASCADE_P2P_TEST=1`, `CLIPCASCADE_P2S_TEST=1`).

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
Compatible with [Sathvik-Rao/ClipCascade](https://github.com/Sathvik-Rao/ClipCascade).
