<img src="assets/icon.svg" width="64" height="64" alt="ClipCascade Lite icon">

# ClipCascade Lite

[English](README.md) | 日本語

[![CI](https://github.com/GoodLight999/clipcascade-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/GoodLight999/clipcascade-lite/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GoodLight999/clipcascade-lite)](https://github.com/GoodLight999/clipcascade-lite/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Rust とネイティブ Win32 API で作った、既存の [ClipCascade](https://github.com/Sathvik-Rao/ClipCascade) サーバーに接続する超軽量 Windows クライアントです。サーバーの設定に合わせて **P2P（WebRTC）** と **P2S（STOMP 中継）** を自動で切り替えます。

> **注意**：本ソフトウェアは第三者による**非公式（Unofficial）クライアント**です。公式の ClipCascade プロジェクトおよび開発者とは無関係であり、プロトコル互換の独立実装として作成しています。

## 主な特徴

- **超軽量ネイティブ実装（Rust + Win32）**：単体 EXE で動作し、メモリ・CPU 負荷を抑えています。
- **ClipCascade フル互換**：
  - サーバー設定に応じた **P2P**（WebRTC DataChannel） / **P2S**（STOMP over WebSocket）自動切替。
  - **CCB1 バイナリ形式**と従来 JSON 形式の両方に対応。
  - 公式版互換の**エンドツーエンド暗号化**（AES-256-GCM + PBKDF2-HMAC-SHA256）。
  - **テキスト・画像・複数ファイル**の双方向同期（Windows で受信したファイルは受信単位で保存され、そのままエクスプローラーへ貼り付け可能）。
- **P2P 自動復旧**：WebRTC 接続の失敗や待機詰まりを検知し、短時間での再試行・シグナリング自動再入室を行います。
- **普段使い向けの機能**：
  - **Windows 資格情報マネージャー**へのパスワード安全保存と、保存済み設定での**起動時自動接続**。
  - トレイ常駐、一時停止・再開、手動送信、起動中の**同期履歴プレビュー**（テキスト・画像）、**診断ログ／デバッグログ**。
  - セルフホスト環境向けのカスタム CA 証明書（PEM）対応。

## 導入方法

### ビルド済み EXE を使う

1. [GitHub Releases](https://github.com/GoodLight999/clipcascade-lite/releases) から `clipcascade-lite-windows-x86_64.exe` をダウンロードします。
2. 任意のフォルダーに置いて起動します（インストール不要）。

### ソースからビルドする

Windows 環境に [Rust ツールチェーン](https://rustup.rs/) を導入したうえで実行します：

```powershell
cargo build --release --locked
```

`target\release\clipcascade-lite.exe` が生成されます。

## 使い方

1. 起動後、メイン画面にサーバー URL・ユーザー名・パスワードを入力し、「設定を保存」を選びます。
2. 暗号化、ソルト、鍵導出の反復回数を相手端末（公式 Android アプリなど）と揃えて「接続」を選びます。
   - 「パスワードを保存」をオンにして接続に成功すると、Windows 資格情報マネージャーにサーバー・ユーザー名ごとに保存されます。次回起動時は保存済み設定とパスワードが揃っていれば自動で接続を開始します。
   - Lite で使用できるパスワードが未入力かつ保存されていない場合、環境変数 `CLIPCASCADE_OFFICIAL_DATA` に公式版の `DATA` ファイルパスを指定していれば、有効な公式版セッションを再利用できます。
3. P2P では接続端末が現れると、P2S ではサーバー中継に接続すると、Windows でコピーしたテキスト・画像・複数ファイルを自動同期できます。

メイン画面から切断、一時停止・再開、現在のクリップボードの手動送信、保存先の表示、設定保存、保存済みパスワードの削除ができます。「トレイへ」で同期を続けながらウィンドウを隠し、トレイアイコンから開き直せます。ウィンドウを閉じると終了します。

## 設定・ログ・制限

- **設定ファイル**：`%LOCALAPPDATA%\ClipCascade Lite\settings.json`
- **資格情報**：Windows 資格情報マネージャー（`ClipCascade Lite/<sha256>`）
- **転送上限**：既定 32 MiB、最大 256 MiB（P2S モードではサーバー側の上限も適用されます）
- **同期履歴**：起動中の最新 60 件かつ合計 16 MiB までメモリ上に保持し、終了時に消去します（画面から手動消去も可能）
- **ログ**：`%LOCALAPPDATA%\ClipCascade Lite\logs\`
  - `diagnostic.log`（約 512 KiB ごとにローテーション）：日時・接続状態・転送結果・エラーを記録（画面の「診断ログ」タブに最新 300 件を表示）
  - `debug.log`（約 1 MiB ごとにローテーション）：シグナリングや WebRTC 状態遷移などの詳細解析ログ（パスワード・鍵・公開 IP・クリップボード内容は記録しません）

## 検証

```powershell
cargo test --release --locked
```

従来 JSON と CCB1 の各形式（暗号化の有無・分割転送・破損データ拒否）、STOMP フレーム処理、P2P メッシュ接続、資格情報保存、診断・デバッグログなどを検証します。

公式 Android 版との相互接続テストは隔離した検証環境用です。公式サーバーをループバックの 18765 番で起動し、初期アカウントでログインした公式 Android アプリを同じサーバーへ接続したうえで、`CLIPCASCADE_ANDROID_INTEROP=1` を指定して `cargo test --release --locked official_android_interop -- --ignored --nocapture` を実行します。

## ライセンス

[GNU General Public License v3.0](LICENSE) の下で公開しています。プロトコル互換のクライアントとして [Sathvik-Rao/ClipCascade](https://github.com/Sathvik-Rao/ClipCascade) に対応しています。
