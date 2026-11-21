<img src="assets/icon.svg" width="64" height="64" alt="">

# ClipCascade Lite

RustとWin32で作った、既存の [ClipCascade](https://github.com/Sathvik-Rao/ClipCascade) サーバーに接続する超軽量Windowsクライアントです。サーバーの設定に合わせてP2PとP2Sを自動で切り替えます。

## Windowsで使う

1. `cargo build --release --locked` でビルドし、`target\release\clipcascade-lite.exe` を開きます。
2. 初回はメイン画面にサーバーのURLとユーザー名を入力し、「設定を保存」を選びます。保存済みパスワードや公式版の保存セッションを利用できる場合は、パスワード欄を空のまま接続できます。
3. 暗号化、ソルト、鍵導出の反復回数を相手端末と揃えて「接続」を選びます。Android側では公式アプリの「Start sync」で同期を開始します。
4. P2Pでは接続端末が現れると、P2Sではサーバー中継に接続すると、Windowsでコピーしたテキスト、画像、複数ファイルを同期できます。Androidからは公式アプリの共有操作も使えます。Windowsで受信したファイルは、設定したフォルダーの下に受信単位で保存され、エクスプローラーに貼り付けられます。

メイン画面から切断、一時停止・再開、現在のクリップボードの手動送信、保存先の表示、設定保存ができます。「トレイへ」で同期を続けながらウィンドウを隠し、トレイアイコンから開き直せます。ウィンドウを閉じると終了します。設定は `%LOCALAPPDATA%\ClipCascade Lite\settings.json` に保存します。

「パスワードを保存」をオンにしてパスワードを入力し、接続に成功すると、Windows資格情報マネージャーにサーバー・ユーザー名ごとに保存します。次回起動時は保存済み設定とパスワードが揃っていれば自動で接続を開始します。「保存済みパスワードを削除」は表示中のサーバーとユーザー名に対応する資格情報を削除します。

Liteで使用できるパスワードが未入力かつ保存されていない場合、環境変数 `CLIPCASCADE_OFFICIAL_DATA` に公式版の `DATA` ファイルパスを指定していれば、有効な公式版セッションを再利用できます。

画像・ファイルの同期、転送上限、保存先、カスタムCA証明書（PEM）は接続前に設定できます。転送上限は既定で32 MiB、最大256 MiBです。

「同期履歴」では送信・受信したテキストと画像を時刻順に選び、内容をプレビューできます。履歴は起動中の最新60件かつ合計16 MiBまで保持し、画面から消去できます。

「診断ログ」には日時、接続状態、転送結果、エラーを記録します。最新300件を画面に表示し、`%LOCALAPPDATA%\ClipCascade Lite\logs` に約512 KiBずつの現行・前回ファイル（`diagnostic.log`）と、詳細な接続解析用のデバッグログ（`debug.log`、クリップボード内容や認証情報は含みません）を保存します。診断ログ画面から保存フォルダーを開けます。

公式サーバーのP2Pモードでは、サーバーが接続の仲介を行い、クリップボードデータは端末間で直接転送します。P2S（Peer-to-Server）モードでは、サーバーが各端末のデータを中継します。P2Sではサーバー側の転送上限も適用されます。

## 検証

`cargo test --release --locked` で、従来JSONとCCB1の各形式について、暗号化の有無、分割転送、破損した暗号化データの拒否を検証します。

公式Android版との相互接続テストは隔離した検証環境用です。公式サーバーをループバックの18765番で検証したいモードに設定し、初期アカウントでログインした公式Androidアプリを同じサーバーへ接続します。Windows側で環境変数 `CLIPCASCADE_ANDROID_INTEROP=1` を指定して `cargo test --release --locked official_android_interop -- --ignored --nocapture` を実行します。

Androidから `android-to-rust-351`、2×2のPNG（左上RGBAは `231,21,55,255`）、`android-a.txt`（内容は `android file a`）と `android-b.bin`（`0xD2` を57,000バイト）を順に共有します。各転送後に、Androidで返信を受信できたことを確認します。最後に `rust-a.txt` と `rust-b.bin` をAndroidで保存して内容を確認し、`downloaded-rust-files-351` を共有するとテストが完了します。

## ライセンス

[GNU General Public License v3.0](LICENSE) の下で公開しています。プロトコル互換のクライアントとして [Sathvik-Rao/ClipCascade](https://github.com/Sathvik-Rao/ClipCascade) に対応しています。
