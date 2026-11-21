use crate::{
    clipboard,
    credentials::Target,
    diagnostic::DiskLog,
    network::{self, Event, Outbound, Reporter, Settings},
    protocol::{Content, Kind, MAX_LIMIT, Sharing},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    collections::VecDeque,
    ffi::OsStr,
    fs,
    io::Cursor,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use windows_sys::{
    Win32::{
        Foundation::*,
        Graphics::Gdi::*,
        System::{
            DataExchange::*, LibraryLoader::GetModuleHandleW, SystemInformation::GetLocalTime,
        },
        UI::{
            Controls::*,
            HiDpi::*,
            Input::KeyboardAndMouse::{EnableWindow, SetFocus},
            Shell::*,
            WindowsAndMessaging::*,
        },
    },
    w,
};
use zeroize::Zeroizing;

const TITLE: *const u16 = w!("ClipCascade Lite");
const CLASS: *const u16 = w!("ClipCascadeLite.Main");
const EVENTS: u32 = WM_APP + 1;
const TRAY: u32 = WM_APP + 2;
const READ_TIMER: usize = 1;
const SAME_CLIPBOARD_BURST: Duration = Duration::from_millis(1500);
const OPEN: usize = 1;
const CONNECT: usize = 101;
const PAUSE: usize = 102;
const SEND: usize = 103;
const FOLDER: usize = 104;
const HIDE: usize = 105;
const QUIT: usize = 106;
const SAVE: usize = 107;
const ENCRYPTED: usize = 108;
const CONNECTION_VIEW: usize = 110;
const HISTORY_VIEW: usize = 111;
const LOG_VIEW: usize = 112;
const HISTORY_LIST: usize = 113;
const CLEAR_HISTORY: usize = 114;
const OPEN_LOG_FOLDER: usize = 115;
const FORGET_PASSWORD: usize = 116;
const HISTORY_LIMIT: usize = 60;
const LOG_LIMIT: usize = 300;
const HISTORY_BYTES: usize = 16 * 1024 * 1024;
const WIDTH: i32 = 660;
const HEIGHT: i32 = 568;
const MIB: usize = 1024 * 1024;
const STATIC_NO_PREFIX: u32 = 0x80;
const STATIC_ETCHED_LINE: u32 = 0x10;
const STATIC_OWNER_DRAW: u32 = 0x0d;

thread_local! { static DISPATCHING: Cell<bool> = const { Cell::new(false) }; }

#[derive(Deserialize, Serialize)]
#[serde(default)]
struct Profile {
    server: String,
    username: String,
    encrypted: bool,
    remember_password: bool,
    salt: String,
    rounds: u32,
    ca: String,
    images: bool,
    files: bool,
    limit_mib: usize,
    directory: String,
}

impl Default for Profile {
    fn default() -> Self {
        let downloads = unsafe {
            let mut path = null_mut();
            if SHGetKnownFolderPath(&FOLDERID_Downloads, 0, null_mut(), &mut path) >= 0
                && !path.is_null()
            {
                let len = (0..).find(|&i| *path.add(i) == 0).unwrap();
                let result = String::from_utf16_lossy(std::slice::from_raw_parts(path, len));
                windows_sys::Win32::System::Com::CoTaskMemFree(path.cast());
                PathBuf::from(result)
            } else {
                std::env::var_os("USERPROFILE")
                    .map(PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir)
                    .join("Downloads")
            }
        };
        Self {
            server: String::new(),
            username: String::new(),
            encrypted: true,
            remember_password: true,
            salt: String::new(),
            rounds: 664_937,
            ca: String::new(),
            images: true,
            files: true,
            limit_mib: 32,
            directory: downloads
                .join("ClipCascade Lite")
                .to_string_lossy()
                .into_owned(),
        }
    }
}

impl Profile {
    fn path() -> Result<PathBuf> {
        Ok(PathBuf::from(
            std::env::var_os("LOCALAPPDATA").context("ローカル設定フォルダーが見つかりません")?,
        )
        .join("ClipCascade Lite")
        .join("settings.json"))
    }

    fn load() -> Result<Self> {
        match fs::read(Self::path()?) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;
        let candidate = dir.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            fs::write(&candidate, serde_json::to_vec_pretty(&self)?)?;
            fs::rename(&candidate, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(candidate);
        }
        result
    }

    fn sharing(&self) -> Sharing {
        Sharing {
            images: self.images,
            files: self.files,
            limit: self.limit_mib * MIB,
        }
    }
}

#[derive(Clone)]
struct WindowReporter {
    window: usize,
    session: u64,
    sender: mpsc::SyncSender<(u64, UiEvent)>,
}

enum UiEvent {
    Network(Event),
    Clipboard {
        sequence: u32,
        result: Result<Option<ClipboardSnapshot>>,
    },
    Applied {
        epoch: u64,
        sequence: u32,
        kind: Kind,
        size: usize,
        result: Result<Option<PathBuf>>,
    },
}

struct ClipboardSnapshot {
    content: Content,
    fingerprint: [u8; 32],
}

#[derive(Default)]
struct ClipboardBurst(Option<([u8; 32], Instant)>);

impl ClipboardBurst {
    fn should_send(&mut self, fingerprint: [u8; 32], manual: bool, now: Instant) -> bool {
        let repeated = self.0.is_some_and(|(previous, at)| {
            previous == fingerprint && now.duration_since(at) < SAME_CLIPBOARD_BURST
        });
        self.0 = Some((fingerprint, now));
        manual || !repeated
    }
}

impl WindowReporter {
    fn post(&self, event: UiEvent) {
        if self.sender.send((self.session, event)).is_ok() {
            unsafe {
                PostMessageW(self.window as HWND, EVENTS, 0, 0);
            }
        }
    }
}

impl Reporter for WindowReporter {
    fn emit(&self, event: Event) {
        self.post(UiEvent::Network(event));
    }
}

struct Active {
    outgoing: watch::Sender<Outbound>,
    paused: watch::Sender<bool>,
    cancel: oneshot::Sender<()>,
    sharing: Sharing,
    folder: PathBuf,
    pending_password: Option<(Target, Zeroizing<String>)>,
}

#[derive(Default)]
struct Fields {
    server: HWND,
    username: HWND,
    password: HWND,
    encrypted: HWND,
    remember_password: HWND,
    salt: HWND,
    rounds: HWND,
    ca: HWND,
    images: HWND,
    files: HWND,
    limit: HWND,
    directory: HWND,
    connect: HWND,
    pause: HWND,
    send: HWND,
    hide: HWND,
    status: HWND,
    peers: HWND,
    detail: HWND,
    navigation: [HWND; 3],
    history_list: HWND,
    history_title: HWND,
    history_text: HWND,
    history_image: HWND,
    log: HWND,
}

#[derive(Clone, Copy, PartialEq)]
enum View {
    Connection,
    History,
    Log,
}

struct HistoryEntry {
    time: String,
    outgoing: bool,
    content: Arc<Content>,
}

impl HistoryEntry {
    fn label(&self) -> String {
        let direction = if self.outgoing { "送信" } else { "受信" };
        format!(
            "{}   {}   {}",
            self.time,
            direction,
            self.content.kind().label()
        )
    }
}

struct App {
    window: HWND,
    fields: Fields,
    editable: Vec<HWND>,
    controls: Vec<(HWND, [i32; 4], bool)>,
    dpi: u32,
    font: HFONT,
    heading: HFONT,
    sender: mpsc::SyncSender<(u64, UiEvent)>,
    inbox: mpsc::Receiver<(u64, UiEvent)>,
    session: u64,
    active: Option<Active>,
    peer_count: usize,
    relay_ready: bool,
    sequence: u32,
    clipboard_burst: ClipboardBurst,
    read_in_progress: bool,
    read_pending: bool,
    manual_send: bool,
    apply_in_progress: bool,
    next_received: Option<Arc<Content>>,
    epoch: Arc<AtomicU64>,
    last_received_folder: Option<PathBuf>,
    tray: bool,
    taskbar_created: u32,
    view: View,
    pages: [std::ops::Range<usize>; 3],
    history: VecDeque<HistoryEntry>,
    history_size: usize,
    history_preview: Option<image::RgbaImage>,
    log: VecDeque<String>,
    disk_log: Option<DiskLog>,
}

impl App {
    fn new(window: HWND) -> Self {
        let (sender, inbox) = mpsc::sync_channel(4);
        let dpi = unsafe { GetDpiForWindow(window) }.max(96);
        Self {
            window,
            fields: Fields::default(),
            editable: Vec::new(),
            controls: Vec::new(),
            dpi,
            font: null_mut(),
            heading: null_mut(),
            sender,
            inbox,
            session: 0,
            active: None,
            peer_count: 0,
            relay_ready: false,
            sequence: 0,
            clipboard_burst: ClipboardBurst::default(),
            read_in_progress: false,
            read_pending: false,
            manual_send: false,
            apply_in_progress: false,
            next_received: None,
            epoch: Arc::new(AtomicU64::new(0)),
            last_received_folder: None,
            tray: false,
            taskbar_created: unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) },
            view: View::Connection,
            pages: [0..0, 0..0, 0..0],
            history: VecDeque::new(),
            history_size: 0,
            history_preview: None,
            log: VecDeque::new(),
            disk_log: None,
        }
    }

    fn scale(&self, value: i32) -> i32 {
        (value * self.dpi as i32 + 48) / 96
    }

    fn create(
        &mut self,
        class: *const u16,
        title: &str,
        style: u32,
        id: usize,
        bounds: [i32; 4],
        heading: bool,
    ) -> HWND {
        let [x, y, width, height] = bounds.map(|n| self.scale(n));
        let title = wide(title);
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class,
                title.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                x,
                y,
                width,
                height,
                self.window,
                id as HMENU,
                GetModuleHandleW(null()),
                null(),
            )
        };
        self.controls.push((hwnd, bounds, heading));
        hwnd
    }

    fn label(&mut self, title: &str, bounds: [i32; 4], heading: bool) -> HWND {
        self.create(w!("STATIC"), title, STATIC_NO_PREFIX, 0, bounds, heading)
    }

    fn edit(&mut self, label: &str, value: &str, y: i32, x: i32, width: i32, style: u32) -> HWND {
        self.label(label, [x, y, width, 20], false);
        let hwnd = self.create(
            w!("EDIT"),
            value,
            WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL as u32 | style,
            0,
            [x, y + 21, width, 27],
            false,
        );
        self.editable.push(hwnd);
        hwnd
    }

    fn check(&mut self, title: &str, id: usize, checked: bool, bounds: [i32; 4]) -> HWND {
        let hwnd = self.create(
            w!("BUTTON"),
            title,
            BS_AUTOCHECKBOX as u32 | WS_TABSTOP,
            id,
            bounds,
            false,
        );
        unsafe {
            SendMessageW(
                hwnd,
                BM_SETCHECK,
                if checked { BST_CHECKED as usize } else { 0 },
                0,
            );
        }
        self.editable.push(hwnd);
        hwnd
    }

    fn button(&mut self, title: &str, id: usize, bounds: [i32; 4]) -> HWND {
        self.create(
            w!("BUTTON"),
            title,
            if id == CONNECT {
                BS_DEFPUSHBUTTON as u32 | WS_TABSTOP
            } else {
                WS_TABSTOP
            },
            id,
            bounds,
            false,
        )
    }

    fn build(&mut self) -> Result<()> {
        let loaded = Profile::load();
        let load_error = loaded
            .as_ref()
            .err()
            .map(|e| format!("保存済み設定の読み込みに失敗しました · {e}"));
        let profile = loaded.unwrap_or_default();
        for (index, (id, title)) in [
            (CONNECTION_VIEW, "接続設定"),
            (HISTORY_VIEW, "同期履歴"),
            (LOG_VIEW, "診断ログ"),
        ]
        .into_iter()
        .enumerate()
        {
            self.fields.navigation[index] = self.create(
                w!("BUTTON"),
                title,
                (BS_CHECKBOX | BS_PUSHLIKE) as u32 | WS_TABSTOP,
                id,
                [24 + index as i32 * 108, 20, 102, 29],
                false,
            );
        }
        self.fields.peers = self.label("接続端末  0 台", [470, 25, 166, 24], false);
        self.fields.status = self.label("未接続", [24, 58, 612, 21], false);
        self.fields.detail = self.label("", [24, 82, 612, 42], false);
        self.create(
            w!("STATIC"),
            "",
            STATIC_ETCHED_LINE,
            0,
            [24, 128, 612, 2],
            false,
        );
        let connection = self.controls.len();
        self.label("サーバーとアカウント", [24, 142, 270, 28], true);
        self.fields.server = self.edit("サーバーURL", &profile.server, 180, 24, 612, 0);
        unsafe {
            SendMessageW(
                self.fields.server,
                EM_SETCUEBANNER,
                0,
                w!("https://clip.example.com") as isize,
            );
        }
        self.fields.username = self.edit("ユーザー名", &profile.username, 236, 24, 298, 0);
        self.fields.password = self.edit("パスワード", "", 236, 338, 298, ES_PASSWORD as u32);
        self.fields.encrypted = self.check(
            "エンドツーエンド暗号化",
            ENCRYPTED,
            profile.encrypted,
            [24, 294, 210, 26],
        );
        self.fields.remember_password = self.check(
            "パスワードを保存",
            0,
            profile.remember_password,
            [258, 294, 170, 26],
        );
        let forget = self.button(
            "保存済みパスワードを削除",
            FORGET_PASSWORD,
            [435, 294, 201, 26],
        );
        self.editable.push(forget);
        self.fields.salt = self.edit("暗号化ソルト", &profile.salt, 326, 24, 298, 0);
        self.fields.rounds = self.edit(
            "鍵導出の反復回数",
            &profile.rounds.to_string(),
            326,
            338,
            140,
            ES_NUMBER as u32,
        );
        self.fields.limit = self.edit(
            "転送上限（MiB）",
            &profile.limit_mib.to_string(),
            326,
            494,
            142,
            ES_NUMBER as u32,
        );
        self.fields.ca = self.edit(
            "カスタムCA証明書のパス（PEM・任意）",
            &profile.ca,
            382,
            24,
            612,
            0,
        );
        self.fields.images = self.check("画像を同期", 0, profile.images, [24, 438, 124, 24]);
        self.fields.files = self.check("ファイルを同期", 0, profile.files, [150, 438, 140, 24]);
        self.fields.directory =
            self.edit("受信ファイルの保存先", &profile.directory, 466, 24, 612, 0);
        self.fields.connect = self.button("接続", CONNECT, [24, 527, 90, 30]);
        self.fields.pause = self.button("一時停止", PAUSE, [120, 527, 88, 30]);
        self.fields.send = self.button("今すぐ送信", SEND, [214, 527, 98, 30]);
        self.button("保存先を開く", FOLDER, [318, 527, 108, 30]);
        self.button("設定を保存", SAVE, [432, 527, 98, 30]);
        self.fields.hide = self.button("トレイへ", HIDE, [536, 527, 100, 30]);
        let history = self.controls.len();
        self.label("この起動中の送受信", [24, 146, 300, 24], true);
        self.fields.history_list = self.create(
            w!("LISTBOX"),
            "",
            WS_TABSTOP | WS_BORDER | WS_VSCROLL | LBS_NOTIFY as u32,
            HISTORY_LIST,
            [24, 181, 225, 323],
            false,
        );
        self.fields.history_title = self.label("", [271, 181, 365, 32], false);
        self.fields.history_text = self.readonly_edit([271, 215, 365, 289]);
        self.fields.history_image = self.create(
            w!("STATIC"),
            "",
            STATIC_OWNER_DRAW,
            0,
            [271, 215, 365, 289],
            false,
        );
        self.label("最大60件／16 MiB · 終了時に消去", [24, 533, 430, 22], false);
        self.button("履歴を消去", CLEAR_HISTORY, [530, 527, 106, 30]);
        let logs = self.controls.len();
        self.label("診断ログ", [24, 146, 300, 24], true);
        self.fields.log = self.readonly_edit([24, 181, 612, 323]);
        self.label(
            "最新300件 · ログは再起動後も確認できます",
            [24, 533, 400, 22],
            false,
        );
        self.button("ログフォルダーを開く", OPEN_LOG_FOLDER, [447, 527, 189, 30]);
        self.pages = [
            connection..history,
            history..logs,
            logs..self.controls.len(),
        ];
        ensure!(
            self.controls.iter().all(|(handle, _, _)| !handle.is_null()),
            "Windowsの画面コントロールを生成できません"
        );
        self.rescale(self.dpi);
        self.change_view(View::Connection);
        self.refresh();
        if let Some(error) = load_error {
            self.detail(&error);
        }
        self.log("アプリを起動しました");
        Ok(())
    }

    fn readonly_edit(&mut self, bounds: [i32; 4]) -> HWND {
        self.create(
            w!("EDIT"),
            "",
            WS_TABSTOP
                | WS_BORDER
                | WS_VSCROLL
                | (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_NOHIDESEL) as u32,
            0,
            bounds,
            false,
        )
    }

    fn change_view(&mut self, view: View) {
        self.view = view;
        if view != View::History {
            self.history_preview = None;
        }
        let index = view as usize;
        unsafe {
            for (page, (range, &button)) in
                self.pages.iter().zip(&self.fields.navigation).enumerate()
            {
                let show = index == page;
                SendMessageW(
                    button,
                    BM_SETCHECK,
                    if show { BST_CHECKED as usize } else { 0 },
                    0,
                );
                for &(control, _, _) in &self.controls[range.clone()] {
                    ShowWindow(control, if show { SW_SHOWNA } else { SW_HIDE });
                }
            }
        }
        match view {
            View::History => self.render_history(),
            View::Log => self.render_log(),
            View::Connection => {}
        }
    }

    fn log(&mut self, message: &str) {
        if self.log.len() == LOG_LIMIT {
            self.log.pop_front();
        }
        let safe: String = message
            .chars()
            .take(800)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let line = format!("{}  {safe}", log_time());
        if let Some(log) = &self.disk_log
            && log.append(&line).is_err()
        {
            set(
                self.fields.detail,
                "診断ログを保存できません。ログフォルダーへの書き込みを確認してください",
            );
        }
        self.log.push_back(line);
        if self.view == View::Log {
            self.render_log();
        }
    }

    fn detail(&mut self, message: &str) {
        set(self.fields.detail, message);
        self.log(message);
    }

    fn render_log(&self) {
        set(
            self.fields.log,
            &self
                .log
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\r\n"),
        );
        unsafe {
            SendMessageW(self.fields.log, EM_SETSEL, usize::MAX, -1);
            SendMessageW(self.fields.log, EM_SCROLLCARET, 0, 0);
            SendMessageW(self.fields.log, WM_VSCROLL, SB_BOTTOM as usize, 0);
        }
    }

    fn record_history(&mut self, content: Arc<Content>, outgoing: bool) {
        if !matches!(content.kind(), Kind::Text | Kind::Image) || content.size() > HISTORY_BYTES {
            return;
        }
        self.history_size += content.size();
        self.history.push_front(HistoryEntry {
            time: local_time(),
            outgoing,
            content,
        });
        while self.history.len() > HISTORY_LIMIT || self.history_size > HISTORY_BYTES {
            self.history_size -= self.history.pop_back().unwrap().content.size();
        }
        if self.view == View::History {
            let previous = unsafe { SendMessageW(self.fields.history_list, LB_GETCURSEL, 0, 0) };
            let index = (previous.max(0) as usize) + usize::from(previous >= 0);
            self.refresh_history_list(index, previous < 0 || index >= self.history.len());
        }
    }

    fn render_history(&mut self) {
        self.refresh_history_list(0, true);
    }

    fn refresh_history_list(&mut self, index: usize, update_preview: bool) {
        unsafe {
            SendMessageW(self.fields.history_list, LB_RESETCONTENT, 0, 0);
            for entry in &self.history {
                SendMessageW(
                    self.fields.history_list,
                    LB_ADDSTRING,
                    0,
                    wide(entry.label()).as_ptr() as isize,
                );
            }
            if !self.history.is_empty() {
                SendMessageW(
                    self.fields.history_list,
                    LB_SETCURSEL,
                    index.min(self.history.len() - 1),
                    0,
                );
            }
        }
        if update_preview {
            self.show_history_selection();
        }
    }

    fn show_history_selection(&mut self) {
        let selected = unsafe { SendMessageW(self.fields.history_list, LB_GETCURSEL, 0, 0) };
        let mut image = None;
        let mut text = String::new();
        let mut title = "送受信したテキストと画像がここに表示されます。".to_owned();
        if let Some(entry) = self.history.get(selected as usize) {
            title = format!("{}   {} バイト", entry.label(), entry.content.size());
            match entry.content.as_ref() {
                Content::Text(value) => {
                    let mut chars = value.chars();
                    text = chars
                        .by_ref()
                        .take(20_000)
                        .collect::<String>()
                        .replace('\0', "�")
                        .replace("\r\n", "\n")
                        .replace('\n', "\r\n");
                    if chars.next().is_some() {
                        text.push_str("\r\n… プレビューの表示上限に達しました");
                    }
                }
                Content::Image(data) => {
                    image = history_thumbnail(data);
                    if image.is_none() {
                        text = "この画像はプレビューの表示範囲外です。".into();
                    }
                }
                Content::Files(_) => {}
            }
        }
        set(self.fields.history_title, &title);
        set(self.fields.history_text, &text);
        self.history_preview = image;
        unsafe {
            let shown = self.history_preview.is_some();
            ShowWindow(
                self.fields.history_text,
                if shown { SW_HIDE } else { SW_SHOWNA },
            );
            ShowWindow(
                self.fields.history_image,
                if shown { SW_SHOWNA } else { SW_HIDE },
            );
            InvalidateRect(self.fields.history_image, null(), 1);
        }
    }

    fn draw_history_image(&self, item: &DRAWITEMSTRUCT) {
        let Some(image) = &self.history_preview else {
            return;
        };
        let (width, height) = (image.width() as i32, image.height() as i32);
        let mut info: BITMAPINFO = unsafe { zeroed() };
        info.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth = width;
        info.bmiHeader.biHeight = -height;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        let bounds = item.rcItem;
        let (display_width, display_height) = (self.scale(width), self.scale(height));
        let x = bounds.left + (bounds.right - bounds.left - display_width) / 2;
        let y = bounds.top + (bounds.bottom - bounds.top - display_height) / 2;
        unsafe {
            FillRect(item.hDC, &bounds, GetSysColorBrush(COLOR_WINDOW));
            SetStretchBltMode(item.hDC, HALFTONE);
            StretchDIBits(
                item.hDC,
                x,
                y,
                display_width,
                display_height,
                0,
                0,
                width,
                height,
                image.as_raw().as_ptr().cast(),
                &info,
                DIB_RGB_COLORS,
                SRCCOPY,
            );
        }
    }

    fn rescale(&mut self, dpi: u32) {
        unsafe {
            let old_font = self.font;
            let old_heading = self.heading;
            self.dpi = dpi;
            self.font = CreateFontW(
                -self.scale(14),
                0,
                0,
                0,
                FW_NORMAL as i32,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                0,
                0,
                CLEARTYPE_QUALITY as u32,
                0,
                w!("Yu Gothic UI"),
            );
            self.heading = CreateFontW(
                -self.scale(20),
                0,
                0,
                0,
                FW_SEMIBOLD as i32,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                0,
                0,
                CLEARTYPE_QUALITY as u32,
                0,
                w!("Yu Gothic UI"),
            );
            for &(control, bounds, heading) in &self.controls {
                let [x, y, width, height] = bounds.map(|n| self.scale(n));
                MoveWindow(control, x, y, width, height, 1);
                SendMessageW(
                    control,
                    WM_SETFONT,
                    if heading { self.heading } else { self.font } as usize,
                    1,
                );
            }
            if !old_font.is_null() {
                DeleteObject(old_font);
            }
            if !old_heading.is_null() {
                DeleteObject(old_heading);
            }
        }
    }

    fn profile(&self) -> Result<Profile> {
        let f = &self.fields;
        let limit_mib = get(f.limit)
            .trim()
            .parse::<usize>()
            .context("転送上限をMiB単位の整数で入力してください")?;
        ensure!(
            (1..=MAX_LIMIT / MIB).contains(&limit_mib),
            "転送上限は1〜{} MiBで指定してください",
            MAX_LIMIT / MIB
        );
        let directory = get(f.directory).trim().to_owned();
        ensure!(
            Path::new(&directory).is_absolute(),
            "保存先には絶対パスを指定してください"
        );
        let rounds = get(f.rounds)
            .trim()
            .parse::<u32>()
            .context("鍵導出の反復回数を入力してください")?;
        ensure!(rounds > 0, "鍵導出の反復回数は1以上で指定してください");
        Ok(Profile {
            server: get(f.server).trim().to_owned(),
            username: get(f.username).trim().to_owned(),
            encrypted: checked(f.encrypted),
            remember_password: checked(f.remember_password),
            salt: get(f.salt),
            rounds,
            ca: get(f.ca).trim().to_owned(),
            images: checked(f.images),
            files: checked(f.files),
            limit_mib,
            directory,
        })
    }

    fn reporter(&self) -> WindowReporter {
        WindowReporter {
            window: self.window as usize,
            session: self.session,
            sender: self.sender.clone(),
        }
    }

    fn connect(&mut self) -> Result<()> {
        let profile = self.profile()?;
        crate::diagnostic::debug(&format!(
            "ui connect start encrypted={} remember_password={}",
            profile.encrypted, profile.remember_password
        ));
        let mut password = Zeroizing::new(get(self.fields.password));
        ensure!(
            !profile.server.is_empty() && !profile.username.is_empty(),
            "サーバーURLとユーザー名を入力してください"
        );
        let target = Target::new(&profile.server, &profile.username);
        let pending_password = if !password.is_empty() && profile.remember_password {
            Some((target, password.clone()))
        } else {
            if password.is_empty()
                && profile.remember_password
                && let Some(saved) = target.read()?
            {
                password = saved;
            }
            None
        };
        let sharing = profile.sharing();
        let folder = PathBuf::from(profile.directory);
        let mut settings = Settings {
            server: profile.server,
            username: profile.username,
            password,
            saved_session: None,
            encrypted: profile.encrypted,
            salt: profile.salt,
            rounds: profile.rounds,
            ca: (!profile.ca.is_empty()).then(|| PathBuf::from(profile.ca)),
            sharing,
        };
        if settings.password.is_empty() {
            let official_data = std::env::var_os("CLIPCASCADE_OFFICIAL_DATA")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .context("パスワードを入力してください")?;
            settings.saved_session = Some(
                network::SavedSession::from_official_file(&official_data, &settings)
                    .context("保存セッションで接続できません。パスワードを入力してください")?,
            );
        }
        let (outgoing, out_rx) = watch::channel(Outbound::default());
        let (paused, pause_rx) = watch::channel(false);
        let (cancel, cancel_rx) = oneshot::channel();
        self.session += 1;
        let reporter = self.reporter();
        std::thread::Builder::new().name("clipcascade-network".into()).spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread().enable_all().build()
                .map_err(anyhow::Error::from).and_then(|runtime| {
                    let result = runtime.block_on(async {
                        tokio::select! {
                            result = network::run(settings, out_rx, pause_rx, reporter.clone()) => result,
                            _ = cancel_rx => Ok(()),
                        }
                    });
                    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
                    result
                });
            if let Err(e) = result { reporter.emit(Event::Error(format!("{e:#}"))); }
            reporter.emit(Event::Ended);
        })?;
        self.active = Some(Active {
            outgoing,
            paused,
            cancel,
            sharing,
            folder,
            pending_password,
        });
        self.read_in_progress = false;
        self.last_received_folder = None;
        self.sequence = unsafe { GetClipboardSequenceNumber() };
        self.clipboard_burst = ClipboardBurst::default();
        set(self.fields.detail, "");
        set(self.fields.status, "接続しています…");
        self.refresh();
        Ok(())
    }

    fn try_auto_connect(&mut self) {
        let Ok(profile) = self.profile() else {
            crate::diagnostic::debug("startup auto-connect skipped: invalid profile");
            return;
        };
        if !should_auto_connect(&profile) {
            crate::diagnostic::debug(&format!(
                "startup auto-connect skipped: server_set={} user_set={} remember_password={}",
                !profile.server.is_empty(),
                !profile.username.is_empty(),
                profile.remember_password
            ));
            return;
        }
        match Target::new(&profile.server, &profile.username).read() {
            Ok(Some(password)) if !password.is_empty() => {
                crate::diagnostic::debug("startup auto-connect: saved password found, connecting");
                self.log("保存済みパスワードで自動接続します");
                if let Err(error) = self.connect() {
                    crate::diagnostic::debug(&format!("startup auto-connect failed: {error:#}"));
                    self.detail(&format!("自動接続に失敗しました · {error:#}"));
                }
            }
            Ok(_) => {
                crate::diagnostic::debug(
                    "startup auto-connect skipped: no saved password in credential manager",
                );
            }
            Err(error) => {
                crate::diagnostic::debug(&format!(
                    "startup auto-connect credential read error: {error:#}"
                ));
            }
        }
    }

    fn disconnect(&mut self) {
        crate::diagnostic::debug("ui disconnect");
        if let Some(active) = self.active.take() {
            let _ = active.cancel.send(());
        }
        self.session += 1;
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.next_received = None;
        self.peer_count = 0;
        self.relay_ready = false;
        self.read_pending = false;
        self.manual_send = false;
        unsafe {
            KillTimer(self.window, READ_TIMER);
        }
        set(self.fields.status, "未接続");
        self.refresh();
    }

    fn refresh(&self) {
        let connected = self.active.is_some();
        let paused = self
            .active
            .as_ref()
            .is_some_and(|active| *active.paused.borrow());
        let peers = if self.relay_ready {
            "サーバー中継".to_owned()
        } else {
            format!("接続端末  {} 台", self.peer_count)
        };
        set(self.fields.peers, &peers);
        set(self.fields.connect, if connected { "切断" } else { "接続" });
        set(
            self.fields.pause,
            if paused {
                "同期再開"
            } else {
                "一時停止"
            },
        );
        unsafe {
            EnableWindow(self.fields.pause, connected as i32);
            EnableWindow(
                self.fields.send,
                (connected && !paused && self.transport_ready()) as i32,
            );
            EnableWindow(self.fields.hide, self.tray as i32);
            for &field in &self.editable {
                EnableWindow(field, (!connected) as i32);
            }
            for field in [self.fields.salt, self.fields.rounds] {
                EnableWindow(field, (!connected && checked(self.fields.encrypted)) as i32);
            }
        }
    }

    fn command(&mut self, id: usize) -> Result<()> {
        match id {
            CONNECTION_VIEW => self.change_view(View::Connection),
            HISTORY_VIEW => self.change_view(View::History),
            LOG_VIEW => self.change_view(View::Log),
            OPEN_LOG_FOLDER => {
                let log = self
                    .disk_log
                    .as_ref()
                    .context("ログフォルダーが見つかりません")?;
                fs::create_dir_all(log.folder())?;
                let path = wide(log.folder());
                let result = unsafe {
                    ShellExecuteW(
                        self.window,
                        w!("open"),
                        path.as_ptr(),
                        null(),
                        null(),
                        SW_SHOWNORMAL,
                    )
                };
                ensure!(result as usize > 32, "ログフォルダーを開けません");
            }
            FORGET_PASSWORD if self.active.is_none() => {
                let server = get(self.fields.server);
                let username = get(self.fields.username);
                ensure!(
                    !server.trim().is_empty() && !username.trim().is_empty(),
                    "サーバーURLとユーザー名を入力してください"
                );
                Target::new(server.trim(), username.trim()).delete()?;
                set(self.fields.password, "");
                self.detail("このアカウントの保存済みパスワードを削除しました");
            }
            CLEAR_HISTORY => {
                self.history.clear();
                self.history_size = 0;
                self.render_history();
                self.detail("同期履歴を消去しました");
            }
            OPEN => unsafe {
                ShowWindow(self.window, SW_RESTORE);
                SetForegroundWindow(self.window);
            },
            CONNECT if self.active.is_some() => {
                self.disconnect();
                self.detail("接続を終了しました");
            }
            CONNECT => self.connect()?,
            PAUSE => {
                if let Some(active) = &self.active {
                    let paused = *active.paused.borrow();
                    active.paused.send_replace(!paused);
                    active.outgoing.send_replace(Outbound::default());
                    self.epoch.fetch_add(1, Ordering::Relaxed);
                    self.next_received = None;
                    self.sequence = unsafe { GetClipboardSequenceNumber() };
                    self.read_pending = false;
                    self.manual_send = false;
                    self.detail(if paused {
                        "同期を再開しました"
                    } else {
                        "送信と受信を一時停止しました"
                    });
                    self.refresh();
                }
            }
            SEND => self.schedule_read(true),
            FOLDER => {
                let dir = match &self.last_received_folder {
                    Some(path) => path.clone(),
                    None => PathBuf::from(self.profile()?.directory),
                };
                fs::create_dir_all(&dir)?;
                let path = wide(dir.as_os_str());
                let result = unsafe {
                    ShellExecuteW(
                        self.window,
                        w!("open"),
                        path.as_ptr(),
                        null(),
                        null(),
                        SW_SHOWNORMAL,
                    )
                };
                ensure!(result as usize > 32, "保存先を開けません");
            }
            HIDE if self.tray => unsafe {
                ShowWindow(self.window, SW_HIDE);
            },
            QUIT => unsafe {
                PostMessageW(self.window, WM_CLOSE, 0, 0);
            },
            SAVE => {
                self.profile()?.save().context("設定を保存できません")?;
                self.detail("接続設定を保存しました");
            }
            ENCRYPTED => self.refresh(),
            _ => {}
        }
        Ok(())
    }

    fn schedule_read(&mut self, force: bool) {
        if !self.transport_ready() || !self.active.as_ref().is_some_and(|a| !*a.paused.borrow()) {
            return;
        }
        let sequence = unsafe { GetClipboardSequenceNumber() };
        if self.apply_in_progress {
            self.manual_send |= force;
            return;
        }
        if force || self.sequence != sequence {
            self.sequence = sequence;
            self.read_pending = true;
            self.manual_send |= force;
            unsafe {
                SetTimer(self.window, READ_TIMER, 48, None);
            }
        }
    }

    fn transport_ready(&self) -> bool {
        self.relay_ready || self.peer_count > 0
    }

    fn read_clipboard(&mut self) {
        if !self.read_pending || self.read_in_progress || self.apply_in_progress {
            return;
        }
        let Some(active) = &self.active else {
            return;
        };
        if !self.transport_ready() || *active.paused.borrow() {
            return;
        }
        self.read_pending = false;
        self.read_in_progress = true;
        let reporter = self.reporter();
        let sequence = self.sequence;
        let sharing = active.sharing;
        let thread = std::thread::Builder::new()
            .name("clipcascade-clipboard".into())
            .spawn(move || {
                let result = clipboard::read(sharing).map(|content| {
                    content.map(|content| ClipboardSnapshot {
                        fingerprint: content.fingerprint(),
                        content,
                    })
                });
                reporter.post(UiEvent::Clipboard { sequence, result });
            });
        if thread.is_err() {
            self.read_in_progress = false;
            set(
                self.fields.detail,
                "クリップボードの読み込みを開始できません",
            );
        }
    }

    fn apply_received(&mut self, content: Arc<Content>) {
        if self.apply_in_progress {
            self.next_received = Some(content);
            return;
        }
        let Some(active) = &self.active else {
            return;
        };
        if *active.paused.borrow() {
            return;
        }
        let folder = active.folder.clone();
        let reporter = self.reporter();
        let guard = self.epoch.clone();
        let epoch = guard.load(Ordering::Relaxed);
        let before = unsafe { GetClipboardSequenceNumber() };
        let kind = content.kind();
        let size = content.size();
        self.apply_in_progress = true;
        set(
            self.fields.detail,
            &format!("受信中 · {} · {} バイト", kind.label(), size),
        );
        let thread = std::thread::Builder::new()
            .name("clipcascade-receive".into())
            .spawn(move || {
                let result = clipboard::apply(&content, &folder, || {
                    ensure!(guard.load(Ordering::Relaxed) == epoch, "同期を停止しました");
                    ensure!(
                        unsafe { GetClipboardSequenceNumber() } == before,
                        "クリップボードが更新されたため受信の反映を取り消しました"
                    );
                    Ok(())
                });
                let sequence = unsafe { GetClipboardSequenceNumber() };
                reporter.post(UiEvent::Applied {
                    epoch,
                    sequence,
                    kind,
                    size,
                    result,
                });
            });
        if thread.is_err() {
            self.apply_in_progress = false;
            set(self.fields.detail, "クリップボードへの反映を開始できません");
        }
    }

    fn drain(&mut self) {
        while let Ok((session, event)) = self.inbox.try_recv() {
            if session != self.session && !matches!(event, UiEvent::Applied { .. }) {
                continue;
            }
            match event {
                UiEvent::Network(Event::Status(message)) => {
                    set(self.fields.status, &message);
                    self.log(&message);
                }
                UiEvent::Network(Event::Authenticated) => {
                    let pending = self
                        .active
                        .as_mut()
                        .and_then(|active| active.pending_password.take());
                    if let Some((target, password)) = pending {
                        match target.write(&password) {
                            Ok(()) => {
                                set(self.fields.password, "");
                                self.log("Windows資格情報マネージャーにパスワードを保存しました");
                            }
                            Err(error) => {
                                self.detail(&format!("パスワードを保存できません · {error:#}"))
                            }
                        }
                    }
                }
                UiEvent::Network(Event::RelayReady(ready)) => {
                    self.relay_ready = ready;
                    if ready {
                        set(self.fields.status, "P2Sで接続中");
                        self.log("P2Sでサーバー中継に接続しました");
                    }
                    self.refresh();
                }
                UiEvent::Network(Event::Peers(count)) => {
                    if self.peer_count != count {
                        self.peer_count = count;
                        set(
                            self.fields.status,
                            if count > 0 {
                                "P2Pで接続中"
                            } else {
                                "シグナリング接続済み · 端末を待機中"
                            },
                        );
                        self.refresh();
                        self.log(&format!("接続端末数 {count} 台"));
                    }
                }
                UiEvent::Network(Event::Error(message)) => {
                    self.detail(&format!("エラー · {message}"))
                }
                UiEvent::Network(Event::Ended) => self.disconnect(),
                UiEvent::Network(Event::Sent(content, peers)) => {
                    let destination = if peers == 0 {
                        "サーバーへ".to_owned()
                    } else {
                        format!("{peers} 台")
                    };
                    self.detail(&format!(
                        "送信 · {} · {} バイト · {destination}",
                        content.kind().label(),
                        content.size()
                    ));
                    self.record_history(content, true);
                }
                UiEvent::Network(Event::Received(content)) => {
                    let content = Arc::new(content);
                    self.record_history(content.clone(), false);
                    self.apply_received(content);
                }
                UiEvent::Applied {
                    epoch,
                    sequence,
                    kind,
                    size,
                    result,
                } => {
                    self.apply_in_progress = false;
                    let current =
                        epoch == self.epoch.load(Ordering::Relaxed) && session == self.session;
                    if current {
                        match result {
                            Ok(folder) => {
                                if folder.is_some() {
                                    self.last_received_folder = folder;
                                }
                                self.sequence = sequence;
                                self.read_pending = false;
                                self.detail(&format!("受信 · {} · {} バイト", kind.label(), size));
                            }
                            Err(error) => {
                                self.detail(&format!("受信データを適用できません · {error:#}"))
                            }
                        }
                    }
                    if let Some(next) = self.next_received.take() {
                        self.apply_received(next);
                    } else {
                        self.schedule_read(self.manual_send);
                    }
                }
                UiEvent::Clipboard { sequence, result } => {
                    self.read_in_progress = false;
                    let current_sequence = unsafe { GetClipboardSequenceNumber() };
                    if self.sequence != current_sequence {
                        self.schedule_read(false);
                    }
                    let Some(active) = &self.active else {
                        continue;
                    };
                    if sequence == current_sequence
                        && sequence == self.sequence
                        && self.transport_ready()
                        && !self.apply_in_progress
                        && !*active.paused.borrow()
                    {
                        let manual = std::mem::take(&mut self.manual_send);
                        match result {
                            Ok(Some(snapshot))
                                if self.clipboard_burst.should_send(
                                    snapshot.fingerprint,
                                    manual,
                                    Instant::now(),
                                ) =>
                            {
                                active
                                    .outgoing
                                    .send_replace(Outbound::new(snapshot.content));
                            }
                            Ok(None) if manual => set(
                                self.fields.detail,
                                "送信できるクリップボード内容がありません",
                            ),
                            Err(error) => self.detail(&format!("読み込みエラー · {error:#}")),
                            _ => {}
                        }
                    }
                    self.read_clipboard();
                }
            }
        }
    }

    fn add_tray(&mut self) {
        let mut tray: NOTIFYICONDATAW = unsafe { zeroed() };
        tray.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        tray.hWnd = self.window;
        tray.uID = 1;
        tray.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        tray.uCallbackMessage = TRAY;
        tray.hIcon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
        let title = wide("ClipCascade Lite");
        tray.szTip[..title.len()].copy_from_slice(&title);
        self.tray = unsafe { Shell_NotifyIconW(NIM_ADD, &tray) } != 0;
    }

    fn tray_command(&mut self, message: u32) {
        if message == WM_LBUTTONUP {
            let _ = self.command(OPEN);
        } else if matches!(message, WM_RBUTTONUP | WM_CONTEXTMENU) {
            let command = unsafe {
                let menu = CreatePopupMenu();
                let mut point = POINT { x: 0, y: 0 };
                GetCursorPos(&mut point);
                AppendMenuW(menu, MF_STRING, OPEN, w!("メイン画面を開く"));
                if let Some(active) = &self.active {
                    AppendMenuW(
                        menu,
                        MF_STRING,
                        PAUSE,
                        if *active.paused.borrow() {
                            w!("同期再開")
                        } else {
                            w!("一時停止")
                        },
                    );
                    AppendMenuW(menu, MF_STRING, CONNECT, w!("切断"));
                }
                AppendMenuW(menu, MF_SEPARATOR, 0, null());
                AppendMenuW(menu, MF_STRING, QUIT, w!("終了"));
                SetForegroundWindow(self.window);
                let command = TrackPopupMenu(
                    menu,
                    TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                    point.x,
                    point.y,
                    0,
                    self.window,
                    null(),
                );
                DestroyMenu(menu);
                command
            };
            if command != 0 {
                let _ = self.command(command as usize);
            }
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            let _ = active.cancel.send(());
        }
        unsafe {
            RemoveClipboardFormatListener(self.window);
            let mut tray: NOTIFYICONDATAW = zeroed();
            tray.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
            tray.hWnd = self.window;
            tray.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &tray);
            if !self.font.is_null() {
                DeleteObject(self.font);
            }
            if !self.heading.is_null() {
                DeleteObject(self.heading);
            }
        }
    }
}

fn history_thumbnail(data: &[u8]) -> Option<image::RgbaImage> {
    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(48 * 1024 * 1024);
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    reader.limits(limits);
    let mut thumbnail = reader.decode().ok()?.thumbnail(341, 265).into_rgba8();
    for pixel in thumbnail.pixels_mut() {
        let [r, g, b, a] = pixel.0;
        let blend = |channel: u8| 255 - (((255 - u16::from(channel)) * u16::from(a)) / 255) as u8;
        pixel.0 = [blend(b), blend(g), blend(r), 255];
    }
    Some(thumbnail)
}

fn local_time() -> String {
    let time = system_time();
    format!("{:02}:{:02}:{:02}", time.wHour, time.wMinute, time.wSecond)
}

fn log_time() -> String {
    let time = system_time();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond
    )
}

fn system_time() -> SYSTEMTIME {
    let mut time = unsafe { zeroed::<SYSTEMTIME>() };
    unsafe {
        GetLocalTime(&mut time);
    }
    time
}

fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain([0]).collect()
}

fn set(window: HWND, text: &str) {
    unsafe {
        SetWindowTextW(window, wide(text).as_ptr());
    }
}

fn get(window: HWND) -> String {
    unsafe {
        let mut buf = Zeroizing::new(vec![0u16; (GetWindowTextLengthW(window) + 1) as usize]);
        let length = GetWindowTextW(window, buf.as_mut_ptr(), buf.len() as i32);
        String::from_utf16_lossy(&buf[..length as usize])
    }
}

fn should_auto_connect(profile: &Profile) -> bool {
    !profile.server.trim().is_empty()
        && !profile.username.trim().is_empty()
        && profile.remember_password
}

fn checked(window: HWND) -> bool {
    unsafe { SendMessageW(window, BM_GETCHECK, 0, 0) == BST_CHECKED as isize }
}

extern "system" fn window_proc(window: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        if message == WM_CREATE {
            return 0;
        }
        let raw = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut App;
        if raw.is_null() {
            return DefWindowProcW(window, message, wp, lp);
        }
        if DISPATCHING.get() {
            if matches!(
                message,
                WM_CLOSE | WM_COMMAND | WM_TIMER | WM_CLIPBOARDUPDATE | EVENTS | TRAY
            ) {
                PostMessageW(window, message, wp, lp);
                return 0;
            }
            return DefWindowProcW(window, message, wp, lp);
        }
        if message == WM_CLOSE || (message == WM_COMMAND && wp & 0xffff == QUIT) {
            DestroyWindow(window);
            return 0;
        }
        if message == WM_NCDESTROY {
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            drop(Box::from_raw(raw));
            PostQuitMessage(0);
            return DefWindowProcW(window, message, wp, lp);
        }
        DISPATCHING.set(true);
        let app = &mut *raw;
        match message {
            WM_COMMAND if wp & 0xffff == HISTORY_LIST && wp >> 16 == LBN_SELCHANGE as usize => {
                app.show_history_selection();
            }
            WM_COMMAND if wp >> 16 == 0 => {
                if let Err(error) = app.command(wp & 0xffff) {
                    app.detail(&format!("エラー · {error:#}"));
                }
            }
            WM_CLIPBOARDUPDATE => app.schedule_read(false),
            WM_TIMER if wp == READ_TIMER => {
                KillTimer(window, READ_TIMER);
                app.read_clipboard();
            }
            EVENTS => app.drain(),
            TRAY => app.tray_command(lp as u32),
            WM_DRAWITEM if lp != 0 => {
                let item = &*(lp as *const DRAWITEMSTRUCT);
                if item.hwndItem == app.fields.history_image {
                    app.draw_history_image(item);
                    DISPATCHING.set(false);
                    return 1;
                }
            }
            WM_DPICHANGED => {
                app.rescale((wp & 0xffff) as u32);
                let rect = &*(lp as *const RECT);
                SetWindowPos(
                    window,
                    null_mut(),
                    rect.left,
                    rect.top,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
            msg if msg == app.taskbar_created => {
                app.add_tray();
                app.refresh();
                if !app.tray && IsWindowVisible(window) == 0 {
                    ShowWindow(window, SW_RESTORE);
                }
            }
            _ => {
                DISPATCHING.set(false);
                return DefWindowProcW(window, message, wp, lp);
            }
        }
        DISPATCHING.set(false);
        0
    }
}

pub fn run() {
    unsafe {
        let existing = FindWindowW(CLASS, null());
        if !existing.is_null() {
            PostMessageW(existing, WM_COMMAND, OPEN, 0);
            return;
        }
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let instance = GetModuleHandleW(null());
        let icon = LoadIconW(null_mut(), IDI_APPLICATION);
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: CLASS,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hIcon: icon,
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
            ..zeroed()
        };
        if RegisterClassW(&class) == 0 {
            return;
        }
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        let ex_style = WS_EX_CONTROLPARENT;
        let window = CreateWindowExW(
            ex_style,
            CLASS,
            TITLE,
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WIDTH,
            HEIGHT,
            null_mut(),
            null_mut(),
            instance,
            null(),
        );
        if window.is_null() {
            return;
        }
        let mut app = Box::new(App::new(window));
        if let Ok(profile) = Profile::path() {
            let logs = profile.with_file_name("logs");
            crate::diagnostic::init_debug(logs.clone());
            crate::diagnostic::debug("app starting");
            let log = DiskLog::new(logs);
            if let Ok(recent) = log.recent(LOG_LIMIT) {
                app.log = recent;
            }
            app.disk_log = Some(log);
        }
        let mut rect = RECT {
            left: 0,
            top: 0,
            right: app.scale(WIDTH),
            bottom: app.scale(HEIGHT),
        };
        AdjustWindowRectExForDpi(&mut rect, style, 0, ex_style, app.dpi);
        SetWindowPos(
            window,
            null_mut(),
            0,
            0,
            rect.right - rect.left,
            rect.bottom - rect.top,
            SWP_NOZORDER | SWP_NOMOVE,
        );
        if let Err(e) = app.build() {
            MessageBoxW(
                window,
                wide(format!("{e:#}")).as_ptr(),
                TITLE,
                MB_OK | MB_ICONERROR,
            );
            DestroyWindow(window);
            return;
        }
        app.add_tray();
        app.refresh();
        AddClipboardFormatListener(window);
        SetFocus(app.fields.server);
        let raw = Box::into_raw(app);
        SetWindowLongPtrW(window, GWLP_USERDATA, raw as isize);
        ShowWindow(window, SW_SHOWNORMAL);
        (*raw).try_auto_connect();
        let mut message: MSG = zeroed();
        while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(window, &message) == 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_connect_requires_server_username_and_remember_password() {
        let mut profile = Profile::default();
        assert!(!should_auto_connect(&profile));
        profile.server = "https://clip.example.invalid".into();
        assert!(!should_auto_connect(&profile));
        profile.username = "alice".into();
        assert!(should_auto_connect(&profile));
        profile.remember_password = false;
        assert!(!should_auto_connect(&profile));
    }

    #[test]
    fn automatic_copy_collapses_matching_content_bursts() {
        let mut burst = ClipboardBurst::default();
        let start = Instant::now();
        let a = Content::Text("abcd".into()).fingerprint();
        let b = Content::Text("wxyz".into()).fingerprint();
        assert!(burst.should_send(a, false, start));
        assert!(!burst.should_send(a, false, start + Duration::from_millis(80)));
        assert!(!burst.should_send(a, false, start + Duration::from_millis(400)));
        assert!(burst.should_send(b, false, start + Duration::from_millis(450)));
        assert!(burst.should_send(a, false, start + Duration::from_millis(500)));
        assert!(burst.should_send(a, true, start + Duration::from_millis(550)));
        assert!(burst.should_send(a, false, start + Duration::from_millis(2500)));
    }

    #[test]
    #[ignore = "requires an isolated official P2S server on 127.0.0.1:18765"]
    fn p2s_login_remembers_password_and_diagnostics_across_app_instances() -> Result<()> {
        ensure!(
            std::env::var("CLIPCASCADE_P2S_TEST").as_deref() == Ok("1"),
            "explicit opt-in for the isolated local test is required"
        );
        let folder = std::env::temp_dir().join(format!("clipcascade-gui-{}", uuid::Uuid::new_v4()));
        // A distinct literal target allows the fixture to leave existing credentials untouched.
        let server = "http://2130706433:18765";
        let target = Target::new(server, "admin");
        ensure!(
            target.read()?.is_none(),
            "isolated test credential already exists"
        );
        let result = (|| {
            for password in ["admin123", ""] {
                let window = unsafe {
                    CreateWindowExW(
                        0,
                        w!("STATIC"),
                        TITLE,
                        WS_OVERLAPPED,
                        0,
                        0,
                        WIDTH,
                        HEIGHT,
                        null_mut(),
                        null_mut(),
                        GetModuleHandleW(null()),
                        null(),
                    )
                };
                ensure!(!window.is_null(), "could not create test window");
                let connected = (|| {
                    let mut app = App::new(window);
                    let log = DiskLog::new(folder.clone());
                    app.log = log.recent(LOG_LIMIT)?;
                    if password.is_empty() {
                        ensure!(
                            app.log
                                .iter()
                                .any(|line| line.contains("パスワードを保存しました"))
                        );
                    }
                    app.disk_log = Some(log);
                    app.build()?;
                    set(app.fields.server, server);
                    set(app.fields.username, "admin");
                    set(app.fields.password, password);
                    set(app.fields.ca, "");
                    unsafe {
                        SendMessageW(
                            app.fields.remember_password,
                            BM_SETCHECK,
                            BST_CHECKED as usize,
                            0,
                        );
                    }
                    app.command(CONNECT)?;
                    let until = std::time::Instant::now() + std::time::Duration::from_secs(12);
                    while !app.relay_ready
                        && std::time::Instant::now() < until
                        && app.active.is_some()
                    {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        app.drain();
                    }
                    ensure!(
                        app.relay_ready,
                        "P2S connection failed: {}",
                        get(app.fields.detail)
                    );
                    ensure!(get(app.fields.password).is_empty());
                    app.command(CONNECT)?;
                    Ok::<_, anyhow::Error>(())
                })();
                unsafe {
                    DestroyWindow(window);
                }
                connected?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        let cleanup = target.delete();
        let _ = fs::remove_file(folder.join("diagnostic.log"));
        let _ = fs::remove_dir(folder);
        result?;
        cleanup
    }

    #[test]
    fn activity_views_display_transfer_details_without_logging_contents() -> Result<()> {
        let window = unsafe {
            CreateWindowExW(
                0,
                w!("STATIC"),
                TITLE,
                WS_OVERLAPPED,
                0,
                0,
                WIDTH,
                HEIGHT,
                null_mut(),
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            )
        };
        ensure!(!window.is_null(), "could not create test window");
        let result = (|| {
            let mut app = App::new(window);
            app.build()?;
            let reporter = app.reporter();
            let output = Arc::new(Content::Text("sent-only-in-history".into()));
            reporter.emit(Event::Sent(output, 1));
            let mut png = Cursor::new(Vec::new());
            image::RgbaImage::from_pixel(4, 2, image::Rgba([231, 21, 55, 255]))
                .write_to(&mut png, image::ImageFormat::Png)?;
            reporter.emit(Event::Received(Content::Image(png.into_inner())));
            reporter.emit(Event::Error("test connection error".into()));
            app.drain();
            app.command(HISTORY_VIEW)?;
            assert!(get(app.fields.history_title).contains("受信   画像"));
            assert_eq!(
                app.history_preview.as_ref().unwrap().get_pixel(0, 0).0,
                [55, 21, 231, 255]
            );
            unsafe {
                SendMessageW(app.fields.history_list, LB_SETCURSEL, 1, 0);
            }
            app.show_history_selection();
            assert!(get(app.fields.history_title).contains("送信   テキスト"));
            assert_eq!(get(app.fields.history_text), "sent-only-in-history");
            app.command(LOG_VIEW)?;
            let log = get(app.fields.log);
            assert!(log.contains("送信 · テキスト"));
            assert!(log.contains("エラー · test connection error"));
            assert!(!log.contains("sent-only-in-history"));
            app.command(HISTORY_VIEW)?;
            app.command(CLEAR_HISTORY)?;
            assert!(app.history.is_empty());
            assert!(get(app.fields.history_text).is_empty());
            Ok(())
        })();
        unsafe {
            DestroyWindow(window);
        }
        result
    }
}
