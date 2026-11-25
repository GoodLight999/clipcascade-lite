use crate::protocol::{Content, Sharing};
use anyhow::{Context, Result, ensure};
use arboard::{Clipboard, ImageData};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            DataExchange::{
                CloseClipboard, GetClipboardData, GetClipboardOwner, IsClipboardFormatAvailable,
                OpenClipboard, RegisterClipboardFormatW,
            },
            Memory::{GlobalLock, GlobalSize, GlobalUnlock},
            Threading::{
                OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
        UI::{Shell::DragQueryFileW, WindowsAndMessaging::GetWindowThreadProcessId},
    },
    w,
};

const DROP_FORMAT: u32 = 15;

pub fn clipboard_owner_name() -> Option<String> {
    unsafe {
        let owner = GetClipboardOwner();
        if owner.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(owner, &mut pid);
        if pid == 0 {
            return None;
        }
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 512];
        let mut len = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) != 0;
        CloseHandle(handle);
        if !ok || len == 0 {
            return None;
        }
        let full = OsString::from_wide(&buffer[..len as usize]);
        Path::new(&full)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    }
}

pub fn normalize_app_name(name: &str) -> String {
    let trimmed = name.trim().to_ascii_lowercase();
    trimmed
        .strip_suffix(".exe")
        .unwrap_or(&trimmed)
        .trim()
        .to_owned()
}

pub fn is_excluded_app(owner: &str, excluded_apps: &[String]) -> bool {
    let owner = normalize_app_name(owner);
    !owner.is_empty()
        && excluded_apps
            .iter()
            .any(|entry| normalize_app_name(entry) == owner)
}

fn is_excluded_from_monitor() -> Result<bool> {
    unsafe {
        for name in [
            w!("ExcludeClipboardContentFromMonitorProcessing"),
            w!("Clipboard Viewer Ignore"),
        ] {
            let format = RegisterClipboardFormatW(name);
            if format != 0 && IsClipboardFormatAvailable(format) != 0 {
                return Ok(true);
            }
        }
        let history = RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory"));
        let cloud = RegisterClipboardFormatW(w!("CanUploadToCloudClipboard"));
        let check_history = history != 0 && IsClipboardFormatAvailable(history) != 0;
        let check_cloud = cloud != 0 && IsClipboardFormatAvailable(cloud) != 0;
        if !check_history && !check_cloud {
            return Ok(false);
        }
        let _clipboard = clipboard_win::Clipboard::new_attempts(3).map_err(|error| {
            anyhow::anyhow!("クリップボードの同期許可を確認できません: {error}")
        })?;
        for (available, format) in [(check_history, history), (check_cloud, cloud)] {
            if !available {
                continue;
            }
            let handle = GetClipboardData(format);
            ensure!(
                !handle.is_null() && GlobalSize(handle) >= size_of::<u32>(),
                "クリップボードの同期許可を読み取れません"
            );
            let data = GlobalLock(handle).cast::<u32>();
            ensure!(!data.is_null(), "クリップボードの同期許可を読み取れません");
            let allowed = data.read_unaligned() != 0;
            GlobalUnlock(handle);
            if !allowed {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

enum Snapshot {
    Files(Vec<PathBuf>),
    Image(ImageData<'static>),
    Text(String),
}

fn files() -> Result<Vec<PathBuf>> {
    unsafe {
        ensure!(
            OpenClipboard(ptr::null_mut()) != 0,
            "クリップボードを開けません"
        );
        let result = (|| {
            let drop = GetClipboardData(DROP_FORMAT);
            ensure!(!drop.is_null(), "ファイル一覧を読み込めません");
            let count = DragQueryFileW(drop, u32::MAX, ptr::null_mut(), 0);
            ensure!(count <= 4096, "ファイル数の上限を超えています");
            let mut paths = Vec::with_capacity(count as usize);
            for index in 0..count {
                let length = DragQueryFileW(drop, index, ptr::null_mut(), 0);
                let mut buffer = vec![0; length as usize + 1];
                DragQueryFileW(drop, index, buffer.as_mut_ptr(), length + 1);
                paths.push(PathBuf::from(OsString::from_wide(
                    &buffer[..length as usize],
                )));
            }
            Ok(paths)
        })();
        CloseClipboard();
        result
    }
}

pub fn read(
    sharing: Sharing,
    respect_exclusion: bool,
    excluded_apps: &[String],
) -> Result<Option<Content>> {
    let owner = clipboard_owner_name();
    if respect_exclusion {
        let excluded_app = owner
            .as_deref()
            .is_some_and(|name| is_excluded_app(name, excluded_apps));
        let excluded_format = is_excluded_from_monitor()?;
        crate::diagnostic::debug(&format!(
            "clipboard read owner={} excluded_format={excluded_format} excluded_app={excluded_app}",
            owner.as_deref().unwrap_or("<none>")
        ));
        if excluded_format || excluded_app {
            return Ok(None);
        }
    } else {
        crate::diagnostic::debug(&format!(
            "clipboard manual read owner={}",
            owner.as_deref().unwrap_or("<none>")
        ));
    }
    let mut clipboard = Clipboard::new()?;
    let snapshot = if sharing.files && unsafe { IsClipboardFormatAvailable(DROP_FORMAT) != 0 } {
        Some(Snapshot::Files(files()?))
    } else if sharing.images
        && let Ok(image) = clipboard.get_image()
    {
        Some(Snapshot::Image(image))
    } else {
        match clipboard.get_text() {
            Ok(text) if !text.is_empty() => Some(Snapshot::Text(text)),
            Ok(_) | Err(arboard::Error::ContentNotAvailable) => None,
            Err(e) => return Err(e.into()),
        }
    };
    drop(clipboard);
    let content = match snapshot {
        Some(Snapshot::Text(text)) => Content::Text(text),
        Some(Snapshot::Image(image)) => {
            ensure!(
                image.bytes.len() <= 256 * 1024 * 1024,
                "画像の展開サイズが大きすぎます"
            );
            let width = image.width.try_into()?;
            let height = image.height.try_into()?;
            let raw = image::RgbaImage::from_raw(width, height, image.bytes.into_owned())
                .context("クリップボードの画像が破損しています")?;
            let mut png = Cursor::new(Vec::new());
            raw.write_to(&mut png, image::ImageFormat::Png)?;
            Content::Image(png.into_inner())
        }
        Some(Snapshot::Files(paths)) => {
            let mut data = BTreeMap::new();
            let mut names = HashSet::new();
            let mut remaining = sharing.limit;
            for path in paths {
                if !path.is_file() {
                    continue;
                }
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .context("ファイル名が無効です")?;
                ensure!(
                    valid_filename(name) && names.insert(name.to_lowercase()),
                    "同名または未対応のファイル名があります"
                );
                let file = fs::File::open(&path)?;
                ensure!(
                    file.metadata()?.len() <= remaining as u64,
                    "送信サイズの上限を超えています"
                );
                let mut bytes = Vec::new();
                file.take(remaining as u64 + 1).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= remaining, "送信サイズの上限を超えています");
                remaining -= bytes.len();
                data.insert(name.to_owned(), bytes);
            }
            if data.is_empty() {
                return Ok(None);
            }
            Content::Files(data)
        }
        None => return Ok(None),
    };
    ensure!(
        content.size() <= sharing.limit,
        "送信サイズの上限を超えています"
    );
    Ok(Some(content))
}

fn valid_filename(name: &str) -> bool {
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || name.chars().any(char::is_control)
        || name.encode_utf16().count() > 255
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

pub fn apply(
    content: &Content,
    folder: &Path,
    check_current: impl Fn() -> Result<()>,
) -> Result<Option<PathBuf>> {
    check_current()?;
    match content {
        Content::Text(text) => {
            Clipboard::new()?.set_text(text)?;
        }
        Content::Image(bytes) => {
            let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
            let mut limits = image::Limits::default();
            limits.max_alloc = Some(128 * 1024 * 1024);
            limits.max_image_width = Some(16_384);
            limits.max_image_height = Some(16_384);
            reader.limits(limits);
            let image = reader.decode()?.into_rgba8();
            ensure!(
                image.as_raw().len() <= 128 * 1024 * 1024,
                "画像の展開サイズが大きすぎます"
            );
            check_current()?;
            Clipboard::new()?.set_image(ImageData {
                width: image.width() as usize,
                height: image.height() as usize,
                bytes: Cow::Owned(image.into_raw()),
            })?;
        }
        Content::Files(files) => {
            ensure!(!files.is_empty(), "受信ファイルがありません");
            let mut names = HashSet::new();
            ensure!(
                files
                    .keys()
                    .all(|name| valid_filename(name) && names.insert(name.to_lowercase())),
                "受信したファイル名をWindowsで扱えません"
            );
            let destination = folder.join(format!("受信-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(folder)?;
            fs::create_dir(&destination)?;
            let mut paths = Vec::new();
            let result = (|| {
                for (name, data) in files {
                    check_current()?;
                    let path = destination.join(name);
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?;
                    paths.push(path);
                    file.write_all(data)?;
                }
                check_current()?;
                set_files(&paths)?;
                Ok(Some(destination.clone()))
            })();
            if result.is_err() {
                for path in paths {
                    let _ = fs::remove_file(path);
                }
                let _ = fs::remove_dir(&destination);
            }
            return result;
        }
    }
    Ok(None)
}

fn set_files(paths: &[PathBuf]) -> Result<()> {
    let mut bytes = Vec::new();
    // DROPFILES with pFiles = 20 and fWide = TRUE, followed by a UTF-16 multistring.
    for field in [20u32, 0, 0, 0, 1] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    for path in paths {
        for unit in path.as_os_str().encode_wide().chain([0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&[0, 0]);
    clipboard_win::set_clipboard(
        clipboard_win::formats::RawData(DROP_FORMAT),
        bytes.as_slice(),
    )
    .map_err(|e| anyhow::anyhow!("ファイルをクリップボードにコピーできません（{e}）"))
}
