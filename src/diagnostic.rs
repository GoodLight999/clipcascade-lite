use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

const MAX_BYTES: u64 = 512 * 1024;
const MAX_DEBUG_BYTES: u64 = 1024 * 1024;

static DEBUG_LOG: OnceLock<Mutex<DebugLog>> = OnceLock::new();

pub struct DiskLog {
    folder: PathBuf,
}

impl DiskLog {
    pub fn new(folder: PathBuf) -> Self {
        Self { folder }
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn append(&self, line: &str) -> io::Result<()> {
        append_rotating(
            &self.folder,
            "diagnostic.log",
            "diagnostic.previous.log",
            MAX_BYTES,
            line,
        )
    }

    pub fn recent(&self, limit: usize) -> io::Result<VecDeque<String>> {
        let mut lines = VecDeque::new();
        for name in ["diagnostic.previous.log", "diagnostic.log"] {
            let file = match File::open(self.folder.join(name)) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let mut buffer = Vec::new();
            file.take(MAX_BYTES).read_to_end(&mut buffer)?;
            for line in String::from_utf8_lossy(&buffer)
                .lines()
                .filter(|line| !line.is_empty())
            {
                if lines.len() == limit {
                    lines.pop_front();
                }
                lines.push_back(line.to_owned());
            }
        }
        Ok(lines)
    }
}

pub struct DebugLog {
    folder: PathBuf,
}

impl DebugLog {
    pub fn new(folder: PathBuf) -> Self {
        Self { folder }
    }

    pub fn append(&self, message: &str) -> io::Result<()> {
        let safe: String = message
            .chars()
            .take(1000)
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let line = format!("{}  [pid={}]  {safe}", timestamp_ms(), std::process::id());
        append_rotating(
            &self.folder,
            "debug.log",
            "debug.previous.log",
            MAX_DEBUG_BYTES,
            &line,
        )
    }
}

pub fn init_debug(folder: PathBuf) {
    let _ = DEBUG_LOG.set(Mutex::new(DebugLog::new(folder)));
}

pub fn debug(message: &str) {
    if let Some(lock) = DEBUG_LOG.get()
        && let Ok(log) = lock.lock()
    {
        let _ = log.append(message);
    }
}

fn append_rotating(
    folder: &Path,
    current_name: &str,
    previous_name: &str,
    max_bytes: u64,
    line: &str,
) -> io::Result<()> {
    fs::create_dir_all(folder)?;
    let current = folder.join(current_name);
    if let Ok(metadata) = current.metadata()
        && metadata.len() + line.len() as u64 + 2 > max_bytes
    {
        let previous = folder.join(previous_name);
        let _ = fs::remove_file(&previous);
        fs::rename(&current, previous)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(current)?;
    file.write_all(format!("{line}\r\n").as_bytes())
}

#[cfg(windows)]
fn timestamp_ms() -> String {
    use std::mem::zeroed;
    use windows_sys::Win32::{
        Foundation::SYSTEMTIME, System::SystemInformation::GetLocalTime,
    };
    let mut time = unsafe { zeroed::<SYSTEMTIME>() };
    unsafe {
        GetLocalTime(&mut time);
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds
    )
}

#[cfg(not(windows))]
fn timestamp_ms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reloads_recent_diagnostics_across_rotation() -> io::Result<()> {
        let folder = std::env::temp_dir().join(format!("clipcascade-log-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let log = DiskLog::new(folder.clone());
            let padding = "x".repeat(MAX_BYTES as usize - 4);
            log.append(&padding)?;
            log.append("再接続しました")?;
            log.append("送信 · テキスト · 23 バイト")?;
            let reopened = DiskLog::new(folder.clone());
            assert_eq!(
                reopened.recent(2)?.into_iter().collect::<Vec<_>>(),
                ["再接続しました", "送信 · テキスト · 23 バイト"],
            );
            assert!(folder.join("diagnostic.previous.log").is_file());
            Ok::<_, io::Error>(())
        })();
        for file in ["diagnostic.log", "diagnostic.previous.log"] {
            let _ = fs::remove_file(folder.join(file));
        }
        let _ = fs::remove_dir(folder);
        result
    }

    #[test]
    fn debug_log_writes_and_rotates_cleanly() -> io::Result<()> {
        let folder =
            std::env::temp_dir().join(format!("clipcascade-dbg-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let log = DebugLog::new(folder.clone());
            log.append("line-1\nwith-control")?;
            let content = fs::read_to_string(folder.join("debug.log"))?;
            assert!(content.contains("line-1 with-control"));
            assert!(content.contains("[pid="));
            Ok::<_, io::Error>(())
        })();
        for file in ["debug.log", "debug.previous.log"] {
            let _ = fs::remove_file(folder.join(file));
        }
        let _ = fs::remove_dir(folder);
        result
    }
}
