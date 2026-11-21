use crate::{
    network::{Event, Outbound, Reporter, Socket},
    protocol::{self, Content, Key, MAX_LIMIT, Sharing},
};
use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::watch, time};
use tokio_tungstenite::tungstenite::Message;

const SUBSCRIPTION: &str = "clipboard";
const HEADER_LIMIT: usize = 64 * 1024;
const PING_INTERVAL: Duration = Duration::from_secs(20);

pub struct Relay {
    client: Client,
    recipients_url: Url,
    host: String,
    limit: usize,
}

#[derive(Deserialize)]
struct ServerLimit {
    maxsize: usize,
}

#[derive(Deserialize)]
struct Plan {
    format: String,
    recipients: Vec<Recipient>,
}

#[derive(Deserialize)]
struct Recipient {
    id: String,
    binary: bool,
}

impl Plan {
    fn checked(self) -> Option<Self> {
        let mut ids = HashSet::new();
        (self.format == "ccb1"
            && self.recipients.len() <= 256
            && self.recipients.iter().all(|r| {
                !r.id.is_empty()
                    && r.id.len() <= 128
                    && r.id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                    && ids.insert(r.id.as_str())
            }))
        .then_some(self)
    }
}

#[derive(Deserialize)]
struct Control<'a> {
    #[serde(rename = "_cc_control")]
    kind: Option<&'a str>,
    version: Option<u64>,
    epoch: Option<&'a str>,
    revision: Option<u64>,
}

#[derive(Default)]
struct Recipients {
    current: Option<(String, u64, Instant, Option<Plan>)>,
}

impl Recipients {
    fn consume(&mut self, data: &[u8]) -> bool {
        let Ok(control) = serde_json::from_slice::<Control<'_>>(data) else {
            return false;
        };
        if control.kind != Some("relay-recipients") {
            return false;
        }
        if let (Some(1), Some(epoch), Some(revision)) =
            (control.version, control.epoch, control.revision)
            && !epoch.is_empty()
            && epoch.len() <= 128
            && self
                .current
                .as_ref()
                .is_none_or(|(previous, value, _, _)| epoch == previous && revision > *value)
        {
            let plan = serde_json::from_slice::<Plan>(data)
                .ok()
                .and_then(Plan::checked);
            self.current = Some((epoch.into(), revision, Instant::now(), plan));
        }
        true
    }

    fn plan(&self) -> Option<&Plan> {
        let (_, _, created, plan) = self.current.as_ref()?;
        if created.elapsed() >= Duration::from_secs(60) {
            return None;
        }
        plan.as_ref()
    }
}

impl Relay {
    pub async fn discover(base: &Url, client: Client) -> Result<Self> {
        let limit = client
            .get(base.join("max-size")?)
            .send()
            .await?
            .error_for_status()?
            .json::<ServerLimit>()
            .await
            .context("P2Sサーバーの転送上限を取得できません")?
            .maxsize;
        ensure!(limit > 0, "P2Sサーバーの転送上限が無効です");
        Ok(Self {
            client,
            recipients_url: base.join("clipbinary/recipients")?,
            host: base.host_str().unwrap().into(),
            limit,
        })
    }

    pub fn wire_limit(&self) -> usize {
        self.limit.min(MAX_LIMIT).saturating_mul(2)
    }

    async fn recipient_plan(&self) -> Option<Plan> {
        let response = self
            .client
            .get(self.recipients_url.clone())
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .ok()?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|n| n > 128 * 1024)
        {
            return None;
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len() + chunk.len() > 128 * 1024 {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<Plan>(&body).ok()?.checked()
    }

    pub async fn drive(
        &self,
        socket: Socket,
        key: Option<&Key>,
        sharing: Sharing,
        outgoing: &mut watch::Receiver<Outbound>,
        paused: &mut watch::Receiver<bool>,
        report: &impl Reporter,
    ) -> Result<()> {
        let mut link = Stomp {
            socket,
            buffer: BytesMut::new(),
            limit: self.wire_limit(),
        };
        let size = sharing.limit.to_string();
        link.send(
            "CONNECT",
            &[
                ("accept-version", "1.0,1.1,1.2"),
                ("host", &self.host),
                ("heart-beat", "0,20000"),
                ("x-clipcascade-binary", "ccb1"),
                ("x-clipcascade-recipient-updates", "1"),
                ("x-clipcascade-no-self-echo", "true"),
                ("x-clipcascade-receive-limit", &size),
            ],
            &[],
            false,
        )
        .await?;
        let initial = time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(frame) = link.next().await? {
                    return Ok::<_, anyhow::Error>(frame);
                }
            }
        })
        .await
        .context("P2S接続の応答がありません")??;
        ensure!(
            initial.command == "CONNECTED",
            "サーバーがP2S接続を拒否しました"
        );
        let heartbeat = initial
            .headers
            .get("heart-beat")
            .and_then(|s| s.split_once(','))
            .and_then(|(send, _)| send.parse::<u64>().ok())
            .filter(|&ms| ms > 0);
        link.send(
            "SUBSCRIBE",
            &[
                ("id", SUBSCRIPTION),
                ("destination", "/user/queue/cliptext"),
                ("ack", "auto"),
            ],
            &[],
            false,
        )
        .await?;
        report.emit(Event::RelayReady(true));
        let mut recipients = Recipients::default();
        let mut echoes = VecDeque::new();
        let mut ping = time::interval_at(time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
        ping.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut last_rx = Instant::now();
        let sharing = Sharing {
            limit: sharing.limit.min(self.limit),
            ..sharing
        };
        loop {
            tokio::select! {
                received = link.next() => {
                    let frame = received?;
                    last_rx = Instant::now();
                    if let Some(frame) = frame {
                        match frame.command.as_str() {
                            "ERROR" => bail!("サーバーがP2Sの要求を拒否しました"),
                            "MESSAGE" if frame.headers.get("subscription").is_some_and(|id| id == SUBSCRIPTION) => {
                                let binary = frame.body.starts_with(b"CCB1");
                                if !binary && recipients.consume(&frame.body) { continue; }
                                if *paused.borrow() { continue; }
                                match protocol::decode_relay(&frame.body, binary, key, sharing) {
                                    Ok(Some(content)) => {
                                        echoes.retain(|(_, recorded): &([u8; 32], Instant)| recorded.elapsed() < Duration::from_secs(20));
                                        if !echoes.is_empty() {
                                            let signature = content.fingerprint();
                                            if let Some(index) = echoes.iter().position(|(hash, _)| *hash == signature) {
                                                echoes.remove(index);
                                                continue;
                                            }
                                        }
                                        report.emit(Event::Received(content));
                                    }
                                    Ok(None) => {}
                                    Err(_) => report.emit(Event::Error("P2Sの受信データを処理できません。転送上限と暗号化設定を確認してください".into())),
                                }
                            }
                            _ => {}
                        }
                    }
                }
                changed = outgoing.changed() => {
                    changed?;
                    let content = outgoing.borrow_and_update().take();
                    if let Some(content) = content.filter(|_| !*paused.borrow()) {
                        if content.size() > sharing.limit {
                            report.emit(Event::Error(format!("P2Sのサーバー転送上限（{} バイト）を超えています", sharing.limit)));
                            continue;
                        }
                        let fallback = if recipients.plan().is_none() { self.recipient_plan().await } else { None };
                        if *paused.borrow() || outgoing.has_changed().unwrap_or(false) { continue; }
                        let plan = recipients.plan().or(fallback.as_ref());
                        match send_clipboard(&mut link, &content, key, plan).await? {
                            SendResult::Sent => {
                                if plan.is_none() {
                                    if echoes.len() >= 16 { echoes.pop_front(); }
                                    echoes.push_back((content.fingerprint(), Instant::now()));
                                }
                                report.emit(Event::Sent(content, 0));
                            }
                            SendResult::NoRecipients => report.emit(Event::Error("P2Sの送信先端末が見つかりません".into())),
                            SendResult::TooLarge => report.emit(Event::Error("P2Sの転送形式がサーバーのサイズ上限を超えています".into())),
                        }
                    }
                }
                changed = paused.changed() => {
                    changed?;
                    paused.borrow_and_update();
                }
                _ = ping.tick() => {
                    let budget = heartbeat.map_or(60, |ms| (ms.max(20_000) / 1_000).saturating_mul(3)).max(60);
                    ensure!(last_rx.elapsed() <= Duration::from_secs(budget), "P2Sサーバーが応答しません");
                    link.write(Message::Ping(Bytes::new())).await?;
                }
            }
        }
    }
}

enum SendResult {
    Sent,
    NoRecipients,
    TooLarge,
}

async fn send_clipboard(
    link: &mut Stomp,
    content: &Arc<Content>,
    key: Option<&Key>,
    plan: Option<&Plan>,
) -> Result<SendResult> {
    let mut modern = Vec::new();
    let mut legacy = Vec::new();
    if let Some(plan) = plan {
        for r in &plan.recipients {
            if r.binary {
                modern.push(r.id.as_str());
            } else {
                legacy.push(r.id.as_str());
            }
        }
        if modern.is_empty() && legacy.is_empty() {
            return Ok(SendResult::NoRecipients);
        }
    }
    let binary = if modern.is_empty() {
        None
    } else {
        match protocol::encode_relay(content, key, true) {
            Ok(frame)
                if frame.len() + 1024 + modern.iter().map(|id| id.len() + 1).sum::<usize>()
                    < link.limit =>
            {
                Some(frame)
            }
            _ => {
                legacy.append(&mut modern);
                None
            }
        }
    };
    if let Some(frame) = binary {
        link.send(
            "SEND",
            &[
                ("destination", "/app/clipbinary"),
                ("content-type", "application/octet-stream"),
                ("x-clipcascade-recipients", &modern.join(",")),
            ],
            &frame,
            true,
        )
        .await?;
    }
    if plan.is_none() || !legacy.is_empty() {
        let Ok(body) = protocol::encode_relay(content, key, false) else {
            return Ok(SendResult::TooLarge);
        };
        if body.len() + 1024 + legacy.iter().map(|id| id.len() + 1).sum::<usize>() >= link.limit {
            return Ok(if !modern.is_empty() {
                SendResult::Sent
            } else {
                SendResult::TooLarge
            });
        }
        let mut headers = vec![
            ("destination", "/app/cliptext"),
            ("content-type", "application/json"),
        ];
        let selected = legacy.join(",");
        if plan.is_some() {
            headers.push(("x-clipcascade-recipients", &selected));
        }
        link.send("SEND", &headers, &body, false).await?;
    }
    Ok(SendResult::Sent)
}

struct Frame {
    command: String,
    headers: HashMap<String, String>,
    body: Bytes,
}

struct Stomp {
    socket: Socket,
    buffer: BytesMut,
    limit: usize,
}

impl Stomp {
    async fn write(&mut self, message: Message) -> Result<()> {
        time::timeout(Duration::from_secs(20), self.socket.send(message))
            .await
            .context("P2Sの送信がタイムアウトしました")??;
        Ok(())
    }

    async fn send(
        &mut self,
        command: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        binary: bool,
    ) -> Result<()> {
        let mut bytes = Vec::with_capacity(body.len() + 256);
        bytes.extend_from_slice(command.as_bytes());
        bytes.push(b'\n');
        for (key, value) in headers {
            ensure!(!value.contains(['\r', '\n', '\0']), "不正なSTOMPヘッダー");
            bytes.extend_from_slice(format!("{key}:{value}\n").as_bytes());
        }
        if command == "SEND" {
            bytes.extend_from_slice(format!("content-length:{}\n", body.len()).as_bytes());
        }
        bytes.push(b'\n');
        bytes.extend_from_slice(body);
        bytes.push(0);
        ensure!(bytes.len() <= self.limit, "P2Sの転送上限を超えています");
        self.write(if binary {
            Message::Binary(bytes.into())
        } else {
            Message::Text(String::from_utf8(bytes)?.into())
        })
        .await
    }

    async fn next(&mut self) -> Result<Option<Frame>> {
        if let Some(frame) = decode_frame(&mut self.buffer, self.limit)? {
            return Ok(Some(frame));
        }
        let message = self
            .socket
            .next()
            .await
            .context("P2Sの接続が終了しました")??;
        match message {
            Message::Text(text) => self.buffer.extend_from_slice(text.as_bytes()),
            Message::Binary(bytes) => self.buffer.extend_from_slice(&bytes),
            Message::Ping(_) => {
                self.socket.flush().await?;
            }
            Message::Close(_) => bail!("サーバーがP2Sの接続を閉じました"),
            _ => {}
        }
        decode_frame(&mut self.buffer, self.limit)
    }
}

fn decode_frame(buffer: &mut BytesMut, limit: usize) -> Result<Option<Frame>> {
    let leading = buffer
        .iter()
        .take_while(|&&b| matches!(b, b'\r' | b'\n'))
        .count();
    buffer.advance(leading);
    let mut boundary = None;
    for (index, line) in buffer[..buffer.len().min(HEADER_LIMIT)]
        .split_inclusive(|&b| b == b'\n')
        .scan(0, |offset, line| {
            *offset += line.len();
            Some((*offset, line))
        })
    {
        if line == b"\n" || line == b"\r\n" {
            boundary = Some(index);
            break;
        }
    }
    let Some(start) = boundary else {
        ensure!(buffer.len() < HEADER_LIMIT, "STOMPヘッダーが大きすぎます");
        return Ok(None);
    };
    let head = std::str::from_utf8(&buffer[..start])?;
    let mut lines = head.lines();
    let command = lines
        .next()
        .context("STOMPコマンドがありません")?
        .to_owned();
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once(':').context("不正なSTOMPヘッダー")?;
        headers
            .entry(key.to_owned())
            .or_insert_with(|| value.to_owned());
    }
    let end = if let Some(size) = headers.get("content-length") {
        let size = size.parse::<usize>().context("無効なSTOMPサイズ")?;
        ensure!(
            size <= limit.saturating_sub(start + 1),
            "STOMPサイズの上限を超えています"
        );
        if buffer.len() <= start + size {
            return Ok(None);
        }
        start + size
    } else {
        match buffer[start..].iter().position(|&b| b == 0) {
            Some(offset) => start + offset,
            None => {
                ensure!(buffer.len() < limit, "STOMPサイズの上限を超えています");
                return Ok(None);
            }
        }
    };
    ensure!(end < limit && buffer[end] == 0, "無効なSTOMP終端");
    let data = buffer.split_to(end + 1).freeze();
    Ok(Some(Frame {
        command,
        headers,
        body: data.slice(start..end),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_and_combined_stomp_frames_with_binary_body() -> Result<()> {
        let mut data = BytesMut::from(&b"\nMESSAGE\r\ncontent-length:3\r\n\r\na\0"[..]);
        assert!(decode_frame(&mut data, 128)?.is_none());
        data.extend_from_slice(b"b\0\nMESSAGE\n\ntext\0");
        let first = decode_frame(&mut data, 128)?.unwrap();
        assert_eq!(first.body.as_ref(), b"a\0b");
        let second = decode_frame(&mut data, 128)?.unwrap();
        assert_eq!(second.body.as_ref(), b"text");
        assert!(decode_frame(&mut data, 128)?.is_none());
        Ok(())
    }

    #[test]
    fn matches_official_relay_formats_with_and_without_encryption() -> Result<()> {
        let key = protocol::derive_key("test", "example", "", 16);
        let item = Content::Files(std::collections::BTreeMap::from([
            ("日本語.txt".to_owned(), vec![23; 31_000]),
            ("empty.txt".to_owned(), Vec::new()),
        ]));
        for binary in [false, true] {
            for key in [None, Some(&key)] {
                let data = protocol::encode_relay(&item, key, binary)?;
                let sharing = Sharing {
                    images: true,
                    files: true,
                    limit: 32_000,
                };
                assert_eq!(
                    protocol::decode_relay(&data, binary, key, sharing)?.as_ref(),
                    Some(&item)
                );
            }
        }
        Ok(())
    }
}
