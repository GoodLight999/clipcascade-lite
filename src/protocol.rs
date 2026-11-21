use aes_gcm::{
    AesGcm, KeyInit,
    aead::{
        AeadInPlace, OsRng,
        consts::{U12, U16},
        rand_core::RngCore,
    },
    aes::Aes256,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const FRAGMENT: usize = 15_360;
const MAX_HEADER: usize = 65_536;
pub const MAX_LIMIT: usize = 256 * 1024 * 1024;
pub type Key = Zeroizing<[u8; 32]>;

#[derive(Debug, PartialEq)]
pub enum Content {
    Text(String),
    Image(Vec<u8>),
    Files(BTreeMap<String, Vec<u8>>),
}

impl Content {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Text(_) => Kind::Text,
            Self::Image(_) => Kind::Image,
            Self::Files(_) => Kind::Files,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Image(data) => data.len(),
            Self::Files(files) => files.values().map(Vec::len).sum(),
        }
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        match self {
            Self::Text(text) => {
                hash.update([0]);
                hash.update(text.as_bytes());
            }
            Self::Image(data) => {
                hash.update([1]);
                hash.update(data);
            }
            Self::Files(files) => {
                hash.update([2]);
                for (name, content) in files {
                    hash.update(name.len().to_be_bytes());
                    hash.update(name.as_bytes());
                    hash.update(content.len().to_be_bytes());
                    hash.update(content);
                }
            }
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Text,
    Image,
    Files,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "テキスト",
            Self::Image => "画像",
            Self::Files => "ファイル",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Sharing {
    pub images: bool,
    pub files: bool,
    pub limit: usize,
}

impl Sharing {
    pub fn allows(self, kind: Kind) -> bool {
        match kind {
            Kind::Text => true,
            Kind::Image => self.images,
            Kind::Files => self.files,
        }
    }
}

pub fn derive_key(username: &str, password: &str, salt: &str, rounds: u32) -> Key {
    let combined = Zeroizing::new(format!("{username}{password}{salt}"));
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        combined.as_bytes(),
        rounds,
        key.as_mut(),
    );
    key
}

fn encrypt(key: &Key, data: &mut [u8]) -> Result<([u8; 16], [u8; 16])> {
    let mut nonce = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    let tag = AesGcm::<Aes256, U16>::new((&**key).into())
        .encrypt_in_place_detached((&nonce).into(), b"", data)
        .map_err(|_| anyhow!("暗号化できませんでした"))?;
    Ok((nonce, tag.into()))
}

fn decrypt(key: &Key, nonce: &[u8], tag: &[u8], data: &mut [u8]) -> Result<()> {
    ensure!(tag.len() == 16, "暗号化タグが無効です");
    let result = match nonce.len() {
        12 => AesGcm::<Aes256, U12>::new((&**key).into()).decrypt_in_place_detached(
            nonce.into(),
            b"",
            data,
            tag.into(),
        ),
        16 => AesGcm::<Aes256, U16>::new((&**key).into()).decrypt_in_place_detached(
            nonce.into(),
            b"",
            data,
            tag.into(),
        ),
        _ => bail!("暗号化ノンスの長さが無効です"),
    };
    result.map_err(|_| {
        anyhow!("復号できません。端末間のパスワード・ソルト・反復回数を確認してください")
    })
}

fn base64(text: &str) -> Result<Vec<u8>> {
    if text.as_bytes().iter().any(u8::is_ascii_whitespace) {
        Ok(STANDARD.decode(text.split_ascii_whitespace().collect::<String>())?)
    } else {
        Ok(STANDARD.decode(text)?)
    }
}

fn pack(header: &impl Serialize, payload: &[u8]) -> Result<Vec<u8>> {
    let header = serde_json::to_vec(header)?;
    ensure!(header.len() <= MAX_HEADER, "バイナリヘッダーが大きすぎます");
    let mut frame = Vec::with_capacity(8 + header.len() + payload.len());
    frame.extend_from_slice(b"CCB1");
    frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn unpack<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<(T, &[u8])> {
    ensure!(
        data.len() >= 8 && data.starts_with(b"CCB1"),
        "CCB1ヘッダーが無効です"
    );
    let len = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    ensure!(
        len <= MAX_HEADER && len <= data.len() - 8,
        "CCB1ヘッダー長が無効です"
    );
    Ok((serde_json::from_slice(&data[8..8 + len])?, &data[8 + len..]))
}

#[derive(Deserialize, Serialize)]
struct Inner {
    #[serde(rename = "type")]
    kind: Kind,
    files: Option<Vec<(String, usize)>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    id: String,
    is_fragmented: bool,
    index: usize,
    total_fragments: usize,
    #[serde(default)]
    content_size_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    combined_raw_payload_size_in_bytes: Option<usize>,
}

#[derive(Deserialize, Serialize)]
struct Envelope {
    #[serde(rename = "type", default = "text_kind")]
    kind: Kind,
    #[serde(default)]
    metadata: Option<Metadata>,
    #[serde(default)]
    encrypted: bool,
}

fn text_kind() -> Kind {
    Kind::Text
}

#[derive(Deserialize, Serialize)]
struct LegacyFrame {
    #[serde(flatten)]
    envelope: Envelope,
    payload: String,
}

#[derive(Deserialize, Serialize)]
struct LegacyCipher {
    nonce: String,
    tag: String,
    ciphertext: String,
}

pub fn capability(limit: usize) -> String {
    json!({"_cc_keepalive": true, "capabilities": {
        "version": 1, "receiveLimitBytes": limit, "transferFormats": ["ccb1"]
    }})
    .to_string()
}

#[derive(Clone, Copy, Default)]
pub struct Capability {
    pub binary: bool,
    pub limit: Option<u64>,
}

pub enum Incoming {
    Capability(Option<Capability>),
    Fragment(Fragment),
}

pub struct Fragment {
    envelope: Envelope,
    bytes: Vec<u8>,
    binary: bool,
}

pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Deserialize, Serialize)]
struct RelayMetadata {
    #[serde(rename = "contentSizeBytes")]
    size: Option<usize>,
}

#[derive(Deserialize, Serialize)]
struct RelayHeader {
    #[serde(rename = "type", default = "text_kind")]
    kind: Kind,
    metadata: Option<RelayMetadata>,
    #[serde(default)]
    encrypted: bool,
}

#[derive(Deserialize, Serialize)]
struct RelayText {
    #[serde(flatten)]
    header: RelayHeader,
    payload: String,
}

pub fn encode_relay(content: &Content, key: Option<&Key>, binary: bool) -> Result<Vec<u8>> {
    let transfer = Transfer::new(content, key, binary)?;
    let header = RelayHeader {
        kind: content.kind(),
        metadata: Some(RelayMetadata {
            size: Some(content.size()),
        }),
        encrypted: binary && key.is_some(),
    };
    if binary {
        pack(&header, &transfer.raw)
    } else {
        Ok(serde_json::to_vec(&json!({
            "type": header.kind, "metadata": header.metadata, "payload": String::from_utf8(transfer.raw)?
        }))?)
    }
}

pub fn decode_relay(
    data: &[u8],
    binary: bool,
    key: Option<&Key>,
    sharing: Sharing,
) -> Result<Option<Content>> {
    ensure!(
        data.len() <= sharing.limit.saturating_mul(4) + MAX_HEADER + 1024,
        "P2S受信サイズの上限を超えています"
    );
    let (header, raw) = if binary {
        let (header, bytes) = unpack(data)?;
        (header, bytes.to_vec())
    } else {
        let frame: RelayText = serde_json::from_slice(data)?;
        (frame.header, frame.payload.into_bytes())
    };
    if !sharing.allows(header.kind) {
        return Ok(None);
    }
    let size = header.metadata.and_then(|m| m.size);
    ensure!(
        size.is_none_or(|size| size <= sharing.limit),
        "P2S受信サイズの上限を超えています"
    );
    if binary {
        ensure!(
            size.is_some() && raw.len() <= sharing.limit + MAX_HEADER + 64,
            "無効なP2Sバイナリサイズ"
        );
    }
    let fragment = Fragment {
        envelope: Envelope {
            kind: header.kind,
            metadata: None,
            encrypted: header.encrypted,
        },
        bytes: raw,
        binary,
    };
    let content = decode(fragment, key, sharing.limit)?;
    ensure!(
        size.is_none_or(|size| size == content.size()),
        "P2S受信サイズが一致しません"
    );
    Ok(Some(content))
}

pub fn parse(binary: bool, data: &[u8]) -> Result<Incoming> {
    ensure!(
        data.len() <= MAX_HEADER + FRAGMENT * 6 + 1024,
        "転送フレームが大きすぎます"
    );
    let (envelope, bytes) = if binary {
        let (header, payload): (Envelope, _) = unpack(data)?;
        ensure!(payload.len() <= FRAGMENT, "バイナリ断片が大きすぎます");
        ensure!(
            header
                .metadata
                .as_ref()
                .is_some_and(|m| m.content_size_bytes.is_some()),
            "バイナリ転送にサイズ情報がありません"
        );
        (header, payload.to_vec())
    } else {
        let value: Value = serde_json::from_slice(data)?;
        if value.get("_cc_keepalive").and_then(Value::as_bool) == Some(true) {
            let c = &value["capabilities"];
            return Ok(Incoming::Capability(
                (c["version"].as_u64() == Some(1)).then(|| Capability {
                    binary: c["transferFormats"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|v| v == "ccb1")),
                    limit: c["receiveLimitBytes"].as_u64(),
                }),
            ));
        }
        let frame: LegacyFrame = serde_json::from_value(value)?;
        (frame.envelope, frame.payload.into_bytes())
    };
    if let Some(m) = &envelope.metadata {
        ensure!(
            !m.id.is_empty()
                && m.id.len() <= 128
                && (1..=65_536).contains(&m.total_fragments)
                && m.index < m.total_fragments
                && m.is_fragmented == (m.total_fragments > 1),
            "断片情報が無効です"
        );
    }
    Ok(Incoming::Fragment(Fragment {
        envelope,
        bytes,
        binary,
    }))
}

pub struct Transfer {
    raw: Vec<u8>,
    binary: bool,
    encrypted: bool,
    kind: Kind,
    meta: Metadata,
}

impl Transfer {
    pub fn new(content: &Content, key: Option<&Key>, binary: bool) -> Result<Self> {
        let kind = content.kind();
        let (mut raw, plaintext_size) = if binary {
            let files = match content {
                Content::Files(files) => {
                    Some(files.iter().map(|(n, d)| (n.clone(), d.len())).collect())
                }
                _ => None,
            };
            let prefix = pack(&Inner { kind, files }, &[])?;
            let mut raw = Vec::with_capacity(prefix.len() + content.size());
            raw.extend_from_slice(&prefix);
            match content {
                Content::Text(text) => raw.extend_from_slice(text.as_bytes()),
                Content::Image(data) => raw.extend_from_slice(data),
                Content::Files(files) => files.values().for_each(|d| raw.extend_from_slice(d)),
            }
            let size = raw.len();
            (raw, size)
        } else {
            let raw = match content {
                Content::Text(text) => text.clone(),
                Content::Image(data) => STANDARD.encode(data),
                Content::Files(files) => serde_json::to_string(
                    &files
                        .iter()
                        .map(|(n, d)| (n, STANDARD.encode(d)))
                        .collect::<BTreeMap<_, _>>(),
                )?,
            }
            .into_bytes();
            let size = raw.len();
            (raw, size)
        };
        if let Some(key) = key {
            let (nonce, tag) = encrypt(key, &mut raw)?;
            raw = if binary {
                let mut output = Vec::with_capacity(33 + raw.len());
                output.push(nonce.len() as u8);
                output.extend_from_slice(&nonce);
                output.extend_from_slice(&tag);
                output.extend_from_slice(&raw);
                output
            } else {
                serde_json::to_vec(&LegacyCipher {
                    nonce: STANDARD.encode(nonce),
                    tag: STANDARD.encode(tag),
                    ciphertext: STANDARD.encode(raw),
                })?
            };
        }
        Ok(Self {
            raw,
            binary,
            encrypted: key.is_some(),
            kind,
            meta: Metadata {
                id: uuid::Uuid::new_v4().to_string(),
                is_fragmented: false,
                index: 0,
                total_fragments: 1,
                content_size_bytes: Some(content.size()),
                combined_raw_payload_size_in_bytes: Some(plaintext_size),
            },
        })
    }

    pub fn frames(&self) -> Result<impl Iterator<Item = Result<Frame>> + '_> {
        let mut bounds = Vec::new();
        let mut start = 0;
        while start < self.raw.len() {
            let mut end = (start + FRAGMENT).min(self.raw.len());
            if !self.binary {
                while end < self.raw.len() && self.raw[end] & 0xc0 == 0x80 {
                    end -= 1;
                }
            }
            bounds.push(start..end);
            start = end;
        }
        if bounds.is_empty() {
            bounds.push(0..0);
        }
        let count = bounds.len();
        ensure!(count <= 65_536, "転送断片が多すぎます");
        Ok(bounds.into_iter().enumerate().map(move |(index, range)| {
            let meta = Metadata {
                index,
                total_fragments: count,
                is_fragmented: count > 1,
                ..self.meta.clone()
            };
            let envelope = Envelope {
                kind: self.kind,
                metadata: Some(meta),
                encrypted: self.encrypted,
            };
            let payload = &self.raw[range];
            if self.binary {
                Ok(Frame::Binary(pack(&envelope, payload)?))
            } else {
                Ok(Frame::Text(serde_json::to_string(&LegacyFrame {
                    envelope,
                    payload: std::str::from_utf8(payload)?.to_owned(),
                })?))
            }
        }))
    }
}

struct Partial {
    fragment: Fragment,
    next: usize,
    last: Instant,
}

#[derive(Default)]
pub struct Receiver(Option<Partial>);

impl Receiver {
    pub fn expire(&mut self) {
        if self
            .0
            .as_ref()
            .is_some_and(|p| p.last.elapsed() >= Duration::from_secs(60))
        {
            self.0 = None;
        }
    }

    pub fn receive(
        &mut self,
        fragment: Fragment,
        key: Option<&Key>,
        sharing: Sharing,
    ) -> Result<Option<Content>> {
        self.expire();
        let kind = fragment.envelope.kind;
        if !sharing.allows(kind) {
            return Ok(None);
        }
        let metadata = fragment.envelope.metadata.as_ref();
        let size = metadata.and_then(|m| m.content_size_bytes);
        ensure!(
            size.is_none_or(|n| n <= sharing.limit),
            "受信サイズの上限を超えています"
        );
        let bound = if fragment.binary {
            sharing.limit + MAX_HEADER + 64
        } else {
            sharing.limit * 4 + MAX_HEADER
        };
        let fragment = if let Some(m) = metadata.filter(|m| m.is_fragmented) {
            if m.index == 0 {
                self.0 = Some(Partial {
                    fragment,
                    next: 1,
                    last: Instant::now(),
                });
                return Ok(None);
            }
            let Some(partial) = &mut self.0 else {
                return Ok(None);
            };
            let initial = partial.fragment.envelope.metadata.as_ref().unwrap();
            if initial.id != m.id {
                return Ok(None);
            }
            ensure!(
                partial.next == m.index
                    && initial.total_fragments == m.total_fragments
                    && initial.content_size_bytes == size
                    && partial.fragment.binary == fragment.binary
                    && partial.fragment.envelope.kind == kind
                    && partial.fragment.envelope.encrypted == fragment.envelope.encrypted,
                "断片の順序または形式が一致しません"
            );
            ensure!(
                partial.fragment.bytes.len() + fragment.bytes.len() <= bound,
                "受信データが大きすぎます"
            );
            partial.fragment.bytes.extend_from_slice(&fragment.bytes);
            partial.next += 1;
            partial.last = Instant::now();
            if partial.next < m.total_fragments {
                return Ok(None);
            }
            self.0.take().unwrap().fragment
        } else {
            self.0 = None;
            fragment
        };
        ensure!(fragment.bytes.len() <= bound, "受信データが大きすぎます");
        let content = decode(fragment, key, sharing.limit)?;
        ensure!(
            size.is_none_or(|expected| expected == content.size()),
            "受信データのサイズが一致しません"
        );
        Ok(Some(content))
    }
}

fn decode(fragment: Fragment, key: Option<&Key>, limit: usize) -> Result<Content> {
    let Fragment {
        envelope,
        mut bytes,
        binary,
    } = fragment;
    let kind = envelope.kind;
    if !binary {
        if let Some(key) = key {
            let wrapper: LegacyCipher = serde_json::from_slice(&bytes)
                .context("暗号化設定が一致しているか確認してください")?;
            bytes = base64(&wrapper.ciphertext)?;
            decrypt(
                key,
                &base64(&wrapper.nonce)?,
                &base64(&wrapper.tag)?,
                &mut bytes,
            )?;
        }
        let text = String::from_utf8(bytes)?;
        let content = match kind {
            Kind::Text => Content::Text(text),
            Kind::Image => Content::Image(base64(&text)?),
            Kind::Files => Content::Files(
                serde_json::from_str::<BTreeMap<String, String>>(&text)?
                    .into_iter()
                    .map(|(name, data)| Ok((name, base64(&data)?)))
                    .collect::<Result<_>>()?,
            ),
        };
        ensure!(content.size() <= limit, "受信データが大きすぎます");
        return Ok(content);
    }
    ensure!(
        envelope.encrypted == key.is_some(),
        "暗号化設定が一致していません"
    );
    let offset = if let Some(key) = key {
        let size = *bytes.first().context("暗号化データが空です")? as usize;
        ensure!(bytes.len() >= 1 + size + 16, "暗号化データが短すぎます");
        let offset = 1 + size + 16;
        let (header, data) = bytes.split_at_mut(offset);
        decrypt(key, &header[1..1 + size], &header[1 + size..], data)?;
        offset
    } else {
        0
    };
    let (header, payload): (Inner, _) = unpack(&bytes[offset..])?;
    ensure!(
        header.kind == kind && payload.len() <= limit,
        "受信データの種類またはサイズが無効です"
    );
    Ok(match kind {
        Kind::Text => Content::Text(std::str::from_utf8(payload)?.to_owned()),
        Kind::Image => Content::Image(payload.to_vec()),
        Kind::Files => {
            let mut files = BTreeMap::new();
            let mut remaining = payload;
            for (name, len) in header.files.context("ファイル一覧がありません")? {
                ensure!(
                    len <= remaining.len() && !files.contains_key(&name),
                    "ファイル一覧が無効です"
                );
                let (file, rest) = remaining.split_at(len);
                files.insert(name, file.to_vec());
                remaining = rest;
            }
            ensure!(remaining.is_empty(), "ファイル転送に余分なデータがあります");
            Content::Files(files)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_transfers_support_every_content_type_and_encoding() -> Result<()> {
        let key = derive_key("peer", "example", "", 16);
        let sharing = Sharing {
            images: true,
            files: true,
            limit: 1024 * 1024,
        };
        let items = [
            Content::Text(format!("{}🦀日本語", "a".repeat(FRAGMENT - 1))),
            Content::Image(vec![0xc4; FRAGMENT * 3]),
            Content::Files(BTreeMap::from([
                ("日本語.txt".into(), vec![0xab; FRAGMENT * 2]),
                ("empty.txt".into(), Vec::new()),
            ])),
        ];
        for item in items {
            for binary in [false, true] {
                for key in [None, Some(&key)] {
                    let transfer = Transfer::new(&item, key, binary)?;
                    let mut receiver = Receiver::default();
                    let mut output = None;
                    for frame in transfer.frames()? {
                        let frame = match frame? {
                            Frame::Text(s) => parse(false, s.as_bytes())?,
                            Frame::Binary(b) => parse(true, &b)?,
                        };
                        let Incoming::Fragment(fragment) = frame else {
                            unreachable!()
                        };
                        if let Some(content) = receiver.receive(fragment, key, sharing)? {
                            assert!(output.replace(content).is_none());
                        }
                    }
                    assert_eq!(output.as_ref(), Some(&item));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn corrupted_encrypted_fragment_is_rejected() -> Result<()> {
        let key = derive_key("peer", "example", "", 16);
        let sharing = Sharing {
            images: true,
            files: true,
            limit: 1024,
        };
        let transfer = Transfer::new(&Content::Text("example".into()), Some(&key), true)?;
        let Frame::Binary(mut bytes) = transfer.frames()?.next().unwrap()? else {
            unreachable!()
        };
        *bytes.last_mut().unwrap() ^= 1;
        let Incoming::Fragment(fragment) = parse(true, &bytes)? else {
            unreachable!()
        };
        assert!(
            Receiver::default()
                .receive(fragment, Some(&key), sharing)
                .is_err()
        );
        Ok(())
    }
}
