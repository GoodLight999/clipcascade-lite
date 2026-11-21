use crate::protocol::{
    self, Capability, Content, Frame, Incoming, Key, Receiver, Sharing, Transfer,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use reqwest::{
    Url,
    cookie::{CookieStore, Jar},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha3::{Digest, Sha3_512};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    time::{self, MissedTickBehavior},
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest},
};
use webrtc::{
    api::APIBuilder,
    data_channel::{
        RTCDataChannel, data_channel_message::DataChannelMessage,
        data_channel_state::RTCDataChannelState,
    },
    ice_transport::{ice_candidate::RTCIceCandidateInit, ice_server::RTCIceServer},
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription, signaling_state::RTCSignalingState,
    },
};
use zeroize::Zeroizing;

pub struct Settings {
    pub server: String,
    pub username: String,
    pub password: Zeroizing<String>,
    pub saved_session: Option<SavedSession>,
    pub encrypted: bool,
    pub salt: String,
    pub rounds: u32,
    pub ca: Option<PathBuf>,
    pub sharing: Sharing,
}

pub struct SavedSession {
    id: Zeroizing<String>,
    key: Option<Key>,
}

impl SavedSession {
    pub fn from_official_file(path: &std::path::Path, settings: &Settings) -> Result<Self> {
        #[derive(Deserialize)]
        struct OfficialProfile<'a> {
            #[serde(borrow)]
            server_url: &'a str,
            username: &'a str,
            cipher_enabled: bool,
            #[serde(default)]
            salt: &'a str,
            hash_rounds: u32,
            cookie: OfficialCookie<'a>,
            hashed_password: Option<&'a str>,
        }

        #[derive(Deserialize)]
        struct OfficialCookie<'a> {
            #[serde(rename = "JSESSIONID")]
            id: &'a str,
        }

        let raw = Zeroizing::new(std::fs::read(path).context("公式版の保存設定を読み込めません")?);
        let profile: OfficialProfile = serde_json::from_slice(&raw)
            .map_err(|_| anyhow!("公式版の保存セッションを読み込めません"))?;
        ensure!(
            profile.server_url.trim_end_matches('/') == settings.server.trim_end_matches('/')
                && profile.username == settings.username
                && profile.cipher_enabled == settings.encrypted
                && (!settings.encrypted
                    || (profile.salt == settings.salt && profile.hash_rounds == settings.rounds)),
            "公式版と接続先・アカウント・暗号化設定が一致しません"
        );
        ensure!(
            !profile.cookie.id.is_empty()
                && profile
                    .cookie
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
            "公式版の保存セッションが無効です"
        );
        let key = if settings.encrypted {
            let encoded = profile
                .hashed_password
                .context("公式版の暗号鍵が見つかりません")?;
            let decoded = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .context("公式版の暗号鍵を読み込めません")?,
            );
            Some(Zeroizing::new(
                decoded
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("公式版の暗号鍵が無効です"))?,
            ))
        } else {
            None
        };
        Ok(Self {
            id: Zeroizing::new(profile.cookie.id.to_owned()),
            key,
        })
    }
}

pub enum Event {
    Status(String),
    Peers(usize),
    RelayReady(bool),
    Authenticated,
    Received(Content),
    Sent(Arc<Content>, usize),
    Error(String),
    Ended,
}

pub trait Reporter: Clone + Send + Sync + 'static {
    fn emit(&self, event: Event);
}

#[derive(Clone, Default)]
pub struct Outbound(Arc<Mutex<Option<Content>>>);

impl Outbound {
    pub fn new(content: Content) -> Self {
        Self(Arc::new(Mutex::new(Some(content))))
    }

    pub(crate) fn take(&self) -> Option<Arc<Content>> {
        self.0.lock().unwrap().take().map(Arc::new)
    }
}

pub(crate) type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const CHANNEL_LABEL: &str = "cliptext";
const PEER_LIMIT: usize = 32;
const PING_INTERVAL: Duration = Duration::from_secs(20);
const P2P_CHECK_INTERVAL: Duration = Duration::from_secs(3);
const P2P_OFFER_TIMEOUT: Duration = Duration::from_secs(18);
const P2P_FAILURE_RETRY: Duration = Duration::from_secs(2);
const P2P_REJOIN_AFTER: Duration = Duration::from_secs(30);

fn short_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn describe_candidate(raw: &str) -> String {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    if tokens.len() < 8 {
        return "empty-or-unknown".to_owned();
    }
    let proto = tokens[2];
    let addr = classify_addr(tokens[4]);
    let typ = tokens
        .windows(2)
        .find_map(|pair| (pair[0] == "typ").then_some(pair[1]))
        .unwrap_or("unknown");
    format!("proto={proto} typ={typ} addr={addr}")
}

fn classify_addr(ip: &str) -> &'static str {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        if v4.is_loopback() {
            "loopback"
        } else if v4.is_private() {
            "lan"
        } else if v4.is_link_local() {
            "link-local"
        } else if v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]) {
            "cgnat"
        } else {
            "public-v4"
        }
    } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() {
            "loopback-v6"
        } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
            "link-local-v6"
        } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
            "ula-v6"
        } else {
            "public-v6"
        }
    } else if ip.ends_with(".local") {
        "mdns"
    } else {
        "host"
    }
}

struct Session {
    socket_url: Url,
    cookie: reqwest::header::HeaderValue,
    tls: native_tls::TlsConnector,
    mode: Mode,
}

enum Mode {
    Peer { stun: String },
    Relay(crate::relay::Relay),
}

#[derive(Deserialize)]
struct ServerMode {
    mode: String,
}
#[derive(Deserialize)]
struct Stun {
    url: String,
}

impl Session {
    async fn login(settings: &Settings) -> Result<Self> {
        let mut base =
            Url::parse(settings.server.trim()).context("サーバーURLを確認してください")?;
        ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.host().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "サーバーURLを確認してください"
        );
        let path = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&path);
        let cookies = Arc::new(Jar::default());
        let mut tls = native_tls::TlsConnector::builder();
        if let Some(path) = &settings.ca {
            let pem = std::fs::read(path).context("CA証明書を読み込めません")?;
            let pem = std::str::from_utf8(&pem).context("PEM形式のCA証明書を選んでください")?;
            let mut count = 0;
            for block in pem.split_inclusive("-----END CERTIFICATE-----") {
                if let Some(index) = block.find("-----BEGIN CERTIFICATE-----") {
                    tls.add_root_certificate(native_tls::Certificate::from_pem(
                        &block.as_bytes()[index..],
                    )?);
                    count += 1;
                }
            }
            ensure!(count > 0, "PEM形式のCA証明書が見つかりません");
        }
        let tls = tls.build()?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls.clone())
            .cookie_provider(cookies.clone())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(12))
            .build()?;
        if let Some(saved) = &settings.saved_session {
            let cookie = Zeroizing::new(format!("JSESSIONID={}; Path=/", saved.id.as_str()));
            cookies.add_cookie_str(&cookie, &base);
        } else {
            Self::authenticate(&client, base.join("login")?, settings).await?;
        }
        let reply = client.get(base.join("server-mode")?).send().await?;
        ensure!(
            reply.status().is_success(),
            if settings.saved_session.is_some() {
                "保存セッションを利用できません。公式版で再接続するか、Liteにパスワードを入力してください"
            } else {
                "ログインを確認できません。ユーザー名とパスワードを確認してください"
            }
        );
        let mode = reply
            .json::<ServerMode>()
            .await
            .context("サーバーモードを取得できません")?;
        let (mode, endpoint) = match mode.mode.as_str() {
            "P2P" => {
                let stun = client
                    .get(base.join("stun-url")?)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Stun>()
                    .await
                    .context("STUN設定を取得できません")?
                    .url;
                (Mode::Peer { stun }, "p2psignaling")
            }
            "P2S" => (
                Mode::Relay(crate::relay::Relay::discover(&base, client).await?),
                "clipsocket",
            ),
            _ => bail!("サーバーの接続方式に対応していません"),
        };
        let mut socket_url = base.join(endpoint)?;
        let cookie = cookies
            .cookies(&socket_url)
            .context("ログインセッションが見つかりません")?;
        socket_url
            .set_scheme(if socket_url.scheme() == "https" {
                "wss"
            } else {
                "ws"
            })
            .map_err(|_| anyhow!("シグナリングURLが無効です"))?;
        Ok(Self {
            socket_url,
            cookie,
            tls,
            mode,
        })
    }

    async fn authenticate(client: &reqwest::Client, login: Url, settings: &Settings) -> Result<()> {
        let html = client
            .get(login.clone())
            .send()
            .await
            .context("ログインページに接続できません")?
            .error_for_status()?
            .text()
            .await?;
        let csrf = {
            let document = scraper::Html::parse_document(&html);
            let selector = scraper::Selector::parse("input[name='_csrf']").unwrap();
            document
                .select(&selector)
                .next()
                .and_then(|n| n.value().attr("value"))
                .context("ログインページにCSRFトークンがありません")?
                .to_owned()
        };
        let digest = Zeroizing::new(format!(
            "{:x}",
            Sha3_512::digest(settings.password.as_bytes())
        ));
        let result = client
            .post(login)
            .form(&[
                ("username", settings.username.as_str()),
                ("password", digest.as_str()),
                ("_csrf", csrf.as_str()),
            ])
            .send()
            .await
            .context("ログインに失敗しました")?;
        let location = result
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        ensure!(
            (result.status().is_success() || result.status().is_redirection())
                && !location.contains("error"),
            "ログインに失敗しました。ユーザー名とパスワードを確認してください"
        );
        Ok(())
    }

    async fn connect(&self) -> Result<Socket> {
        let mut request = self.socket_url.as_str().into_client_request()?;
        request
            .headers_mut()
            .insert(reqwest::header::COOKIE, self.cookie.clone());
        let max_size = match &self.mode {
            Mode::Peer { .. } => 1024 * 1024,
            Mode::Relay(relay) => relay.wire_limit(),
        };
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(max_size))
            .max_frame_size(Some(max_size));
        let (socket, _) = time::timeout(
            Duration::from_secs(12),
            tokio_tungstenite::connect_async_tls_with_config(
                request,
                Some(config),
                true,
                Some(Connector::NativeTls(self.tls.clone())),
            ),
        )
        .await
        .context("シグナリング接続がタイムアウトしました")??;
        Ok(socket)
    }
}

pub async fn run(
    mut settings: Settings,
    mut outgoing: watch::Receiver<Outbound>,
    mut paused: watch::Receiver<bool>,
    report: impl Reporter,
) -> Result<()> {
    report.emit(Event::Status(if settings.saved_session.is_some() {
        "保存セッションで接続しています…".into()
    } else {
        "ログインしています…".into()
    }));
    crate::diagnostic::debug(&format!(
        "net login start auth={} encrypted={}",
        if settings.saved_session.is_some() {
            "saved-session"
        } else {
            "password"
        },
        settings.encrypted
    ));
    let session = Session::login(&settings).await?;
    match &session.mode {
        Mode::Peer { stun } => {
            crate::diagnostic::debug(&format!("net login ok mode=P2P stun={stun}"));
        }
        Mode::Relay(_) => {
            crate::diagnostic::debug("net login ok mode=P2S");
        }
    }
    report.emit(Event::Authenticated);
    let sharing = settings.sharing;
    let key = if let Some(saved) = settings.saved_session.take() {
        saved.key
    } else if settings.encrypted {
        Some(
            tokio::task::spawn_blocking(move || {
                protocol::derive_key(
                    &settings.username,
                    &settings.password,
                    &settings.salt,
                    settings.rounds,
                )
            })
            .await?,
        )
    } else {
        None
    };
    let mut delay = Duration::from_secs(2);
    loop {
        outgoing.borrow_and_update().take();
        let result = match session.connect().await {
            Ok(socket) => {
                delay = Duration::from_secs(2);
                match &session.mode {
                    Mode::Peer { stun } => {
                        crate::diagnostic::debug("p2p signaling ws connected");
                        report.emit(Event::Status("シグナリング接続済み · 端末を待機中".into()));
                        let mut mesh = Mesh::new(stun, key.as_ref(), sharing, report.clone());
                        let result = mesh.drive(socket, &mut outgoing, &mut paused).await;
                        mesh.close().await;
                        result
                    }
                    Mode::Relay(relay) => {
                        crate::diagnostic::debug("p2s relay ws connected");
                        let result = relay
                            .drive(
                                socket,
                                key.as_ref(),
                                sharing,
                                &mut outgoing,
                                &mut paused,
                                &report,
                            )
                            .await;
                        report.emit(Event::RelayReady(false));
                        result
                    }
                }
            }
            Err(e)
                if e.downcast_ref::<tokio_tungstenite::tungstenite::Error>()
                    .is_some_and(|e| {
                        matches!(e, tokio_tungstenite::tungstenite::Error::Http(response)
                    if matches!(response.status().as_u16(), 301 | 302 | 401 | 403))
                    }) =>
            {
                crate::diagnostic::debug(&format!("net ws auth expired: {e:#}"));
                bail!("サーバーのセッションが失効しました。再接続してください")
            }
            Err(e) => Err(e),
        };
        report.emit(Event::Peers(0));
        if let Err(e) = result {
            crate::diagnostic::debug(&format!("net loop disconnected: {e:#} retry_in={}s", delay.as_secs()));
            report.emit(Event::Error(format!("{e:#}")));
        }
        report.emit(Event::Status(format!(
            "接続が切れました · {} 秒後に再試行",
            delay.as_secs()
        )));
        time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Signal {
    #[serde(rename = "ASSIGNED_ID")]
    Assigned {
        #[serde(rename = "peerId")]
        peer: String,
    },
    #[serde(rename = "PEER_LIST")]
    List { peers: Vec<String> },
    #[serde(rename = "OFFER")]
    Offer {
        #[serde(rename = "fromPeerId")]
        from: String,
        offer: RTCSessionDescription,
    },
    #[serde(rename = "ANSWER")]
    Answer {
        #[serde(rename = "fromPeerId")]
        from: String,
        answer: RTCSessionDescription,
    },
    #[serde(rename = "ICE_CANDIDATE")]
    Candidate {
        #[serde(rename = "fromPeerId")]
        from: String,
        candidate: RTCIceCandidateInit,
    },
    #[serde(other)]
    Unknown,
}

enum Internal {
    Candidate(RTCIceCandidateInit),
    Channel(Arc<RTCDataChannel>),
    Open,
    ConnectionChanged,
    Message(DataChannelMessage),
    Closed,
    Failed,
}

type Notice = (String, u64, Internal);

struct Peer {
    generation: u64,
    connection: Arc<RTCPeerConnection>,
    channel: Option<Arc<RTCDataChannel>>,
    pending: Vec<RTCIceCandidateInit>,
    receiver: Receiver,
    capability: Capability,
    started: Instant,
}

impl Peer {
    fn is_open(&self) -> bool {
        self.connection.connection_state() == RTCPeerConnectionState::Connected
            && self
                .channel
                .as_ref()
                .is_some_and(|c| c.ready_state() == RTCDataChannelState::Open)
    }

    async fn remote(&mut self, description: RTCSessionDescription) -> Result<()> {
        self.connection.set_remote_description(description).await?;
        for candidate in self.pending.drain(..) {
            let _ = self.connection.add_ice_candidate(candidate).await;
        }
        Ok(())
    }
}

struct Mesh<'a, R> {
    api: webrtc::api::API,
    peers: HashMap<String, Peer>,
    expected: HashSet<String>,
    have_list: bool,
    id: String,
    next_generation: u64,
    inbox: mpsc::Receiver<Notice>,
    sender: mpsc::Sender<Notice>,
    stun: &'a str,
    key: Option<&'a Key>,
    sharing: Sharing,
    report: R,
    transfer: Option<tokio::task::JoinHandle<()>>,
    recovery: PeerRecovery,
    reported_roster: Option<(usize, bool)>,
}

#[derive(Default)]
struct PeerRecovery(Option<Instant>);

impl PeerRecovery {
    fn observe(&mut self, available: usize, connected: usize, now: Instant) {
        if available == 0 || connected > 0 {
            self.0 = None;
        } else {
            self.0.get_or_insert(now);
        }
    }

    fn should_rejoin(&self, now: Instant) -> bool {
        self.0.is_some_and(|since| now.duration_since(since) >= P2P_REJOIN_AFTER)
    }
}

impl<'a, R: Reporter> Mesh<'a, R> {
    fn new(stun: &'a str, key: Option<&'a Key>, sharing: Sharing, report: R) -> Self {
        let (sender, inbox) = mpsc::channel(256);
        Self {
            api: APIBuilder::new().build(),
            peers: HashMap::new(),
            expected: HashSet::new(),
            have_list: false,
            id: String::new(),
            next_generation: 0,
            inbox,
            sender,
            stun,
            key,
            sharing,
            report,
            transfer: None,
            recovery: PeerRecovery::default(),
            reported_roster: None,
        }
    }

    async fn drive(
        &mut self,
        mut socket: Socket,
        outgoing: &mut watch::Receiver<Outbound>,
        paused: &mut watch::Receiver<bool>,
    ) -> Result<()> {
        let mut heartbeat = time::interval(PING_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
        heartbeat.tick().await;
        let mut maintenance = time::interval(P2P_CHECK_INTERVAL);
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);
        maintenance.tick().await;
        let mut last_signal = Instant::now();
        loop {
            tokio::select! {
                next = socket.next() => {
                    last_signal = Instant::now();
                    match next.context("シグナリングが終了しました")?? {
                        Message::Text(message) => {
                            match serde_json::from_str(&message) {
                                Ok(signal) => {
                                    if let Err(error) = self.signal(&mut socket, signal).await {
                                        crate::diagnostic::debug(&format!("p2p signal error: {error:#}"));
                                        self.report.emit(Event::Error(format!("端末との接続処理: {error:#}")));
                                    }
                                }
                                Err(_) => {
                                    crate::diagnostic::debug("p2p signal parse error");
                                    self.report.emit(Event::Error("シグナリングメッセージの形式が無効です".into()));
                                }
                            }
                        }
                        Message::Ping(_) => socket.flush().await?,
                        Message::Close(frame) => {
                            crate::diagnostic::debug(&format!("p2p signaling ws close: {frame:?}"));
                            bail!("サーバーが接続を閉じました");
                        }
                        _ => {}
                    }
                }
                Some((id, generation, notice)) = self.inbox.recv() => {
                    if self.peers.get(&id).is_some_and(|peer| peer.generation == generation) {
                        let is_paused = *paused.borrow();
                        self.notice(&mut socket, &id, notice, is_paused).await?;
                    }
                }
                result = outgoing.changed() => {
                    result?;
                    let value = outgoing.borrow_and_update().take();
                    if let Some(content) = value.filter(|_| !*paused.borrow()) {
                        self.send(content);
                    }
                }
                result = paused.changed() => {
                    result?;
                    if *paused.borrow_and_update() {
                        self.cancel_transfer();
                        for peer in self.peers.values_mut() { peer.receiver = Receiver::default(); }
                    }
                }
                _ = maintenance.tick() => {
                    self.report_peers();
                    if self.recovery.should_rejoin(Instant::now()) {
                        crate::diagnostic::debug(&format!(
                            "p2p rejoin triggered: expected={} open=0 self={}",
                            self.expected.len(),
                            short_id(&self.id)
                        ));
                        bail!("P2Pで端末間接続が成立しないため、Lite側でサーバーに入り直します");
                    }
                    let mut expired = Vec::new();
                    for (id, peer) in &self.peers {
                        if !peer.is_open() && peer.started.elapsed() >= P2P_OFFER_TIMEOUT {
                            expired.push((id.clone(), peer.generation, peer.started.elapsed().as_secs()));
                        }
                    }
                    for (id, generation, elapsed) in expired {
                        let role = if self.id < id { "offerer" } else { "answerer" };
                        crate::diagnostic::debug(&format!(
                            "p2p peer={} gen={generation} timeout elapsed={}s role={role}",
                            short_id(&id),
                            elapsed
                        ));
                        self.remove(&id).await;
                        if self.id < id && self.expected.contains(&id) {
                            crate::diagnostic::debug(&format!(
                                "p2p peer={} re-offering after timeout",
                                short_id(&id)
                            ));
                            self.offer(&mut socket, &id).await?;
                        }
                    }
                }
                _ = heartbeat.tick() => {
                    ensure!(last_signal.elapsed() <= PING_INTERVAL * 3, "シグナリングが応答しません");
                    socket.send(Message::Ping(Bytes::new())).await?;
                    for peer in self.peers.values_mut() {
                        peer.receiver.expire();
                        if peer.is_open() {
                            if let Some(channel) = &peer.channel {
                                let _ = channel.send_text(protocol::capability(self.sharing.limit)).await;
                            }
                            peer.started = Instant::now();
                        }
                    }
                }
            }
        }
    }

    async fn signal(&mut self, socket: &mut Socket, signal: Signal) -> Result<()> {
        match signal {
            Signal::Assigned { peer } => {
                crate::diagnostic::debug(&format!("p2p recv ASSIGNED_ID self={}", short_id(&peer)));
                if !self.id.is_empty() && self.id != peer {
                    self.close().await;
                }
                self.id = peer;
                if self.expected.remove(&self.id) {
                    self.recovery = PeerRecovery::default();
                }
                self.start_expected(socket).await?;
                self.report_peers();
            }
            Signal::List { peers } => {
                self.have_list = true;
                let total = peers.len();
                let next: HashSet<String> = peers
                    .into_iter()
                    .filter(|id| *id != self.id)
                    .take(PEER_LIMIT)
                    .collect();
                let summary: Vec<String> = next
                    .iter()
                    .map(|id| {
                        let role = if self.id.is_empty() {
                            "pending-id"
                        } else if self.id < *id {
                            "offerer"
                        } else {
                            "answerer"
                        };
                        format!("{}({role})", short_id(id))
                    })
                    .collect();
                crate::diagnostic::debug(&format!(
                    "p2p recv PEER_LIST total={total} self={} remote=[{}]",
                    short_id(&self.id),
                    summary.join(",")
                ));
                if self.expected != next {
                    self.recovery = PeerRecovery::default();
                    self.expected = next;
                }
                let gone: Vec<_> = self
                    .peers
                    .keys()
                    .filter(|id| !self.expected.contains(*id))
                    .cloned()
                    .collect();
                for id in gone {
                    crate::diagnostic::debug(&format!("p2p peer={} removed (left PEER_LIST)", short_id(&id)));
                    self.remove(&id).await;
                }
                self.start_expected(socket).await?;
                self.report_peers();
            }
            Signal::Offer { from, offer } if self.accepts(&from) => {
                crate::diagnostic::debug(&format!(
                    "p2p peer={} recv OFFER sdp_len={}",
                    short_id(&from),
                    offer.sdp.len()
                ));
                if let Some(peer) = self.peers.get(&from)
                    && peer.connection.remote_description().await.is_some()
                {
                    crate::diagnostic::debug(&format!(
                        "p2p peer={} gen={} replacing existing peer on new OFFER",
                        short_id(&from),
                        peer.generation
                    ));
                    self.remove(&from).await;
                }
                self.ensure_peer(&from).await?;
                let peer = self.peers.get_mut(&from).unwrap();
                let generation = peer.generation;
                peer.remote(offer).await?;
                let answer = peer.connection.create_answer(None).await?;
                peer.connection
                    .set_local_description(answer.clone())
                    .await?;
                crate::diagnostic::debug(&format!(
                    "p2p peer={} gen={generation} send ANSWER sdp_len={}",
                    short_id(&from),
                    answer.sdp.len()
                ));
                self.relay(socket, &from, "ANSWER", "answer", json!(answer))
                    .await?;
            }
            Signal::Offer { from, .. } => {
                crate::diagnostic::debug(&format!(
                    "p2p peer={} ignored OFFER (not accepted)",
                    short_id(&from)
                ));
            }
            Signal::Answer { from, answer } => {
                if let Some(peer) = self.peers.get_mut(&from) {
                    let state = peer.connection.signaling_state();
                    if state == RTCSignalingState::HaveLocalOffer {
                        crate::diagnostic::debug(&format!(
                            "p2p peer={} gen={} recv ANSWER sdp_len={}",
                            short_id(&from),
                            peer.generation,
                            answer.sdp.len()
                        ));
                        peer.remote(answer).await?;
                    } else {
                        crate::diagnostic::debug(&format!(
                            "p2p peer={} gen={} ignored ANSWER in signaling_state={state:?}",
                            short_id(&from),
                            peer.generation
                        ));
                    }
                } else {
                    crate::diagnostic::debug(&format!(
                        "p2p peer={} ignored ANSWER (no peer)",
                        short_id(&from)
                    ));
                }
            }
            Signal::Candidate { from, candidate } if self.accepts(&from) => {
                let desc = describe_candidate(&candidate.candidate);
                self.ensure_peer(&from).await?;
                let peer = self.peers.get_mut(&from).unwrap();
                if peer.connection.remote_description().await.is_some() {
                    crate::diagnostic::debug(&format!(
                        "p2p peer={} gen={} recv ICE_CANDIDATE applied {desc}",
                        short_id(&from),
                        peer.generation
                    ));
                    peer.connection.add_ice_candidate(candidate).await?;
                } else if peer.pending.len() < 256 {
                    peer.pending.push(candidate);
                    crate::diagnostic::debug(&format!(
                        "p2p peer={} gen={} recv ICE_CANDIDATE queued({}) {desc}",
                        short_id(&from),
                        peer.generation,
                        peer.pending.len()
                    ));
                }
            }
            Signal::Candidate { from, .. } => {
                crate::diagnostic::debug(&format!(
                    "p2p peer={} ignored ICE_CANDIDATE (not accepted)",
                    short_id(&from)
                ));
            }
            Signal::Unknown => {}
        }
        Ok(())
    }

    fn accepts(&self, id: &str) -> bool {
        id != self.id && (!self.have_list || self.expected.contains(id))
    }

    async fn start_expected(&mut self, socket: &mut Socket) -> Result<()> {
        if self.id.is_empty() {
            return Ok(());
        }
        self.expected.remove(&self.id);
        let targets: Vec<_> = self
            .expected
            .iter()
            .filter(|id| self.id < **id && !self.peers.contains_key(*id))
            .cloned()
            .collect();
        for id in targets {
            self.offer(socket, &id).await?;
        }
        Ok(())
    }

    async fn offer(&mut self, socket: &mut Socket, id: &str) -> Result<()> {
        self.ensure_peer(id).await?;
        let peer = self.peers.get_mut(id).unwrap();
        let generation = peer.generation;
        let channel = peer
            .connection
            .create_data_channel(CHANNEL_LABEL, None)
            .await?;
        Self::setup_channel(&self.sender, id, generation, &channel);
        peer.channel = Some(channel);
        let offer = peer.connection.create_offer(None).await?;
        peer.connection.set_local_description(offer.clone()).await?;
        crate::diagnostic::debug(&format!(
            "p2p peer={} gen={generation} send OFFER sdp_len={}",
            short_id(id),
            offer.sdp.len()
        ));
        self.relay(socket, id, "OFFER", "offer", json!(offer)).await
    }

    async fn ensure_peer(&mut self, id: &str) -> Result<()> {
        if self.peers.contains_key(id) {
            return Ok(());
        }
        ensure!(
            self.peers.len() < PEER_LIMIT,
            "接続端末数の上限に達しました"
        );
        let ice_servers = if self.stun.is_empty() {
            Vec::new()
        } else {
            vec![RTCIceServer {
                urls: vec![self.stun.to_owned()],
                ..Default::default()
            }]
        };
        let connection = Arc::new(
            self.api
                .new_peer_connection(RTCConfiguration {
                    ice_servers,
                    ..Default::default()
                })
                .await?,
        );
        self.next_generation += 1;
        let generation = self.next_generation;
        crate::diagnostic::debug(&format!(
            "p2p peer={} gen={generation} created peer_connection",
            short_id(id)
        ));
        let (tx, remote) = (self.sender.clone(), id.to_owned());
        connection.on_ice_candidate(Box::new(move |candidate| {
            if let Some(candidate) = candidate.and_then(|c| c.to_json().ok()) {
                let _ = tx.try_send((remote.clone(), generation, Internal::Candidate(candidate)));
            }
            Box::pin(async {})
        }));
        let (tx, remote) = (self.sender.clone(), id.to_owned());
        connection.on_data_channel(Box::new(move |channel| {
            crate::diagnostic::debug(&format!(
                "p2p peer={} gen={generation} on_data_channel label={} state={:?}",
                short_id(&remote),
                channel.label(),
                channel.ready_state()
            ));
            if channel.label() == CHANNEL_LABEL {
                Self::setup_channel(&tx, &remote, generation, &channel);
                let _ = tx.try_send((remote.clone(), generation, Internal::Channel(channel)));
            }
            Box::pin(async {})
        }));
        let remote_ice = id.to_owned();
        connection.on_ice_connection_state_change(Box::new(move |state| {
            crate::diagnostic::debug(&format!(
                "p2p peer={} gen={generation} ice_state={state:?}",
                short_id(&remote_ice)
            ));
            Box::pin(async {})
        }));
        let remote_gather = id.to_owned();
        connection.on_ice_gathering_state_change(Box::new(move |state| {
            crate::diagnostic::debug(&format!(
                "p2p peer={} gen={generation} ice_gather={state:?}",
                short_id(&remote_gather)
            ));
            Box::pin(async {})
        }));
        let (tx, remote) = (self.sender.clone(), id.to_owned());
        connection.on_peer_connection_state_change(Box::new(move |state| {
            crate::diagnostic::debug(&format!(
                "p2p peer={} gen={generation} pc_state={state:?}",
                short_id(&remote)
            ));
            let notice = match state {
                RTCPeerConnectionState::Connected | RTCPeerConnectionState::Disconnected => {
                    Some(Internal::ConnectionChanged)
                }
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    Some(Internal::Failed)
                }
                _ => None,
            };
            if let Some(notice) = notice {
                let _ = tx.try_send((remote.clone(), generation, notice));
            }
            Box::pin(async {})
        }));
        self.peers.insert(
            id.to_owned(),
            Peer {
                generation,
                connection,
                channel: None,
                pending: Vec::new(),
                receiver: Receiver::default(),
                capability: Capability::default(),
                started: Instant::now(),
            },
        );
        Ok(())
    }

    fn setup_channel(
        sender: &mpsc::Sender<Notice>,
        id: &str,
        generation: u64,
        channel: &RTCDataChannel,
    ) {
        let (tx, remote) = (sender.clone(), id.to_owned());
        channel.on_open(Box::new(move || {
            crate::diagnostic::debug(&format!(
                "p2p peer={} gen={generation} dc_open",
                short_id(&remote)
            ));
            let _ = tx.try_send((remote, generation, Internal::Open));
            Box::pin(async {})
        }));
        let (tx, remote) = (sender.clone(), id.to_owned());
        channel.on_close(Box::new(move || {
            crate::diagnostic::debug(&format!(
                "p2p peer={} gen={generation} dc_close",
                short_id(&remote)
            ));
            let _ = tx.try_send((remote.clone(), generation, Internal::Closed));
            Box::pin(async {})
        }));
        let (tx, remote) = (sender.clone(), id.to_owned());
        channel.on_message(Box::new(move |message| {
            let (tx, remote) = (tx.clone(), remote.clone());
            Box::pin(async move {
                let _ = tx
                    .send((remote, generation, Internal::Message(message)))
                    .await;
            })
        }));
    }

    async fn notice(
        &mut self,
        socket: &mut Socket,
        id: &str,
        notice: Internal,
        paused: bool,
    ) -> Result<()> {
        let peer = self.peers.get_mut(id).unwrap();
        let generation = peer.generation;
        match notice {
            Internal::Candidate(mut candidate) if !self.id.is_empty() => {
                if let Some(description) = peer.connection.local_description().await {
                    candidate.sdp_mid = description
                        .sdp
                        .lines()
                        .find_map(|line| line.strip_prefix("a=mid:"))
                        .map(str::to_owned);
                }
                crate::diagnostic::debug(&format!(
                    "p2p peer={} gen={generation} send ICE_CANDIDATE {}",
                    short_id(id),
                    describe_candidate(&candidate.candidate)
                ));
                self.relay(socket, id, "ICE_CANDIDATE", "candidate", json!(candidate))
                    .await?;
            }
            Internal::Channel(channel) => {
                let open = channel.ready_state() == RTCDataChannelState::Open;
                peer.channel = Some(channel);
                if open {
                    if let Some(channel) = &peer.channel {
                        let _ = channel
                            .send_text(protocol::capability(self.sharing.limit))
                            .await;
                    }
                    self.report_peers();
                }
            }
            Internal::Open => {
                if let Some(channel) = &peer.channel {
                    let _ = channel
                        .send_text(protocol::capability(self.sharing.limit))
                        .await;
                }
                self.report_peers();
            }
            Internal::ConnectionChanged => self.report_peers(),
            Internal::Closed | Internal::Failed => {
                let reason = if matches!(notice, Internal::Closed) {
                    "dc_closed"
                } else {
                    "pc_failed"
                };
                crate::diagnostic::debug(&format!(
                    "p2p peer={} gen={generation} {reason} -> scheduling fast retry in {}s",
                    short_id(id),
                    P2P_FAILURE_RETRY.as_secs()
                ));
                peer.receiver = Receiver::default();
                peer.started = Instant::now()
                    .checked_sub(P2P_OFFER_TIMEOUT - P2P_FAILURE_RETRY)
                    .unwrap_or_else(Instant::now);
                self.report_peers();
            }
            Internal::Message(message) => {
                let result = match protocol::parse(!message.is_string, &message.data) {
                    Ok(Incoming::Capability(Some(cap))) => {
                        if peer.capability.binary != cap.binary || peer.capability.limit != cap.limit {
                            crate::diagnostic::debug(&format!(
                                "p2p peer={} gen={generation} recv capability binary={} limit={:?}",
                                short_id(id),
                                cap.binary,
                                cap.limit
                            ));
                        }
                        peer.capability = cap;
                        Ok(None)
                    }
                    Ok(Incoming::Fragment(fragment)) if !paused => {
                        peer.receiver.receive(fragment, self.key, self.sharing)
                    }
                    Ok(_) => Ok(None),
                    Err(e) => Err(e),
                };
                match result {
                    Ok(Some(content)) => self.report.emit(Event::Received(content)),
                    Err(e) => {
                        crate::diagnostic::debug(&format!(
                            "p2p peer={} gen={generation} recv error: {e:#}",
                            short_id(id)
                        ));
                        let message = if e.is::<serde_json::Error>() {
                            "受信エラー · データ形式が無効です".into()
                        } else {
                            format!("受信エラー · {e:#}")
                        };
                        self.report.emit(Event::Error(message));
                    }
                    _ => {}
                }
            }
            Internal::Candidate(_) => {}
        }
        Ok(())
    }

    async fn relay(
        &self,
        socket: &mut Socket,
        to: &str,
        kind: &str,
        field: &str,
        data: Value,
    ) -> Result<()> {
        let mut signal = json!({"type": kind, "fromPeerId": self.id, "toPeerId": to});
        signal[field] = data;
        socket
            .send(Message::Text(signal.to_string().into()))
            .await?;
        Ok(())
    }

    fn report_peers(&mut self) {
        let connected = self.peers.values().filter(|p| p.is_open()).count();
        self.report.emit(Event::Peers(connected));
        if !self.have_list || self.id.is_empty() {
            return;
        }
        let available = self.expected.len();
        self.recovery.observe(available, connected, Instant::now());
        let roster = (available, connected > 0);
        if self.reported_roster != Some(roster) {
            self.reported_roster = Some(roster);
            if connected == 0 {
                let status = if available == 0 {
                    "シグナリング接続済み · サーバー通知端末 0 台".to_owned()
                } else {
                    format!("P2P接続を確立中 · サーバー通知端末 {available} 台")
                };
                self.report.emit(Event::Status(status));
            }
        }
    }

    async fn remove(&mut self, id: &str) {
        if let Some(peer) = self.peers.remove(id) {
            let _ = time::timeout(Duration::from_secs(1), peer.connection.close()).await;
        }
    }

    fn cancel_transfer(&mut self) {
        if let Some(task) = self.transfer.take() {
            task.abort();
        }
    }

    async fn close(&mut self) {
        self.cancel_transfer();
        for (_, peer) in self.peers.drain() {
            let _ = time::timeout(Duration::from_secs(1), peer.connection.close()).await;
        }
    }

    fn send(&mut self, content: Arc<Content>) {
        self.cancel_transfer();
        let size = content.size();
        let mut modern = Vec::new();
        let mut legacy = Vec::new();
        for peer in self.peers.values().filter(|p| p.is_open()) {
            if peer
                .capability
                .limit
                .is_some_and(|limit| (size as u64) > limit)
            {
                continue;
            }
            let channel = peer.channel.as_ref().unwrap().clone();
            if peer.capability.binary {
                modern.push(channel);
            } else {
                legacy.push(channel);
            }
        }
        let report = self.report.clone();
        if modern.is_empty() && legacy.is_empty() {
            report.emit(Event::Error(
                "送信できません。接続端末と受信サイズ上限を確認してください".into(),
            ));
            return;
        }
        let key = self.key.cloned();
        self.transfer = Some(tokio::spawn(async move {
            let groups = async {
                let modern = send_group(content.clone(), key.clone(), true, modern);
                let legacy = send_group(content.clone(), key, false, legacy);
                let (modern, legacy) = tokio::join!(modern, legacy);
                let mut delivered = 0;
                for result in [modern, legacy] {
                    match result {
                        Ok((count, failed)) => {
                            delivered += count;
                            if failed > 0 {
                                report.emit(Event::Error(format!(
                                    "{failed} 台への転送が途中で止まりました"
                                )));
                            }
                        }
                        Err(error) => report.emit(Event::Error(format!("送信エラー · {error:#}"))),
                    }
                }
                if delivered > 0 {
                    report.emit(Event::Sent(content, delivered));
                }
            };
            groups.await;
        }));
    }
}

async fn send_group(
    content: Arc<Content>,
    key: Option<Key>,
    binary: bool,
    mut channels: Vec<Arc<RTCDataChannel>>,
) -> Result<(usize, usize)> {
    if channels.is_empty() {
        return Ok((0, 0));
    }
    let initial = channels.len();
    let transfer =
        tokio::task::spawn_blocking(
            move || match Transfer::new(&content, key.as_ref(), binary) {
                Err(error) if binary && error.to_string().contains("ヘッダー") => {
                    Transfer::new(&content, key.as_ref(), false)
                }
                result => result,
            },
        )
        .await??;
    for frame in transfer.frames()? {
        let binary;
        let frame = match frame? {
            Frame::Text(text) => {
                binary = false;
                Bytes::from(text)
            }
            Frame::Binary(data) => {
                binary = true;
                Bytes::from(data)
            }
        };
        let mut remaining = Vec::with_capacity(channels.len());
        for channel in channels {
            let sent = time::timeout(Duration::from_secs(15), async {
                while channel.buffered_amount().await > 1024 * 1024 {
                    ensure!(
                        channel.ready_state() == RTCDataChannelState::Open,
                        "データチャネルが閉じました"
                    );
                    time::sleep(Duration::from_millis(20)).await;
                }
                if binary {
                    channel.send(&frame).await?;
                } else {
                    channel.send_text(std::str::from_utf8(&frame)?).await?;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
            if matches!(sent, Ok(Ok(()))) {
                remaining.push(channel);
            }
        }
        channels = remaining;
        if channels.is_empty() {
            break;
        }
    }
    Ok((channels.len(), initial - channels.len()))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Clone)]
    struct Probe(mpsc::UnboundedSender<Event>);

    impl Reporter for Probe {
        fn emit(&self, event: Event) {
            let _ = self.0.send(event);
        }
    }

    #[test]
    fn p2p_recovery_only_rejoins_when_a_listed_peer_stays_unconnected() {
        let mut recovery = PeerRecovery::default();
        let start = Instant::now();
        recovery.observe(0, 0, start);
        assert!(!recovery.should_rejoin(start + P2P_REJOIN_AFTER));
        recovery.observe(1, 0, start);
        recovery.observe(1, 0, start + PING_INTERVAL);
        assert!(!recovery.should_rejoin(start + PING_INTERVAL));
        assert!(recovery.should_rejoin(start + P2P_REJOIN_AFTER));
        recovery.observe(2, 1, start + P2P_REJOIN_AFTER);
        assert!(!recovery.should_rejoin(start + P2P_REJOIN_AFTER * 2));
    }

    #[test]
    fn describe_candidate_classifies_without_leaking_public_ip() {
        let lan = describe_candidate(
            "candidate:1 1 udp 2122260223 192.168.0.10 50000 typ host generation 0",
        );
        assert_eq!(lan, "proto=udp typ=host addr=lan");
        let public = describe_candidate(
            "candidate:2 1 udp 1686052607 203.0.113.42 50001 typ srflx raddr 0.0.0.0 rport 0",
        );
        assert_eq!(public, "proto=udp typ=srflx addr=public-v4");
        assert!(!public.contains("203.0.113.42"));
    }

    #[tokio::test]
    async fn mesh_connects_both_sides_when_peer_list_precedes_assigned_id() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (s1, _) = listener.accept().await.unwrap();
            let mut ws1 = tokio_tungstenite::accept_async(s1).await.unwrap();
            let (s2, _) = listener.accept().await.unwrap();
            let mut ws2 = tokio_tungstenite::accept_async(s2).await.unwrap();

            let list = json!({"type": "PEER_LIST", "peers": ["peer-a", "peer-b"]}).to_string();
            // Send ASSIGNED_ID then PEER_LIST to peer-a (offerer),
            // and PEER_LIST BEFORE ASSIGNED_ID to peer-b (answerer).
            ws1.send(Message::Text(
                json!({"type": "ASSIGNED_ID", "peerId": "peer-a"})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            ws2.send(Message::Text(list.clone().into())).await.unwrap();
            ws2.send(Message::Text(
                json!({"type": "ASSIGNED_ID", "peerId": "peer-b"})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            ws1.send(Message::Text(list.into())).await.unwrap();

            loop {
                tokio::select! {
                    msg = ws1.next() => match msg {
                        Some(Ok(Message::Text(text))) => { let _ = ws2.send(Message::Text(text)).await; }
                        Some(Ok(Message::Ping(p))) => { let _ = ws1.send(Message::Pong(p)).await; }
                        None | Some(Err(_)) => break,
                        _ => {}
                    },
                    msg = ws2.next() => match msg {
                        Some(Ok(Message::Text(text))) => { let _ = ws1.send(Message::Text(text)).await; }
                        Some(Ok(Message::Ping(p))) => { let _ = ws2.send(Message::Pong(p)).await; }
                        None | Some(Err(_)) => break,
                        _ => {}
                    },
                }
            }
        });

        let url = format!("ws://{addr}");
        let (ws_a, _) = tokio_tungstenite::connect_async(&url).await?;
        let (ws_b, _) = tokio_tungstenite::connect_async(&url).await?;
        let sharing = Sharing {
            images: true,
            files: true,
            limit: 1024 * 1024,
        };
        let (tx_a, mut rx_a) = watch::channel(Outbound::default());
        let (_tx_b, mut rx_b) = watch::channel(Outbound::default());
        let (_pa, mut pause_a) = watch::channel(false);
        let (_pb, mut pause_b) = watch::channel(false);
        let (ev_a, mut inbox_a) = mpsc::unbounded_channel();
        let (ev_b, mut inbox_b) = mpsc::unbounded_channel();

        let drive_a = tokio::spawn(async move {
            let mut mesh = Mesh::new("", None, sharing, Probe(ev_a));
            let _ = mesh.drive(ws_a, &mut rx_a, &mut pause_a).await;
            mesh.close().await;
        });
        let drive_b = tokio::spawn(async move {
            let mut mesh = Mesh::new("", None, sharing, Probe(ev_b));
            let _ = mesh.drive(ws_b, &mut rx_b, &mut pause_b).await;
            mesh.close().await;
        });

        let wait_open = time::timeout(Duration::from_secs(15), async {
            let (mut a_open, mut b_open, mut b_got_msg) = (false, false, false);
            while !(a_open && b_open && b_got_msg) {
                tokio::select! {
                    Some(ev) = inbox_a.recv() => match ev {
                        Event::Peers(1) => {
                            a_open = true;
                            if b_open {
                                tx_a.send_replace(Outbound::new(Content::Text("hello-p2p".into())));
                            }
                        }
                        Event::Status(s) => assert!(!s.contains("2 台"), "miscounted self: {s}"),
                        _ => {}
                    },
                    Some(ev) = inbox_b.recv() => match ev {
                        Event::Peers(1) => {
                            b_open = true;
                            if a_open {
                                tx_a.send_replace(Outbound::new(Content::Text("hello-p2p".into())));
                            }
                        }
                        Event::Status(s) => assert!(!s.contains("2 台"), "miscounted self: {s}"),
                        Event::Received(Content::Text(t)) if t == "hello-p2p" => b_got_msg = true,
                        _ => {}
                    },
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;

        drive_a.abort();
        drive_b.abort();
        server.abort();
        wait_open??;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires an isolated official P2P server on 127.0.0.1:18765"]
    async fn rejoins_official_signaling_when_other_peer_stays_silent() -> Result<()> {
        ensure!(std::env::var("CLIPCASCADE_P2P_TEST").as_deref() == Ok("1"),
            "explicit opt-in for the isolated local test is required");
        let settings = Settings {
            server: "http://127.0.0.1:18765".into(),
            username: "admin".into(),
            password: Zeroizing::new("admin123".into()),
            saved_session: None,
            encrypted: false,
            salt: String::new(),
            rounds: 1,
            ca: None,
            sharing: Sharing { images: true, files: true, limit: 32 * 1024 * 1024 },
        };
        let session = Session::login(&settings).await?;
        ensure!(matches!(&session.mode, Mode::Peer { .. }));
        let mut silent = session.connect().await?;
        let (_tx, rx) = watch::channel(Outbound::default());
        let (_pause, pause_rx) = watch::channel(false);
        let (events, _inbox) = mpsc::unbounded_channel();
        let lite = run(settings, rx, pause_rx, Probe(events));
        let observe = async {
            let mut this = String::new();
            let mut first = None;
            while let Some(message) = silent.next().await {
                match message? {
                    Message::Ping(_) => silent.flush().await?,
                    Message::Text(text) => match serde_json::from_str::<Signal>(&text)? {
                        Signal::Assigned { peer } => this = peer,
                        Signal::List { peers } if !this.is_empty() && peers.len() == 2 => {
                            let other = peers.into_iter().find(|peer| peer != &this).unwrap();
                            if first.as_ref().is_some_and(|previous| previous != &other) {
                                return Ok(());
                            }
                            first = Some(other);
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            bail!("silent peer's signaling session ended")
        };
        tokio::select! {
            result = lite => result,
            result = time::timeout(Duration::from_secs(95), observe) => result?,
        }
    }

    // Run against an isolated official server on loopback and its Android app.
    #[tokio::test]
    #[ignore = "requires the official server and Android app"]
    async fn official_android_interop() -> Result<()> {
        ensure!(
            std::env::var("CLIPCASCADE_ANDROID_INTEROP").as_deref() == Ok("1"),
            "explicit opt-in for the isolated local test is required"
        );
        let settings = Settings {
            server: "http://127.0.0.1:18765".into(),
            username: "admin".into(),
            password: Zeroizing::new("admin123".into()),
            saved_session: None,
            encrypted: true,
            salt: String::new(),
            rounds: 664_937,
            ca: None,
            sharing: Sharing {
                images: true,
                files: true,
                limit: 32 * 1024 * 1024,
            },
        };
        let (tx, rx) = watch::channel(Outbound::default());
        let (_pause, pause_rx) = watch::channel(false);
        let (events, mut inbox) = mpsc::unbounded_channel();
        let network = tokio::spawn(run(settings, rx, pause_rx, Probe(events)));
        let scenario = async {
            let mut sent = 0;
            let mut received = HashSet::new();
            while let Some(event) = inbox.recv().await {
                match event {
                    Event::Status(status) => eprintln!("status {status}"),
                    Event::Peers(count) => eprintln!("peers {count}"),
                    Event::Error(error) => eprintln!("error {error}"),
                    Event::Received(content) => {
                        eprintln!("received {:?} {} bytes", content.kind(), content.size());
                        match content {
                            Content::Text(text) if text == "android-to-rust-351" => {
                                assert!(received.insert("text"));
                                tx.send_replace(Outbound::new(Content::Text(
                                    "rust-to-android-351".into(),
                                )));
                            }
                            Content::Image(data) => {
                                let img = image::load_from_memory(&data)?.into_rgba8();
                                assert_eq!(img.dimensions(), (2, 2));
                                assert_eq!(img.get_pixel(0, 0).0, [231, 21, 55, 255]);
                                assert!(received.insert("image"));
                                let output = image::RgbaImage::from_pixel(
                                    3,
                                    2,
                                    image::Rgba([22, 158, 73, 255]),
                                );
                                let mut png = std::io::Cursor::new(Vec::new());
                                output.write_to(&mut png, image::ImageFormat::Png)?;
                                tx.send_replace(Outbound::new(Content::Image(png.into_inner())));
                            }
                            Content::Files(files) => {
                                assert_eq!(
                                    files.get("android-a.txt").map(Vec::as_slice),
                                    Some(&b"android file a"[..])
                                );
                                assert_eq!(
                                    files.get("android-b.bin").map(Vec::as_slice),
                                    Some(&vec![0xd2; 57_000][..])
                                );
                                assert!(received.insert("files"));
                                tx.send_replace(Outbound::new(Content::Files(BTreeMap::from([
                                    ("rust-a.txt".into(), b"rust file a".to_vec()),
                                    ("rust-b.bin".into(), vec![0xa7; 65_000]),
                                ]))));
                            }
                            Content::Text(text) if text == "downloaded-rust-files-351" => {
                                ensure!(
                                    received.len() == 3 && sent == 3,
                                    "incomplete Android exchange"
                                );
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                    Event::Sent(content, peers) => {
                        eprintln!(
                            "sent {:?} {} bytes to {peers} peer(s)",
                            content.kind(),
                            content.size()
                        );
                        sent += 1;
                    }
                    Event::Ended => bail!("network ended"),
                    Event::RelayReady(ready) => eprintln!("relay ready {ready}"),
                    Event::Authenticated => {}
                }
            }
            bail!("network closed the report channel")
        };
        tokio::select! {
            result = time::timeout(Duration::from_secs(240), scenario) => result?,
            result = network => result?,
        }
    }
}
