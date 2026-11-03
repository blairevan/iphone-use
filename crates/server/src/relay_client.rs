//! The cloud relay tunnel: lets a phone outside this network reach the daemon
//! with no Mac and no open port.
//!
//! The daemon dials out to `<relay>/t/<id>` over a WebSocket and keeps it
//! open. Requests that reach `<relay>/p/<id>/<path>` arrive on it as frames;
//! each is replayed against this daemon on loopback and the answer is streamed
//! back, so the daemon's own authentication applies unchanged. See
//! `relay/src/index.ts` for the frame format.
//!
//! The relay address comes from `IPHONE_USE_RELAY_URL`, or, for the on-phone
//! daemon, from `relay.json` a Mac drops into the app's Documents
//! (`iphone-use setup-app --connect-to … --relay …`). The phone's id and key
//! are made once and kept in the state directory: the relay pins the first key
//! an id presents.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

/// Largest body chunk sent in one frame.
const CHUNK: usize = 256 * 1024;
/// Body bytes a request may have in flight before the relay acks them (the
/// viewer took them). A live picture past this drops whole frames; anything
/// else waits.
const WINDOW: usize = 512 * 1024;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Identity {
    id: String,
    key: String,
}

/// Where requests reach this daemon through `relay`: `<relay>/p/<id>`.
pub fn public_url(relay: &str, state_dir: &Path) -> Option<String> {
    let relay = crate::security::relay_base(relay).ok()?;
    let identity = load_identity(state_dir).ok()?;
    Some(format!(
        "{}/p/{}",
        relay.as_str().trim_end_matches('/'),
        identity.id
    ))
}

/// Keep the tunnel to the relay that `relay_url` names open for as long as the
/// process runs. `relay_url` is asked again before each attempt, so a relay
/// configured later is picked up.
pub fn spawn(
    relay_url: impl Fn() -> Option<String> + Send + 'static,
    state_dir: PathBuf,
    port: u16,
    ingress: String,
    public: Option<String>,
) {
    tokio::spawn(async move {
        let mut backoff = 1u64;
        loop {
            if let Some(relay) = relay_url() {
                match run(&relay, &state_dir, port, &ingress, public.as_deref()).await {
                    Ok(()) => backoff = 1,
                    Err(_) => tracing::warn!("relay tunnel failed; reconnecting without logging remote response content"),
                }
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    });
}

fn identity_path(state_dir: &Path) -> PathBuf {
    state_dir.join("relay-identity.json")
}

fn load_identity(state_dir: &Path) -> Result<Identity, String> {
    use std::io::Write;
    let path = identity_path(state_dir);
    match read_identity(&path) {
        Ok(identity) => return Ok(identity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err("relay identity is unreadable or insecure; refusing to replace it".into())
        }
    }
    let mut id = [0u8; 16];
    let mut key = [0u8; 32];
    getrandom::fill(&mut id).map_err(|e| e.to_string())?;
    getrandom::fill(&mut key).map_err(|e| e.to_string())?;
    let identity = Identity { id: URL_SAFE_NO_PAD.encode(id), key: URL_SAFE_NO_PAD.encode(key) };
    // A NamedTempFile is private from creation. Persist without replacing a
    // concurrently created identity, and never follow a symlink at the target.
    let mut staged = tempfile::NamedTempFile::new_in(state_dir)
        .map_err(|_| "could not create private relay identity staging file")?;
    let bytes = serde_json::to_vec(&identity).map_err(|_| "could not serialize relay identity")?;
    staged
        .write_all(&bytes)
        .and_then(|_| staged.as_file().sync_all())
        .map_err(|_| "could not persist relay identity")?;
    match staged.persist_noclobber(&path) {
        Ok(_) => Ok(identity),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_identity(&path)
                .map_err(|_| "concurrent relay identity is insecure or invalid".into())
        }
        Err(_) => Err("could not install relay identity without replacement".into()),
    }
}

/// Open private key material without following symlinks. Never silently mint a
/// new identity for a corrupt file: that would defeat pairing and revocation.
fn read_identity(path: &Path) -> std::io::Result<Identity> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid relay identity");
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid reads process identity and has no pointer arguments.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    let identity: Identity = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if URL_SAFE_NO_PAD
        .decode(&identity.id)
        .ok()
        .is_none_or(|b| b.len() != 16)
        || URL_SAFE_NO_PAD
            .decode(&identity.key)
            .ok()
            .is_none_or(|b| b.len() != 32)
    {
        return Err(invalid());
    }
    Ok(identity)
}

/// One tunnel session, until the relay or the network drops it.
async fn run(
    relay: &str,
    state_dir: &Path,
    port: u16,
    ingress: &str,
    public: Option<&str>,
) -> Result<(), String> {
    let relay_base = crate::security::relay_base(relay)?;
    let ingress_base = public
        .map(crate::security::relay_base)
        .transpose()?
        .unwrap_or_else(|| relay_base.clone());
    let identity = load_identity(state_dir)?;
    let url = format!("{}/t/{}", relay_base.as_str().trim_end_matches('/'), identity.id)
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let mut request = url.as_str().into_client_request().map_err(|e| e.to_string())?;
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", identity.key).parse().map_err(|_| "bad key".to_string())?,
    );
    let uri = request.uri().clone();
    let host = uri.host().ok_or("relay url has no host")?.to_string();
    let tls = uri.scheme_str() == Some("wss");
    let port_num = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port_num))
        .await
        .map_err(|e| format!("connect {host}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let limits = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(2 * 1024 * 1024))
        .max_frame_size(Some(2 * 1024 * 1024));
    let (socket, _) = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|e| format!("tls {host}: {e}"))?;
        let (ws, response) = tokio_tungstenite::client_async_with_config(request, Box::new(stream) as Box<dyn Io>, Some(limits))
            .await
            .map_err(|e| format!("handshake: {e}"))?;
        (ws, response)
    } else {
        tokio_tungstenite::client_async_with_config(request, Box::new(tcp) as Box<dyn Io>, Some(limits))
            .await
            .map_err(|e| format!("handshake: {e}"))?
    };
    tracing::info!("authenticated relay tunnel open");

    let (mut sink, mut stream) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
    });
    let pinger = {
        let out_tx = out_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(25)).await;
                // The relay answers this text without waking its object.
                if out_tx.send(Message::Text("ping".into())).await.is_err() {
                    break;
                }
            }
        })
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|e| e.to_string())?;
    let mut tasks: HashMap<u32, (tokio::task::JoinHandle<()>, Arc<tokio::sync::Semaphore>)> = HashMap::new();
    let result = loop {
        let Some(message) = stream.next().await else { break Ok(()) };
        let text = match message {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => break Ok(()),
            Ok(_) => continue,
            Err(e) => break Err(e.to_string()),
        };
        if text.as_str() == "pong" {
            continue;
        }
        let Ok(frame) = serde_json::from_str::<serde_json::Value>(text.as_str()) else { continue };
        if text.len() > 2 * 1024 * 1024 {
            break Err("relay frame exceeds limit".into());
        }
        let Some(id) = frame["id"].as_u64().and_then(|id| u32::try_from(id).ok()) else {
            continue;
        };
        tasks.retain(|_, (task, _)| !task.is_finished());
        match frame["t"].as_str() {
            Some("req") => {
                if tasks.len() >= 32 || tasks.contains_key(&id) {
                    break Err("relay concurrent request limit or duplicate request id".into());
                }
                let window = Arc::new(tokio::sync::Semaphore::new(WINDOW));
                let authority = match ingress_base.port() {
                    Some(port) => format!("{}:{port}", ingress_base.host_str().unwrap_or("")),
                    None => ingress_base.host_str().unwrap_or("").to_string(),
                };
                let task = tokio::spawn(serve(client.clone(), port, id, frame, out_tx.clone(), window.clone(), TrustedIngress { authority, token: ingress.to_string() }));
                tasks.insert(id, (task, window));
            }
            Some("ack") => {
                if let (Some((_, window)), Some(n)) = (tasks.get(&id), frame["n"].as_u64()) {
                    if n > WINDOW as u64 { break Err("invalid relay acknowledgement".into()); }
                    window.add_permits((n as usize).min(WINDOW.saturating_sub(window.available_permits())));
                }
            }
            Some("cancel") => {
                if let Some((task, _)) = tasks.remove(&id) {
                    task.abort();
                }
            }
            _ => {}
        }
    };
    for (_, (task, _)) in tasks {
        task.abort();
    }
    pinger.abort();
    writer.abort();
    result
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// The configured relay's authority and the private local replay capability
/// travel together; neither comes from a client's forwarded headers.
struct TrustedIngress {
    authority: String,
    token: String,
}

/// Replay one relayed request on loopback and stream the answer back.
async fn serve(
    client: reqwest::Client,
    port: u16,
    id: u32,
    frame: serde_json::Value,
    out: mpsc::Sender<Message>,
    window: Arc<tokio::sync::Semaphore>,
    ingress: TrustedIngress,
) {
    let method = frame["m"].as_str().unwrap_or("GET");
    let path = frame["p"].as_str().unwrap_or("/");
    let reply = |status: u16, headers: Vec<(String, String)>| {
        Message::Text(serde_json::json!({ "t": "res", "id": id, "s": status, "h": headers }).to_string().into())
    };
    let end = || Message::Text(serde_json::json!({ "t": "end", "id": id }).to_string().into());
    if !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.len() > 8192
        || frame["h"].as_array().is_some_and(|h| h.len() > 64)
        || frame["b"].as_str().is_some_and(|b| b.len() > 1_400_000)
    {
        let _ = out.send(reply(400, Vec::new())).await;
        let _ = out.send(end()).await;
        return;
    }
    let Ok(method) = reqwest::Method::from_bytes(method.as_bytes()) else { return };
    let mut request = client.request(method, format!("http://127.0.0.1:{port}{path}"));
    for pair in frame["h"].as_array().into_iter().flatten() {
        if let (Some(name), Some(value)) = (pair[0].as_str(), pair[1].as_str()) {
            let name = name.to_ascii_lowercase();
            if !matches!(name.as_str(), "host" | "connection" | "content-length" | "transfer-encoding" | "forwarded" | "x-forwarded-host" | "x-forwarded-proto" | "x-real-ip")
                && !name.starts_with("x-iphone-use-") {
                request = request.header(name, value);
            }
        }
    }
    request = request
        .header("host", &ingress.authority)
        .header("x-forwarded-proto", "https")
        .header("x-iphone-use-relay-ingress", ingress.token);
    if let Some(source) = frame["source"]
        .as_str()
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
    {
        request = request.header("x-real-ip", source.to_string());
    }
    if let Some(body) = frame["b"].as_str().filter(|b| !b.is_empty()) {
        request = request.body(STANDARD.decode(body).unwrap_or_default());
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(_) => {
            let _ = out.send(reply(502, Vec::new())).await;
            let _ = out.send(end()).await;
            return;
        }
    };
    // A live picture (`multipart/x-mixed-replace; boundary=…`) may drop frames.
    let boundary = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with("multipart/x-mixed-replace"))
        .and_then(|v| v.split("boundary=").nth(1))
        .map(|b| format!("--{}", b.trim_matches('"').trim_start_matches("--")).into_bytes());
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
        .collect();
    if out.send(reply(response.status().as_u16(), headers)).await.is_err() {
        return;
    }
    let send = |piece: &[u8]| {
        let mut frame = Vec::with_capacity(4 + piece.len());
        frame.extend_from_slice(&id.to_be_bytes());
        frame.extend_from_slice(piece);
        Message::Binary(frame.into())
    };
    let mut body = response.bytes_stream();
    let mut parts = boundary.map(MultipartSplitter::new);
    while let Some(Ok(chunk)) = body.next().await {
        if let Some(splitter) = parts.as_mut() {
            for part in splitter.push(&chunk) {
                // Too far ahead of the viewer: skip this frame, keep the newest.
                let Ok(permit) = window.try_acquire_many(part.len().min(WINDOW) as u32) else { continue };
                permit.forget();
                if out.send(send(&part)).await.is_err() {
                    return;
                }
            }
            continue;
        }
        for piece in chunk.chunks(CHUNK) {
            let Ok(permit) = window.acquire_many(piece.len() as u32).await else { return };
            permit.forget();
            if out.send(send(piece)).await.is_err() {
                return;
            }
        }
    }
    let _ = out.send(end()).await;
}

/// Cuts a multipart stream into whole parts, each starting at its boundary,
/// so frames can be dropped without corrupting the ones that are sent.
struct MultipartSplitter {
    boundary: Vec<u8>,
    buffer: Vec<u8>,
}

impl MultipartSplitter {
    fn new(boundary: Vec<u8>) -> Self {
        Self { boundary, buffer: Vec::new() }
    }

    fn find(&self, from: usize) -> Option<usize> {
        let b = &self.boundary;
        self.buffer.get(from..)?.windows(b.len()).position(|w| w == b.as_slice()).map(|i| i + from)
    }

    /// The parts completed by `data` (a part ends where the next boundary starts).
    fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        let mut parts = Vec::new();
        while let Some(start) = self.find(0) {
            let Some(next) = self.find(start + self.boundary.len()) else {
                self.buffer.drain(..start);
                break;
            };
            parts.push(self.buffer[start..next].to_vec());
            self.buffer.drain(..next);
        }
        if self.buffer.len() > 16 << 20 {
            self.buffer.clear();
        }
        parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_parts_come_out_whole_whatever_the_chunking() {
        let stream = b"--B\r\nA1\r\n--B\r\nBB22\r\n--B\r\nC";
        for size in [1, 3, 7, stream.len()] {
            let mut splitter = MultipartSplitter::new(b"--B".to_vec());
            let mut parts = Vec::new();
            for chunk in stream.chunks(size) {
                parts.extend(splitter.push(chunk));
            }
            assert_eq!(parts, vec![b"--B\r\nA1\r\n".to_vec(), b"--B\r\nBB22\r\n".to_vec()], "chunk {size}");
        }
    }

    #[test]
    fn the_identity_is_made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("ipu-relay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_identity(&dir).unwrap();
        let second = load_identity(&dir).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.key, second.key);
        assert!(first.id.len() >= 22 && first.key.len() >= 32);
        assert_eq!(
            public_url("https://relay.example/", &dir).unwrap(),
            format!("https://relay.example/p/{}", first.id)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_identity_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        std::fs::write(&path, b"broken identity").unwrap();
        assert!(load_identity(dir.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"broken identity");
    }

    #[cfg(unix)]
    #[test]
    fn identity_is_private_and_symlinks_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        load_identity(dir.path()).unwrap();
        let path = identity_path(dir.path());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_identity(dir.path()).is_err());
        let other = tempfile::tempdir().unwrap();
        symlink(&path, identity_path(other.path())).unwrap();
        assert!(load_identity(other.path()).is_err());
    }
}
