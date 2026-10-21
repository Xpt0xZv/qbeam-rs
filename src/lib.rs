use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use futures_util::StreamExt;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use hyper_util::service::TowerToHyperService;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::RngCore;
use rayon::prelude::*;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use walkdir::WalkDir;

pub const CHUNK_SIZE: usize = 1024 * 1024;
pub const SMALL_FILE_THRESHOLD: u64 = 128 * 1024;
pub const BATCH_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const BATCH_MAX_FILES: usize = 64;
pub const STRIPE_THRESHOLD: u64 = 16 * 1024 * 1024;
pub const STRIPE_SEGMENT_SIZE: u64 = 8 * 1024 * 1024;
pub const MAX_RETRIES: usize = 8;
pub const BASE_RETRY_DELAY_MS: u64 = 250;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub rel_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub root_name: String,
    pub is_dir: bool,
    pub files: Vec<FileEntry>,
    pub empty_dirs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BatchRequest {
    paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StripeMeta {
    size: u64,
    segment_size: u64,
    completed: Vec<u64>,
}

#[derive(Clone)]
struct AppState {
    base_dir: PathBuf,
    manifest: Arc<Manifest>,
    expected_auth: String,
}

/// Computes SHA-256 hex digest of a file on disk.
pub fn compute_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Detects the primary LAN/VPN IPv4 address of the host.
pub fn get_local_ip() -> String {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("10.255.255.255:1").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

/// Generates an ephemeral ECDSA P-256 certificate and private key in memory,
/// returning (cert_der, key_der, 16-char sha256 hex fingerprint).
pub fn generate_ephemeral_tls(
    ip_str: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>, String), Box<dyn std::error::Error + Send + Sync>>
{
    let mut params = CertificateParams::new(vec!["qbeam-ephemeral".to_string()])?;
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        params.subject_alt_names.push(SanType::IpAddress(ip));
    }
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let full_fp = hex::encode(hasher.finalize());
    let short_fp = full_fp[..16].to_string();

    Ok((cert_der, key_der, short_fp))
}

/// Custom Rustls ServerCertVerifier that enforces strict TLS 1.3 certificate fingerprint
/// pinning in constant time while validating the cryptographic handshake signature.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_fp: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCertVerifier {
    fn new(expected_fp: String) -> Self {
        Self {
            expected_fp: expected_fp.to_lowercase(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let actual_fp = hex::encode(hasher.finalize())[..16].to_lowercase();

        if actual_fp
            .as_bytes()
            .ct_eq(self.expected_fp.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(TlsError::General(format!(
                "Certificate fingerprint mismatch! Expected {}, got {}",
                self.expected_fp, actual_fp
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is disabled; TLS 1.3 required".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Scans target_path using Rayon multi-core parallelism to compute SHA-256 digests.
pub fn scan_target(target_path: &Path) -> std::io::Result<(PathBuf, Manifest)> {
    let target_path = std::fs::canonicalize(target_path)?;
    let is_dir = target_path.is_dir();
    let base_dir = if is_dir {
        target_path.clone()
    } else {
        target_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    let root_name = target_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "root".to_string());

    let mut discovered_files: Vec<(String, PathBuf, u64)> = Vec::new();
    let mut empty_dirs: Vec<String> = Vec::new();

    if !is_dir {
        let meta = std::fs::metadata(&target_path)?;
        discovered_files.push((root_name.clone(), target_path.clone(), meta.len()));
    } else {
        for entry in WalkDir::new(&target_path).into_iter().filter_map(Result::ok) {
            let p = entry.path();
            if p == target_path {
                continue;
            }
            let rel = p
                .strip_prefix(&base_dir)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");

            if entry.file_type().is_dir() {
                if std::fs::read_dir(p)?.next().is_none() {
                    empty_dirs.push(rel);
                }
            } else if entry.file_type().is_file() {
                let sz = entry.metadata()?.len();
                discovered_files.push((rel, p.to_path_buf(), sz));
            }
        }
    }

    let files: std::io::Result<Vec<FileEntry>> = discovered_files
        .into_par_iter()
        .map(|(rel_path, fpath, size)| {
            let sha256 = compute_sha256(&fpath)?;
            Ok(FileEntry {
                rel_path,
                size,
                sha256,
            })
        })
        .collect();

    Ok((
        base_dir,
        Manifest {
            root_name,
            is_dir,
            files: files?,
            empty_dirs,
        },
    ))
}

/// Validates that a relative path contains no parent/root traversal components and resolves inside base_dir.
fn resolve_safe_path(base_dir: &Path, rel_path: &str, must_exist: bool) -> Result<PathBuf, StatusCode> {
    if rel_path.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let rel = Path::new(rel_path);
    for comp in rel.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(StatusCode::NOT_FOUND),
        }
    }
    let joined = base_dir.join(rel);
    if must_exist {
        let canon_base = std::fs::canonicalize(base_dir).map_err(|_| StatusCode::NOT_FOUND)?;
        let canon_target = std::fs::canonicalize(&joined).map_err(|_| StatusCode::NOT_FOUND)?;
        if !canon_target.starts_with(&canon_base) || !canon_target.is_file() {
            return Err(StatusCode::NOT_FOUND);
        }
        Ok(canon_target)
    } else {
        Ok(joined)
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_hdr = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth_hdr
        .as_bytes()
        .ct_eq(state.expected_auth.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

async fn handle_manifest(State(state): State<AppState>) -> Json<Manifest> {
    Json((*state.manifest).clone())
}

async fn handle_file(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let rel_path = params.get("path").map(String::as_str).unwrap_or("");
    let full_path = resolve_safe_path(&state.base_dir, rel_path, true)?;
    let meta = tokio::fs::metadata(&full_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let file_size = meta.len();

    let mut file = tokio::fs::File::open(&full_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    if let Some(range_val) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let Some(spec) = range_val.strip_prefix("bytes=") {
            let parts: Vec<&str> = spec.split('-').collect();
            if parts.len() == 2 {
                let start: u64 = parts[0].parse().map_err(|_| StatusCode::RANGE_NOT_SATISFIABLE)?;
                let end: u64 = if parts[1].is_empty() {
                    file_size.saturating_sub(1)
                } else {
                    parts[1]
                        .parse::<u64>()
                        .map_err(|_| StatusCode::RANGE_NOT_SATISFIABLE)?
                        .min(file_size.saturating_sub(1))
                };

                if start >= file_size || start > end {
                    return Err(StatusCode::RANGE_NOT_SATISFIABLE);
                }

                let length = end - start + 1;
                file.seek(SeekFrom::Start(start))
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                let limited = file.take(length);
                let stream = ReaderStream::with_capacity(limited, CHUNK_SIZE);

                return Ok(Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONTENT_LENGTH, length.to_string())
                    .header(
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", start, end, file_size),
                    )
                    .body(Body::from_stream(stream))
                    .unwrap());
            }
        }
    }

    let stream = ReaderStream::with_capacity(file, CHUNK_SIZE);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_LENGTH, file_size.to_string())
        .body(Body::from_stream(stream))
        .unwrap())
}

async fn handle_batch(
    State(state): State<AppState>,
    Json(payload): Json<BatchRequest>,
) -> Result<Response, StatusCode> {
    if payload.paths.len() > BATCH_MAX_FILES {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut out = Vec::new();
    for rel in &payload.paths {
        let full_path = resolve_safe_path(&state.base_dir, rel, true)?;
        let data = tokio::fs::read(&full_path)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
        let rel_bytes = rel.as_bytes();
        out.extend_from_slice(&(rel_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u64).to_be_bytes());
        out.extend_from_slice(rel_bytes);
        out.extend_from_slice(&data);
    }

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Bytes::from(out),
    )
        .into_response())
}

pub fn create_router(base_dir: PathBuf, manifest: Manifest, token: &str) -> Router {
    let state = AppState {
        base_dir,
        manifest: Arc::new(manifest),
        expected_auth: format!("Bearer {}", token),
    };
    Router::new()
        .route("/manifest", get(handle_manifest))
        .route("/file", get(handle_file))
        .route("/batch", post(handle_batch))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
}

/// Starts a TLS 1.3 server on `bind_addr` and returns `(SocketAddr, ticket, JoinHandle)`.
pub async fn spawn_server(
    target_path: &Path,
    bind_addr: SocketAddr,
) -> Result<
    (SocketAddr, String, tokio::task::JoinHandle<()>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let (base_dir, manifest) = scan_target(target_path)?;
    let mut token_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let token = URL_SAFE_NO_PAD.encode(token_bytes);

    let local_ip = if bind_addr.ip().is_unspecified() {
        get_local_ip()
    } else {
        bind_addr.ip().to_string()
    };

    let (cert_der, key_der, cert_fp) = generate_ephemeral_tls(&local_ip)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(_) if bind_addr.port() != 0 => {
            eprintln!(
                "Port {} is already in use; automatically selecting a free port...",
                bind_addr.port()
            );
            let fallback = SocketAddr::new(bind_addr.ip(), 0);
            TcpListener::bind(fallback).await?
        }
        Err(e) => return Err(e.into()),
    };
    let actual_addr = listener.local_addr()?;
    let ticket = format!("{}:{}:{}:{}", local_ip, actual_addr.port(), cert_fp, token);

    let app = create_router(base_dir, manifest, &token);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp_stream, _)) = listener.accept().await else {
                break;
            };
            let _ = tcp_stream.set_nodelay(true);
            let acceptor = tls_acceptor.clone();
            let app_clone = app.clone();

            tokio::spawn(async move {
                if let Ok(tls_stream) = acceptor.accept(tcp_stream).await {
                    let io = TokioIo::new(tls_stream);
                    let service = TowerToHyperService::new(app_clone);
                    let _ = ServerBuilder::new(hyper_util::rt::TokioExecutor::new())
                        .http1()
                        .timer(TokioTimer::new())
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });

    Ok((actual_addr, ticket, handle))
}

/// CLI Sender Entrypoint (Machine A).
pub async fn run_sender(
    target_path: &Path,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Scanning & hashing {} (Rayon multi-core)...", target_path.display());
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let (base_dir, manifest) = scan_target(target_path)?;
    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    let num_files = manifest.files.len();
    drop(base_dir);
    drop(manifest);

    let (_, ticket, handle) = spawn_server(target_path, bind_addr).await?;

    println!(
        "\nReady! Serving {} files ({:.2} MB) over TLS 1.3 (SHA-256 Verified)",
        num_files,
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("\nRun this on Machine B:");
    println!("  qbeam-rs pull {}\n", ticket);
    println!("Press Ctrl+C to stop server...");

    tokio::signal::ctrl_c().await?;
    handle.abort();
    Ok(())
}

fn verify_file_integrity(path: &Path, expected_size: u64, expected_sha256: &str) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if meta.len() != expected_size {
        return false;
    }
    if expected_sha256.is_empty() {
        return true;
    }
    let Ok(actual) = compute_sha256(path) else {
        return false;
    };
    actual
        .to_lowercase()
        .as_bytes()
        .ct_eq(expected_sha256.to_lowercase().as_bytes())
        .unwrap_u8()
        == 1
}

/// Builds a reqwest::Client strictly locked to TLS 1.3 + pinned certificate fingerprint.
pub fn build_pinned_client(
    expected_fp: &str,
    token: &str,
    concurrency: usize,
) -> Result<reqwest::Client, Box<dyn std::error::Error + Send + Sync>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(
            expected_fp.to_string(),
        )))
        .with_no_client_auth();

    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", token).parse()?,
    );

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_cfg)
        .default_headers(default_headers)
        .pool_max_idle_per_host(concurrency + 5)
        .http1_only()
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()?;

    Ok(client)
}

/// Receiver Engine (Machine B): 3-Tier uv-style worker pool with auto-resume & SHA-256 check.
pub async fn run_receiver(
    ticket: &str,
    concurrency: usize,
    dest_root: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let start_instant = Instant::now();
    let parts: Vec<&str> = ticket.split(':').collect();
    if parts.len() != 4 {
        return Err("Invalid ticket format. Expected IP:PORT:FP:TOKEN".into());
    }
    let (ip, port_str, expected_fp, token) = (parts[0], parts[1], parts[2], parts[3]);
    let port: u16 = port_str.parse()?;
    let base_url = format!("https://{}:{}", ip, port);

    let client = build_pinned_client(expected_fp, token, concurrency)?;

    // Fetch manifest with retry
    let mut manifest: Option<Manifest> = None;
    for attempt in 0..=MAX_RETRIES {
        match client.get(format!("{}/manifest", base_url)).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    manifest = Some(resp.json::<Manifest>().await?);
                    break;
                } else {
                    return Err(format!("Manifest request failed with HTTP {}", resp.status()).into());
                }
            }
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("Certificate fingerprint mismatch") {
                    return Err(format!("Certificate fingerprint mismatch: {}", e).into());
                }
                if attempt >= MAX_RETRIES {
                    return Err(e.into());
                }
                let delay = (BASE_RETRY_DELAY_MS * (1 << attempt.min(5))).min(5000);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
        }
    }
    let manifest = manifest.ok_or("Failed to fetch manifest")?;

    let out_base = if manifest.is_dir {
        dest_root.join(&manifest.root_name)
    } else {
        dest_root.to_path_buf()
    };
    tokio::fs::create_dir_all(&out_base).await?;

    // Validate paths & pre-create directory tree
    let mut dirs_to_create: HashSet<PathBuf> = HashSet::new();
    for rel_empty in &manifest.empty_dirs {
        let target = resolve_safe_path(&out_base, rel_empty, false)
            .map_err(|_| format!("Unsafe empty_dir path: {}", rel_empty))?;
        dirs_to_create.insert(target);
    }
    for f_info in &manifest.files {
        let target = resolve_safe_path(&out_base, &f_info.rel_path, false)
            .map_err(|_| format!("Unsafe file path in manifest: {}", f_info.rel_path))?;
        if let Some(parent) = target.parent() {
            dirs_to_create.insert(parent.to_path_buf());
        }
    }
    for dir in dirs_to_create {
        tokio::fs::create_dir_all(dir).await?;
    }

    let total_bytes: u64 = manifest.files.iter().map(|f| f.size).sum();
    let total_files = manifest.files.len();

    let multi = MultiProgress::new();
    let overall_style = ProgressStyle::with_template(
        "{spinner:.green} {msg:<28} [{bar:28.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
    )?
    .progress_chars("=>-");
    let file_style = ProgressStyle::with_template(
        "  {msg:<28} [{bar:28.blue/black}] {bytes}/{total_bytes} ({bytes_per_sec})",
    )?
    .progress_chars("=>-");

    let overall_pb = multi.add(ProgressBar::new(total_bytes));
    overall_pb.set_style(overall_style);
    overall_pb.set_message(format!("TOTAL (0/{} files)", total_files));

    let mut large_files = Vec::new();
    let mut medium_files = Vec::new();
    let mut small_files = Vec::new();

    for f_info in manifest.files {
        let local_file = out_base.join(&f_info.rel_path);
        let expected_sha = f_info.sha256.clone();
        let sz = f_info.size;
        let lf_clone = local_file.clone();
        let already_ok =
            tokio::task::spawn_blocking(move || verify_file_integrity(&lf_clone, sz, &expected_sha))
                .await?;
        if already_ok {
            overall_pb.inc(sz);
            continue;
        }
        if sz >= STRIPE_THRESHOLD {
            large_files.push(f_info);
        } else if sz > SMALL_FILE_THRESHOLD {
            medium_files.push(f_info);
        } else {
            small_files.push(f_info);
        }
    }

    large_files.sort_by(|a, b| b.size.cmp(&a.size));
    medium_files.sort_by(|a, b| b.size.cmp(&a.size));

    let mut small_batches: Vec<Vec<FileEntry>> = Vec::new();
    let mut cur_batch: Vec<FileEntry> = Vec::new();
    let mut cur_bytes: u64 = 0;
    for sf in small_files {
        if !cur_batch.is_empty()
            && (cur_batch.len() >= BATCH_MAX_FILES || cur_bytes + sf.size > BATCH_MAX_BYTES)
        {
            small_batches.push(cur_batch);
            cur_batch = Vec::new();
            cur_bytes = 0;
        }
        cur_bytes += sf.size;
        cur_batch.push(sf);
    }
    if !cur_batch.is_empty() {
        small_batches.push(cur_batch);
    }

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    // Helper closure for single/medium file downloads with HTTP Range resume
    async fn download_one(
        client: reqwest::Client,
        base_url: String,
        out_base: PathBuf,
        f_info: FileEntry,
        sem: Arc<Semaphore>,
        multi: MultiProgress,
        file_style: ProgressStyle,
        overall_pb: ProgressBar,
    ) -> Result<(), String> {
        let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
        let local_file = out_base.join(&f_info.rel_path);
        let part_file = local_file.with_file_name(format!(
            "{}.qbeam.part",
            local_file.file_name().unwrap().to_string_lossy()
        ));

        let pb = multi.add(ProgressBar::new(f_info.size));
        pb.set_style(file_style);
        let short_name: String = Path::new(&f_info.rel_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .chars()
            .take(28)
            .collect();
        pb.set_message(short_name);

        let mut tracked: u64 = 0;
        for attempt in 0..=MAX_RETRIES {
            let mut resume_offset = tokio::fs::metadata(&part_file)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            if resume_offset > f_info.size {
                let _ = tokio::fs::remove_file(&part_file).await;
                resume_offset = 0;
            }
            if resume_offset > tracked {
                let delta = resume_offset - tracked;
                pb.inc(delta);
                overall_pb.inc(delta);
                tracked = resume_offset;
            }

            if resume_offset == f_info.size && f_info.size > 0 {
                let pf = part_file.clone();
                let sha = f_info.sha256.clone();
                let sz = f_info.size;
                let ok = tokio::task::spawn_blocking(move || verify_file_integrity(&pf, sz, &sha))
                    .await
                    .unwrap_or(false);
                if ok {
                    tokio::fs::rename(&part_file, &local_file)
                        .await
                        .map_err(|e| e.to_string())?;
                    pb.finish_and_clear();
                    return Ok(());
                }
                let _ = tokio::fs::remove_file(&part_file).await;
                resume_offset = 0;
                tracked = 0;
            }

            let mut req = client
                .get(format!("{}/file", base_url))
                .query(&[("path", &f_info.rel_path)]);
            if resume_offset > 0 {
                req = req.header(header::RANGE, format!("bytes={}-", resume_offset));
            }

            let res = async {
                let resp = req.send().await.map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("HTTP {}", resp.status()));
                }
                let is_partial = resp.status() == StatusCode::PARTIAL_CONTENT;
                let mut file = if resume_offset > 0 && is_partial {
                    tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&part_file)
                        .await
                        .map_err(|e| e.to_string())?
                } else {
                    tokio::fs::File::create(&part_file)
                        .await
                        .map_err(|e| e.to_string())?
                };

                let mut stream = resp.bytes_stream();
                while let Some(chunk_res) = stream.next().await {
                    let chunk = chunk_res.map_err(|e| e.to_string())?;
                    file.write_all(&chunk).await.map_err(|e| e.to_string())?;
                    let n = chunk.len() as u64;
                    tracked += n;
                    pb.inc(n);
                    overall_pb.inc(n);
                }
                file.flush().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            .await;

            if res.is_ok() {
                let pf = part_file.clone();
                let sha = f_info.sha256.clone();
                let sz = f_info.size;
                let ok = tokio::task::spawn_blocking(move || verify_file_integrity(&pf, sz, &sha))
                    .await
                    .unwrap_or(false);
                if ok {
                    tokio::fs::rename(&part_file, &local_file)
                        .await
                        .map_err(|e| e.to_string())?;
                    pb.finish_and_clear();
                    return Ok(());
                } else {
                    let _ = tokio::fs::remove_file(&part_file).await;
                    pb.finish_and_clear();
                    return Err(format!("SHA-256 integrity mismatch for {}", f_info.rel_path));
                }
            }

            if attempt >= MAX_RETRIES {
                pb.finish_and_clear();
                return res;
            }
            let delay = (BASE_RETRY_DELAY_MS * (1 << attempt.min(5))).min(5000);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        pb.finish_and_clear();
        Err("Exhausted retries".into())
    }

    // Spawn Tier 3 (Striped Large Files)
    for f_info in large_files {
        let client = client.clone();
        let base_url = base_url.clone();
        let out_base = out_base.clone();
        let sem = sem.clone();
        let overall_pb = overall_pb.clone();
        tasks.push(tokio::spawn(async move {
            let local_file = out_base.join(&f_info.rel_path);
            let part_file = local_file.with_file_name(format!(
                "{}.qbeam.part",
                local_file.file_name().unwrap().to_string_lossy()
            ));
            let meta_file = local_file.with_file_name(format!(
                "{}.qbeam.meta",
                local_file.file_name().unwrap().to_string_lossy()
            ));

            {
                let f = File::create(&part_file).map_err(|e| e.to_string())?;
                f.set_len(f_info.size).map_err(|e| e.to_string())?;
            }

            let num_segments = (f_info.size + STRIPE_SEGMENT_SIZE - 1) / STRIPE_SEGMENT_SIZE;
            let completed = Arc::new(Mutex::new(Vec::<u64>::new()));
            let mut seg_tasks = Vec::new();

            for seg_idx in 0..num_segments {
                let client = client.clone();
                let base_url = base_url.clone();
                let rel_path = f_info.rel_path.clone();
                let part_file = part_file.clone();
                let meta_file = meta_file.clone();
                let sem = sem.clone();
                let overall_pb = overall_pb.clone();
                let completed = completed.clone();
                let total_size = f_info.size;

                seg_tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
                    let seg_start = seg_idx * STRIPE_SEGMENT_SIZE;
                    let seg_end = (seg_start + STRIPE_SEGMENT_SIZE).min(total_size) - 1;
                    let resp = client
                        .get(format!("{}/file", base_url))
                        .query(&[("path", &rel_path)])
                        .header(header::RANGE, format!("bytes={}-{}", seg_start, seg_end))
                        .send()
                        .await
                        .map_err(|e| e.to_string())?;

                    if resp.status() != StatusCode::PARTIAL_CONTENT {
                        return Err(format!("Expected 206, got {}", resp.status()));
                    }
                    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
                    let pf = part_file.clone();
                    let len = bytes.len() as u64;
                    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                        let mut f = std::fs::OpenOptions::new().write(true).open(&pf)?;
                        f.seek(SeekFrom::Start(seg_start))?;
                        f.write_all(&bytes)?;
                        Ok(())
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;

                    overall_pb.inc(len);
                    let mut guard = completed.lock().await;
                    guard.push(seg_idx);
                    let meta_json = serde_json::to_string(&StripeMeta {
                        size: total_size,
                        segment_size: STRIPE_SEGMENT_SIZE,
                        completed: guard.clone(),
                    })
                    .unwrap_or_default();
                    let _ = tokio::fs::write(&meta_file, meta_json).await;
                    Ok::<(), String>(())
                }));
            }

            for st in seg_tasks {
                st.await.map_err(|e| e.to_string())??;
            }

            let pf = part_file.clone();
            let sha = f_info.sha256.clone();
            let sz = f_info.size;
            let ok = tokio::task::spawn_blocking(move || verify_file_integrity(&pf, sz, &sha))
                .await
                .map_err(|e| e.to_string())?;
            if !ok {
                let _ = tokio::fs::remove_file(&part_file).await;
                let _ = tokio::fs::remove_file(&meta_file).await;
                return Err(format!("SHA-256 mismatch on striped file {}", f_info.rel_path));
            }
            tokio::fs::rename(&part_file, &local_file)
                .await
                .map_err(|e| e.to_string())?;
            let _ = tokio::fs::remove_file(&meta_file).await;
            Ok::<(), String>(())
        }));
    }

    // Spawn Tier 2 (Medium Files)
    for f_info in medium_files {
        tasks.push(tokio::spawn(download_one(
            client.clone(),
            base_url.clone(),
            out_base.clone(),
            f_info,
            sem.clone(),
            multi.clone(),
            file_style.clone(),
            overall_pb.clone(),
        )));
    }

    // Spawn Tier 1 (Batched Small Files)
    for batch in small_batches {
        if batch.len() == 1 {
            tasks.push(tokio::spawn(download_one(
                client.clone(),
                base_url.clone(),
                out_base.clone(),
                batch.into_iter().next().unwrap(),
                sem.clone(),
                multi.clone(),
                file_style.clone(),
                overall_pb.clone(),
            )));
            continue;
        }
        let client = client.clone();
        let base_url = base_url.clone();
        let out_base = out_base.clone();
        let sem = sem.clone();
        let overall_pb = overall_pb.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
            let by_rel: HashMap<String, FileEntry> =
                batch.iter().map(|f| (f.rel_path.clone(), f.clone())).collect();
            let paths: Vec<String> = batch.iter().map(|f| f.rel_path.clone()).collect();

            let resp = client
                .post(format!("{}/batch", base_url))
                .json(&BatchRequest { paths })
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("Batch request failed with HTTP {}", resp.status()));
            }
            let raw = resp.bytes().await.map_err(|e| e.to_string())?;
            let mut offset = 0usize;
            while offset + 12 <= raw.len() {
                let path_len =
                    u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
                let data_len =
                    u64::from_be_bytes(raw[offset + 4..offset + 12].try_into().unwrap()) as usize;
                offset += 12;
                let rel_path = std::str::from_utf8(&raw[offset..offset + path_len])
                    .map_err(|e| e.to_string())?;
                offset += path_len;
                let file_bytes = &raw[offset..offset + data_len];
                offset += data_len;

                if let Some(entry) = by_rel.get(rel_path) {
                    let mut hasher = Sha256::new();
                    hasher.update(file_bytes);
                    let actual_sha = hex::encode(hasher.finalize());
                    if actual_sha
                        .as_bytes()
                        .ct_eq(entry.sha256.to_lowercase().as_bytes())
                        .unwrap_u8()
                        != 1
                    {
                        return Err(format!("SHA-256 mismatch in batch for {}", rel_path));
                    }
                    let local_file = out_base.join(rel_path);
                    let part_file = local_file.with_file_name(format!(
                        "{}.qbeam.part",
                        local_file.file_name().unwrap().to_string_lossy()
                    ));
                    tokio::fs::write(&part_file, file_bytes)
                        .await
                        .map_err(|e| e.to_string())?;
                    tokio::fs::rename(&part_file, &local_file)
                        .await
                        .map_err(|e| e.to_string())?;
                    overall_pb.inc(data_len as u64);
                }
            }
            Ok::<(), String>(())
        }));
    }

    for t in tasks {
        t.await.map_err(|e| e.to_string())??;
    }

    overall_pb.finish_with_message(format!("TOTAL ({}/{} files)", total_files, total_files));
    let elapsed = start_instant.elapsed().as_secs_f64().max(0.001);
    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    println!(
        "\n✔ Downloaded {} files ({:.2} MB) in {:.2}s ({:.1} MB/s) -> {}",
        total_files,
        mb,
        elapsed,
        mb / elapsed,
        out_base.display()
    );
    Ok(out_base)
}

// =====================================================================
// OPTIONAL PYTHON (PyO3) BINDINGS (`--features python`)
// =====================================================================
#[cfg(feature = "python")]
mod python_bindings {
    use super::*;
    use pyo3::exceptions::PyRuntimeError;
    use pyo3::prelude::*;

    #[pyfunction]
    #[pyo3(signature = (path, port=8443))]
    fn serve(py: Python<'_>, path: String, port: u16) -> PyResult<()> {
        py.allow_threads(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            rt.block_on(run_sender(Path::new(&path), port))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
        })
    }

    #[pyfunction]
    #[pyo3(signature = (ticket, concurrency=15, dest=".".to_string()))]
    fn pull(py: Python<'_>, ticket: String, concurrency: usize, dest: String) -> PyResult<String> {
        py.allow_threads(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let out = rt
                .block_on(run_receiver(&ticket, concurrency, Path::new(&dest)))
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(out.to_string_lossy().to_string())
        })
    }

    #[pyfunction]
    fn cli_main(py: Python<'_>) -> PyResult<()> {
        let args: Vec<String> = py
            .import_bound("sys")?
            .getattr("argv")?
            .extract()?;
        if args.len() < 3 || (args[1] != "serve" && args[1] != "pull") {
            println!("Usage:\n  qbeam-rs serve <folder_or_file> [port=8443]\n  qbeam-rs pull <ticket> [concurrency=15]");
            return Ok(());
        }
        if args[1] == "serve" {
            let port = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8443);
            serve(py, args[2].clone(), port)
        } else {
            let workers = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15);
            let _ = pull(py, args[2].clone(), workers, ".".to_string())?;
            Ok(())
        }
    }

    #[pymodule]
    fn qbeam_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(serve, m)?)?;
        m.add_function(wrap_pyfunction!(pull, m)?)?;
        m.add_function(wrap_pyfunction!(cli_main, m)?)?;
        Ok(())
    }
}

// =====================================================================
// AUTOMATED INTEGRATION & SECURITY TESTS (`cargo test`)
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_end_to_end_directory_and_batch_transfer() {
        let tmp = tempdir().unwrap();
        let src = tmp.path().join("pkg_src");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::create_dir_all(src.join("empty_sub")).unwrap();

        // Small files (/batch) + Medium file (/file)
        for i in 0..10 {
            std::fs::write(
                src.join(format!("nested/small_{}.txt", i)),
                format!("small payload {}", i).repeat(50),
            )
            .unwrap();
        }
        let big_payload = vec![0xABu8; 300 * 1024];
        std::fs::write(src.join("nested/medium.bin"), &big_payload).unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (addr, ticket, handle) = spawn_server(&src, bind_addr).await.unwrap();
        // Rewrite ticket IP to 127.0.0.1 for local loopback test
        let parts: Vec<&str> = ticket.split(':').collect();
        let local_ticket = format!("127.0.0.1:{}:{}:{}", addr.port(), parts[2], parts[3]);

        let dest = tmp.path().join("dest");
        std::fs::create_dir_all(&dest).unwrap();

        let pulled_root = run_receiver(&local_ticket, 4, &dest).await.unwrap();
        handle.abort();

        assert!(pulled_root.join("empty_sub").is_dir());
        assert_eq!(
            std::fs::read(pulled_root.join("nested/medium.bin")).unwrap(),
            big_payload
        );
        for i in 0..10 {
            let p = pulled_root.join(format!("nested/small_{}.txt", i));
            assert!(p.is_file());
        }
    }

    #[tokio::test]
    async fn test_certificate_pinning_rejects_tampered_fingerprint() {
        let tmp = tempdir().unwrap();
        let src_file = tmp.path().join("secret.bin");
        std::fs::write(&src_file, b"top secret").unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (addr, ticket, handle) = spawn_server(&src_file, bind_addr).await.unwrap();
        let parts: Vec<&str> = ticket.split(':').collect();
        let bad_ticket = format!("127.0.0.1:{}:0000000000000000:{}", addr.port(), parts[3]);

        let dest = tmp.path().join("dest_mitm");
        std::fs::create_dir_all(&dest).unwrap();

        let res = run_receiver(&bad_ticket, 2, &dest).await;
        handle.abort();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_invalid_token_and_path_traversal_blocked() {
        let tmp = tempdir().unwrap();
        let src = tmp.path().join("shared");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("ok.txt"), b"allowed").unwrap();

        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (addr, ticket, handle) = spawn_server(&src, bind_addr).await.unwrap();
        let parts: Vec<&str> = ticket.split(':').collect();
        let fp = parts[2];
        let token = parts[3];

        // 1. Bad token -> 403 Forbidden
        let bad_client = build_pinned_client(fp, "wrong_token", 2).unwrap();
        let r1 = bad_client
            .get(format!("https://127.0.0.1:{}/manifest", addr.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::FORBIDDEN);

        // 2. Path traversal -> 404 Not Found
        let good_client = build_pinned_client(fp, token, 2).unwrap();
        let r2 = good_client
            .get(format!("https://127.0.0.1:{}/file", addr.port()))
            .query(&[("path", "../outside.txt")])
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::NOT_FOUND);

        handle.abort();
    }
}
