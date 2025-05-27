use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
    upgrade::Upgraded,
};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    sync::{atomic::AtomicI8, Arc},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use http::{Method, Request, Response, StatusCode};
use log::{info, error};

use crate::model::config::APP_CONFIG;

type ClientBuilder = hyper::client::conn::http1::Builder;
type ServerBuilder = hyper::server::conn::http1::Builder;

static CURRENT_INDEX: AtomicI8 = AtomicI8::new(0);


fn pick_key() -> Vec<u8> {
    // 负载均衡：轮询选择 key
    let total = APP_CONFIG.gemini.len() as i8;
    if total == 0 {
        error!("No Gemini API Key configured");
        return b"".to_vec();
    }
    let index = CURRENT_INDEX.fetch_update(
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
        |i| Some((i + 1) % total)
    ).unwrap_or(0);
    APP_CONFIG.gemini
        .get(index as usize)
        .map_or_else(
            || {
                error!("No Gemini API Key configured at index {index}");
                b"".to_vec()
            },
            |config| config.key.as_bytes().to_vec(),
        )
}

// 运行代理服务
pub(crate) async fn run_service() -> anyhow::Result<()> {
    log::info!("代理服务运行中...");
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8443);
    let listener = TcpListener::bind(addr).await?;
    info!("Listening on http://{addr}");

    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(err) = ServerBuilder::new()
                .serve_connection(TokioIo::new(stream), service_fn(proxy))
                .with_upgrades()
                .await
            {
                error!("Failed to serve connection from {addr}: {err:?}");
            }
        });
    }
}

async fn proxy(req: Request<Incoming>) -> anyhow::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    if Method::CONNECT == req.method() {
        if let Some(addr) = req.uri().authority().map(|auth| auth.to_string()) {
            // 立即返回一个成功的 Response
            let mut resp = Response::new(empty());
            *resp.status_mut() = StatusCode::OK;

            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = mitm_tunnel(upgraded, addr).await {
                            let msg = format!("{e}");
                            if !msg.contains("peer closed connection without sending TLS close_notify") {
                                error!("MITM tunnel error: {e:?}");
                            }
                            // 否则静默忽略
                        }
                    }
                    Err(e) => error!("Upgrade error: {e:?}"),
                }
            });

            Ok(resp)
        } else {
            error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        // 普通 HTTP流量直接转发或自定义处理
        let host = req.uri().host().map(|h| h.to_string()).expect("uri has no host");
        let port = req.uri().port_u16().unwrap_or(80);
        let mut req = req;
        let old_uri = req.uri();
        let need_rewrite = old_uri.scheme().is_some();
        if need_rewrite {
            let path_and_query = old_uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
            let new_uri = http::Uri::builder().path_and_query(path_and_query).build().unwrap();
            // 构造新 request，保留 method、headers、body、version
            let (parts, body) = req.into_parts();
            let mut new_parts = parts;
            new_parts.uri = new_uri;
            req = Request::from_parts(new_parts, body);
        }

        let stream = TcpStream::connect((host.as_str(), port)).await.unwrap();
        let io = TokioIo::new(stream);

        let (mut sender, conn) = ClientBuilder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                error!("Connection failed: {err:?}");
            }
        });

        let resp = sender.send_request(req).await?;
        Ok(resp.map(|b| b.boxed()))
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn mitm_tunnel(upgraded: Upgraded, addr: String) -> anyhow::Result<()> {
    // 1. 解析主机名
    let host = addr.split(':').next().unwrap_or("localhost").to_string();

    // 2. 动态签发目标证书
    let SignResult { cert, key } = sign(&host)?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert.clone(), key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // 3. 与客户端完成 TLS 握手
    let client_tls = tls_acceptor.accept(TokioIo::new(upgraded)).await?;

    // 4. 连接到目标服务器，并作为 TLS 客户端握手
    let server_tcp = TcpStream::connect(&addr).await?;
    let mut root_store = RootCertStore::empty();
    // Load system root certificates
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host)?;
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_tls = connector.connect(server_name, server_tcp).await?;

    // 5. 在客户端和目标服务器之间复制流量
    let (mut client_reader, mut client_writer) = tokio::io::split(client_tls);
    let (mut server_reader, mut server_writer) = tokio::io::split(server_tls);

    // 篡改客户端发送过来的请求内容
    let client_to_server = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = client_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let mut modified = buf[..n].to_vec();
            let mut i = 0;
            while i + 4 < modified.len() {
                if &modified[i..i + 4] == b"key=" {
                    // 找到 key=，替换后面的内容
                    let mut j = i + 4;
                    while j < modified.len() && modified[j] != b'&' && modified[j] != b' ' && modified[j] != b'\r' && modified[j] != b'\n' {
                        j += 1;
                    }
                    // 将要替换的内容
                    let replaced = pick_key();
                    info!("current key: {}", String::from_utf8_lossy(&replaced));
                    modified.splice(i + 4..j, replaced.iter().cloned());
                    i = i + 4 + replaced.len();
                } else {
                    i += 1;
                }
            }
            server_writer.write_all(&modified).await?;
        }
        server_writer.shutdown().await?; // 保证发送 close_notify
        Ok::<_, std::io::Error>(())
    };

    let server_to_client = async {
        tokio::io::copy(&mut server_reader, &mut client_writer).await?;
        client_writer.shutdown().await?; // 保证发送 close_notify
        Ok::<_, std::io::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

pub struct SignResult {
    pub cert: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

fn sign(domain: &str) -> anyhow::Result<SignResult> {
    let issuer_key = load_private_key("certs/privatekey.pem")?;
    let issuer_params = load_certs("certs/certificate.pem")?;
    let issuer_cert = issuer_params.self_signed(&issuer_key)?;
    let mut params = CertificateParams::new(vec![
        domain.to_owned(),
        "127.0.0.1".to_owned(),
        "localhost".to_owned(),
    ])?;
    params.is_ca = rcgen::IsCa::NoCa;
    // 你可以在此处加载自己的 CA 证书和密钥进行签名
    let key = KeyPair::generate()?;
    let leaf_cert = params.signed_by(&key, &issuer_cert, &issuer_key)?;

    let cert_pem = leaf_cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let cert = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let key_pem = key.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader).map(|key| key.unwrap())?;

    Ok(SignResult { cert, key })
}

fn load_certs(filename: &str) -> anyhow::Result<CertificateParams> {
    let pem_str = fs::read_to_string(filename)?;
    Ok(CertificateParams::from_ca_cert_pem(&pem_str)?)
}

fn load_private_key(filename: &str) -> anyhow::Result<KeyPair> {
    let key_str = fs::read_to_string(filename)?;
    Ok(KeyPair::from_pem(&key_str)?)
}
