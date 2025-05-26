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
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use http::{Method, Request, Response, StatusCode};

type ClientBuilder = hyper::client::conn::http1::Builder;
type ServerBuilder = hyper::server::conn::http1::Builder;

/// 持有 CA 证书和缓存的中间证书

// 运行代理服务
pub(crate) async fn run_service() -> anyhow::Result<()> {
    log::info!("代理服务运行中...");
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8443);
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on https://{addr}");

    loop {
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(err) = ServerBuilder::new()
                .serve_connection(TokioIo::new(stream), service_fn(proxy))
                .with_upgrades()
                .await
            {
                eprintln!("Failed to serve connection from {addr}: {err:?}");
            }
        });
    }
}

async fn proxy(req: Request<Incoming>) -> anyhow::Result<Response<BoxBody<Bytes, hyper::Error>>> {
    println!("Received request: {:?}", req);
    if Method::CONNECT == req.method() {
        if let Some(addr) = req.uri().authority().map(|auth| auth.to_string()) {
            // 立即返回一个成功的 Response
            let mut resp = Response::new(empty());
            *resp.status_mut() = StatusCode::OK;

            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = mitm_tunnel(upgraded, addr).await {
                            eprintln!("MITM tunnel error: {e:?}");
                        }
                    }
                    Err(e) => eprintln!("Upgrade error: {e:?}"),
                }
            });

            Ok(resp)
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
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
                println!("Connection failed: {err:?}");
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

    // 5. 使用 hyper 处理明文 HTTP 流量
    async fn handle_decrypted_request(
        req: Request<Incoming>,
    ) -> anyhow::Result<Response<BoxBody<Bytes, hyper::Error>>> {
        println!("Received decrypted request: {:?}", req);
        println!("Received decrypted request body: {:?}", req.body());

        // 将解密后的请求转发到目标服务器
        let host = req.uri().host().expect("uri has no host");
        let port = req.uri().port_u16().unwrap_or(443);

        let stream = TcpStream::connect((host, port)).await.unwrap();
        let io = TokioIo::new(stream);

        let (mut sender, conn) = ClientBuilder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {err:?}");
            }
        });

        let resp = sender.send_request(req).await?;
        Ok(resp.map(|b| b.boxed()))
    }

    if let Err(err) = ServerBuilder::new()
        .serve_connection(TokioIo::new(client_tls), service_fn(handle_decrypted_request))
        .await
    {
        eprintln!("Failed to serve MITM connection: {err:?}");
    }

    // 6. 关闭与目标服务器的连接
    // server_tls 连接将在 serve_connection 结束后自动关闭

    Ok(())
}

pub struct SignResult {
    pub cert: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

fn sign(domain: &str) -> anyhow::Result<SignResult> {
    let issuer_key = load_private_key("certs/key.pem")?;
    let issuer_params = load_certs("certs/cert.pem")?;
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

    let issuer_cert_pem = issuer_cert.pem();
    let mut issuer_cert_reader = issuer_cert_pem.as_bytes();
    let issuer_cert_der = rustls_pemfile::certs(&mut issuer_cert_reader).collect::<Result<Vec<_>, _>>()?;

    let cert_pem = leaf_cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let cert = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let key_pem = key.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader).map(|key| key.unwrap())?;
    
    let mut full_chain = cert.clone();
    full_chain.extend(issuer_cert_der);

    Ok(SignResult { cert: full_chain, key })
}

fn load_certs(filename: &str) -> anyhow::Result<CertificateParams> {
    let pem_str = fs::read_to_string(filename)?;
    Ok(CertificateParams::from_ca_cert_pem(&pem_str)?)
}

fn load_private_key(filename: &str) -> anyhow::Result<KeyPair> {
    let key_str = fs::read_to_string(filename)?;
    Ok(KeyPair::from_pem(&key_str)?)
}
