use std::{net::SocketAddr, sync::Arc, time::Duration};

use http_body_util::BodyExt;
use proxy_core::TcpingResult;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("invalid uri: missing authority")]
    MissingAuthority,
    #[error("invalid uri authority")]
    InvalidAuthority,
    #[error("missing server port")]
    MissingPort,
    #[error("Invalid dns name")]
    InvalidDnsName(#[source] rustls::pki_types::InvalidDnsNameError),
}

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("io error")]
    Io(#[source] std::io::Error),
    #[error("failed to connect proxy")]
    ProxyConnect,
    #[error("tls connect error")]
    Tls(#[source] std::io::Error),
    #[error("http connect error")]
    Http(#[source] hyper::Error),
}

pub struct Tester {
    connector: TlsConnector,
    uri: http::Uri,
    server_name: rustls::pki_types::ServerName<'static>,
    server_host: String,
    server_port: u16,
}
impl Tester {
    pub fn new(uri: http::Uri) -> Result<Self, InitError> {
        let (server_name, server_host, server_port) = {
            let auth = uri.authority().ok_or(InitError::MissingAuthority)?;
            if let Ok(addr) = auth.as_str().parse::<SocketAddr>() {
                (
                    rustls::pki_types::ServerName::IpAddress(addr.ip().into()),
                    auth.host().to_string(),
                    addr.port(),
                )
            } else {
                let host = auth.host();
                (
                    rustls::pki_types::ServerName::DnsName(
                        rustls::pki_types::DnsName::try_from_str(host)
                            .map_err(|_| InitError::InvalidAuthority)?
                            .to_owned(),
                    ),
                    host.to_string(),
                    match auth.port_u16() {
                        Some(p) => p,
                        None if uri.scheme() == Some(&http::uri::Scheme::HTTPS) => 443,
                        _ => return Err(InitError::MissingPort),
                    },
                )
            }
        };

        Ok(Self {
            connector: Arc::new({
                let mut cfg = rustls::ClientConfig::builder()
                    .with_root_certificates(Arc::new({
                        let mut root = rustls::RootCertStore::empty();
                        for cert in rustls_native_certs::load_native_certs().certs {
                            let _ = root.add(cert);
                        }
                        root
                    }))
                    .with_no_client_auth();
                cfg.enable_sni = true;
                cfg.alpn_protocols = Vec::from([b"http/1.1".to_vec()]);
                cfg
            })
            .into(),
            server_name,
            server_host,
            server_port,
            uri,
        })
    }

    async fn connect_https<C>(&self, conn: C) -> Result<(), TestError>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let tls_conn = self
            .connector
            .connect(self.server_name.clone(), conn)
            .await
            .map_err(TestError::Tls)?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls_conn))
                .await
                .map_err(TestError::Http)?;

        tokio::spawn(conn);
        let mut resp = sender
            .send_request(
                http::Request::get(self.uri.clone())
                    .body(http_body_util::Empty::<&'static [u8]>::new())
                    .unwrap(),
            )
            .await
            .map_err(TestError::Http)?;
        while let Some(r) = resp.body_mut().frame().await {
            r.map_err(TestError::Http)?;
        }
        Ok(())
    }
    async fn test_http_connect_impl<C>(&self, mut conn: C) -> Result<Duration, TestError>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ts = std::time::Instant::now();

        conn.write_all(
            format!(
                "CONNECT {host}:{port} HTTP/1.1\r\nHost {host}:{port}\r\n\r\n",
                host = self.server_host,
                port = self.server_port,
            )
            .as_bytes(),
        )
        .await
        .map_err(TestError::Io)?;

        let mut buf = Vec::new();
        loop {
            conn.read_buf(&mut buf).await.map_err(TestError::Io)?;
            if buf.starts_with(b"HTTP/1.1 200") && buf.ends_with(b"\r\n\r\n") {
                break;
            } else if buf.len() > 8192 {
                return Err(TestError::ProxyConnect);
            }
        }

        self.connect_https(conn).await?;

        Ok(ts.elapsed())
    }

    pub async fn test_http_proxy_unix(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Duration, TestError> {
        self.test_http_connect_impl(Box::new(
            tokio::net::UnixStream::connect(path)
                .await
                .map_err(TestError::Io)?,
        ))
        .await
    }
}

pub fn tcping(addr: &SocketAddr) -> Result<TcpingResult, std::io::Error> {
    let start = std::time::Instant::now();
    let conn = std::net::TcpStream::connect_timeout(addr, std::time::Duration::from_secs(1))?;
    let duration = start.elapsed();
    let peer_addr = conn.peer_addr()?;
    Ok(TcpingResult {
        peer_addr,
        duration,
    })
}
