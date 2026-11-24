//! Engagement-bound TLS termination. This module never opens an origin socket;
//! decrypted requests enter the same governed transport as ordinary HTTP.

use std::{
    convert::Infallible,
    fs, io,
    net::IpAddr,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rcgen::{Certificate, CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};
use uuid::Uuid;
use x509_parser::prelude::*;

use crate::transport::{Transport, TunnelTarget};

const HANDSHAKE_LIMIT: Duration = Duration::from_secs(5);

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// Signing material is supplied by the operator under one canonical engagement
/// directory. It is never generated from or selected by a client header/path.
pub struct WorkspaceCa {
    issuer: Certificate,
    key: KeyPair,
    certificate: CertificateDer<'static>,
}

impl WorkspaceCa {
    pub fn load(root: &Path, engagement: Uuid) -> io::Result<Self> {
        let root = root.canonicalize()?;
        let directory = root.join(engagement.to_string()).canonicalize()?;
        if directory != root.join(engagement.to_string()) {
            return Err(invalid("workspace CA escaped its engagement directory"));
        }
        let read = |name: &str| -> io::Result<String> {
            let path = directory.join(name).canonicalize()?;
            if path.parent() != Some(directory.as_path()) {
                return Err(invalid(
                    "workspace CA file escaped its engagement directory",
                ));
            }
            let metadata = fs::metadata(&path)?;
            if !metadata.is_file() || metadata.len() > 1024 * 1024 {
                return Err(invalid("workspace CA must be a bounded regular file"));
            }
            fs::read_to_string(path)
        };
        Self::from_pem(&read("ca.pem")?, &read("ca-key.pem")?)
    }

    fn from_pem(certificate: &str, private_key: &str) -> io::Result<Self> {
        let certificates =
            rustls_pemfile::certs(&mut certificate.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        if certificates.len() != 1 {
            return Err(invalid("workspace CA requires exactly one certificate"));
        }
        let certificate = certificates
            .into_iter()
            .next()
            .expect("checked single certificate");
        let key = KeyPair::from_pem(private_key).map_err(invalid)?;
        let (remaining, parsed) = parse_x509_certificate(certificate.as_ref()).map_err(invalid)?;
        if !remaining.is_empty() || !parsed.validity().is_valid() {
            return Err(invalid(
                "workspace CA certificate is malformed or not currently valid",
            ));
        }
        if !parsed
            .basic_constraints()
            .map_err(invalid)?
            .is_some_and(|v| v.value.ca)
            || parsed
                .key_usage()
                .map_err(invalid)?
                .is_some_and(|v| !v.value.key_cert_sign())
        {
            return Err(invalid("workspace certificate cannot sign certificates"));
        }
        if parsed.public_key().raw != key.public_key_der() {
            return Err(invalid(
                "workspace CA private key does not match its certificate",
            ));
        }
        let issuer = CertificateParams::from_ca_cert_der(&certificate)
            .map_err(invalid)?
            .self_signed(&key)
            .map_err(invalid)?;
        Ok(Self {
            issuer,
            key,
            certificate,
        })
    }

    /// Issue a leaf with precisely the CONNECT hostname or IP SAN, preserving
    /// the provisioned CA's validity ceiling. Only HTTP/1.1 is implemented.
    pub fn server_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(invalid)?;
        params.not_before = self.issuer.params().not_before;
        params.not_after = self.issuer.params().not_after;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().map_err(invalid)?;
        let leaf = params
            .signed_by(&key, &self.issuer, &self.key)
            .map_err(invalid)?;
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(invalid)?
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), self.certificate.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .map_err(invalid)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

/// Prefix bytes have already been consumed by the unmodified ingress
/// classifier. Replaying them must not duplicate, discard, or reorder bytes.
struct Replay<S> {
    prefix: Bytes,
    stream: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() && buffer.remaining() > 0 {
            let count = self.prefix.len().min(buffer.remaining());
            buffer.put_slice(&self.prefix.split_to(count));
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buffer)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub async fn serve<S>(
    client: S,
    prefix: Bytes,
    config: Arc<ServerConfig>,
    engagement: Uuid,
    target: TunnelTarget,
    transport: Transport,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = accept_bound(client, prefix, config, &target.host).await?;
    let service = service_fn(move |request| {
        let transport = transport.clone();
        let target = target.clone();
        async move { Ok::<_, Infallible>(transport.forward(request, engagement, Some(target)).await) }
    });
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HANDSHAKE_LIMIT)
        .serve_connection(TokioIo::new(stream), service)
        .await
        .map_err(invalid)
}

async fn accept_bound<S: AsyncRead + AsyncWrite + Unpin>(
    client: S,
    prefix: Bytes,
    config: Arc<ServerConfig>,
    host: &str,
) -> io::Result<tokio_rustls::server::TlsStream<Replay<S>>> {
    let stream = timeout(
        HANDSHAKE_LIMIT,
        TlsAcceptor::from(config).accept(Replay {
            prefix,
            stream: client,
        }),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client TLS handshake timed out"))??;
    // A client may explicitly suppress SNI (including every IP-address client).
    // If supplied, SNI cannot select a destination different from CONNECT.
    if let Some(sni) = stream.get_ref().1.server_name() {
        let matches = match (sni.parse::<IpAddr>(), host.parse::<IpAddr>()) {
            (Ok(left), Ok(right)) => left == right,
            _ => sni
                .trim_end_matches('.')
                .eq_ignore_ascii_case(host.trim_end_matches('.')),
        };
        if !matches {
            return Err(invalid("client SNI differs from CONNECT authority"));
        }
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose};
    use tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    };

    fn ca() -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let key = KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    }

    #[test]
    fn provisioned_ca_rejects_wrong_key_and_non_ca_certificates() {
        let (cert, key) = ca();
        let (_, other_key) = ca();
        assert!(WorkspaceCa::from_pem(&cert.pem(), &other_key.serialize_pem()).is_err());
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(WorkspaceCa::from_pem(&leaf.pem(), &key.serialize_pem()).is_err());
        assert!(WorkspaceCa::from_pem(&cert.pem(), &key.serialize_pem()).is_ok());
        let mut params = cert.params().clone();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let invalid_usage = params.clone().self_signed(&key).unwrap();
        assert!(WorkspaceCa::from_pem(&invalid_usage.pem(), &key.serialize_pem()).is_err());
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        let expired = params.self_signed(&key).unwrap();
        assert!(WorkspaceCa::from_pem(&expired.pem(), &key.serialize_pem()).is_err());
    }

    #[tokio::test]
    async fn generated_dns_and_ip_leaves_are_trusted_only_by_their_engagement_ca() {
        let (cert, key) = ca();
        let (other_cert, _) = ca();
        let workspace = WorkspaceCa::from_pem(&cert.pem(), &key.serialize_pem()).unwrap();
        for name in ["localhost", "127.0.0.1", "::1"] {
            for trusted in [true, false] {
                let config = workspace.server_config(name).unwrap();
                let (client, server) = tokio::io::duplex(8192);
                let accept =
                    tokio::spawn(async move { TlsAcceptor::from(config).accept(server).await });
                let mut roots = RootCertStore::empty();
                roots
                    .add(if trusted {
                        cert.der().clone()
                    } else {
                        other_cert.der().clone()
                    })
                    .unwrap();
                let config = ClientConfig::builder_with_provider(Arc::new(
                    tokio_rustls::rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                let result = TlsConnector::from(Arc::new(config))
                    .connect(ServerName::try_from(name.to_owned()).unwrap(), client)
                    .await;
                assert_eq!(result.is_ok(), trusted, "name={name} trusted={trusted}");
                drop(result);
                let _ = accept.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn valid_tls_handshake_cannot_change_the_connect_server_name_binding() {
        let (cert, key) = ca();
        let workspace = WorkspaceCa::from_pem(&cert.pem(), &key.serialize_pem()).unwrap();
        for host in ["fixture.invalid", "different.invalid"] {
            let config = workspace.server_config("fixture.invalid").unwrap();
            let (client, server) = tokio::io::duplex(8192);
            let accept =
                tokio::spawn(async move { accept_bound(server, Bytes::new(), config, host).await });
            let mut roots = RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let config = ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            // The client verifies its peer normally. The separate immutable
            // CONNECT hostname must still agree with the TLS ClientHello SNI.
            let stream = TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from("fixture.invalid").unwrap(), client)
                .await
                .unwrap();
            assert_eq!(accept.await.unwrap().is_ok(), host == "fixture.invalid");
            drop(stream);
        }
    }

    #[cfg(unix)]
    #[test]
    fn engagement_directory_alias_cannot_select_a_different_engagement_ca() {
        let root = std::env::temp_dir().join(format!("redops-ca-boundary-{}", Uuid::new_v4()));
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        fs::create_dir_all(root.join(second.to_string())).unwrap();
        std::os::unix::fs::symlink(root.join(second.to_string()), root.join(first.to_string()))
            .unwrap();
        assert!(WorkspaceCa::load(&root, first).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
