// rustls client on tokio for the integration tests, with rustls's default
// crypto provider (aws-lc-rs):
//   rustlsasync <port> <path> [tls12]
// sends a GET for <path> to 127.0.0.1:<port> over TLS 1.3, or TLS 1.2,
// accepting any certificate, and prints the response.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: rustlsasync <port> <path> [tls12]");
        std::process::exit(2);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if args.get(3).map(String::as_str) == Some("tls12") {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", args[1].parse::<u16>().unwrap())).await.unwrap();
    let mut tls = connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap();
    let request = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", args[2]);
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    // Servers may close without close_notify; what arrived is enough.
    let _ = tls.read_to_end(&mut response).await;
    print!("{}", String::from_utf8_lossy(&response));
}
