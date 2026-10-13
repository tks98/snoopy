// Minimal rustls client for the integration tests:
//   rustlsclient <port> <path>
// sends a GET for <path> to 127.0.0.1:<port>, accepting any certificate.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: rustlsclient <port> <path>");
        std::process::exit(2);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
        .expect("client connection");
    let port: u16 = args[1].parse().expect("port");
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let req = format!("GET {} HTTP/1.0\r\nHost: localhost\r\n\r\n", args[2]);
    tls.write_all(req.as_bytes()).expect("write");
    let mut resp = Vec::new();
    match tls.read_to_end(&mut resp) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {} // closed without close_notify
        Err(e) => panic!("read: {e}"),
    }
    std::io::stdout().write_all(&resp).unwrap();
}
