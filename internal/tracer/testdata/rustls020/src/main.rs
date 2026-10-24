// rustls 0.20 client on tokio for the integration tests, whose crypto is
// ring 0.16:
//   rustls020 <port> <path> [tls12] [chacha]
// sends a GET for <path> to 127.0.0.1:<port> over TLS 1.3, or TLS 1.2, with
// AES-GCM or ChaCha20-Poly1305, accepting any certificate, and prints the
// response.

use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, CipherSuite, ServerName, SupportedCipherSuite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &Certificate,
        _: &[Certificate],
        _: &ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: rustls020 <port> <path> [tls12] [chacha]");
        std::process::exit(2);
    }
    let options = &args[3..];
    let chacha = options.iter().any(|o| o == "chacha");
    let suites: Vec<SupportedCipherSuite> = rustls::ALL_CIPHER_SUITES
        .iter()
        .copied()
        .filter(|s| {
            let is_chacha = matches!(
                s.suite(),
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                    | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            );
            is_chacha == chacha
        })
        .collect();
    let versions: &[&rustls::SupportedProtocolVersion] = if options.iter().any(|o| o == "tls12") {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(versions)
        .unwrap()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
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
