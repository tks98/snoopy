// HTTP/3 server and client over quinn for the integration tests:
//   quinnh3 server <port>
// serves "served <path> on <port>" for any request on 127.0.0.1:<port>, with
// a self-signed certificate, and prints "listening" once it is ready;
//   quinnh3 client <port>[,<port>...] <path>
// sends a GET for <path> to each, at once over one socket, accepting any
// certificate, and prints each response's status and body. Both use rustls's aws-lc-rs provider, or ring if built with
// the ring feature.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
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

fn provider() -> Arc<CryptoProvider> {
    #[cfg(feature = "ring")]
    return Arc::new(rustls::crypto::ring::default_provider());
    #[cfg(not(feature = "ring"))]
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
}

async fn server(port: u16) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    println!("listening");
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else {
                return;
            };
            while let Ok(Some(resolver)) = h3.accept().await {
                let Ok((req, mut stream)) = resolver.resolve_request().await else { break };
                let body = format!("served {} on {port}", req.uri().path());
                let response = http::Response::builder().status(200).body(()).unwrap();
                if stream.send_response(response).await.is_ok() && stream.send_data(Bytes::from(body)).await.is_ok() {
                    let _ = stream.finish().await;
                }
            }
        });
    }
}

async fn client(ports: Vec<u16>, path: &str) {
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let requests = ports.into_iter().map(|port| {
        let endpoint = endpoint.clone();
        let path = path.to_string();
        tokio::spawn(async move { get(&endpoint, port, &path).await })
    });
    for request in requests.collect::<Vec<_>>() {
        println!("{}", request.await.unwrap());
    }
    endpoint.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
}

async fn get(endpoint: &quinn::Endpoint, port: u16, path: &str) -> String {
    let conn = endpoint
        .connect(SocketAddr::from(([127, 0, 0, 1], port)), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = http::Request::get(format!("https://localhost:{port}{path}")).body(()).unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let part = chunk.chunk();
            body.extend_from_slice(part);
            let n = part.len();
            chunk.advance(n);
        }
    }
    drop(send_request);
    drive.abort();
    format!("{} {}", response.status(), String::from_utf8_lossy(&body))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.len()) {
        (Some("server"), 3) => server(args[2].parse().unwrap()).await,
        (Some("client"), 4) => client(args[2].split(',').map(|p| p.parse().unwrap()).collect(), &args[3]).await,
        _ => {
            eprintln!("usage: quinnh3 server <port> | quinnh3 client <port>[,<port>...] <path>");
            std::process::exit(2);
        }
    }
}
