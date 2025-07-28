use std::{error::Error, net::SocketAddr, sync::Arc};
use bcrypt::DEFAULT_COST;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, crypto::rustls::QuicClientConfig};
use rustls::{
    DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

#[derive(Debug)]
pub struct NoCertVerify;

impl ServerCertVerifier for NoCertVerify {
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
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

async fn open_connection(
    host: SocketAddr,
) -> Result<(Endpoint, Connection), Box<dyn Error>> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();

    let verifier = Arc::new(NoCertVerify);
    client_crypto.dangerous().set_certificate_verifier(verifier);
    client_crypto.alpn_protocols = vec![b"hq-29".into()];

    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(Arc::new(client_crypto))?));
    let mut endpoint = quinn::Endpoint::client(host)?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(host, &host.ip().to_string())?
        .await?;

    Ok((endpoint, conn))
}

async fn open_request(
    conn: &mut Connection,
    remote: SocketAddr,
    password: &str
) -> Result<(SendStream, RecvStream), Box<dyn Error>> {
    let (mut send, recv) = conn
        .open_bi()
        .await?;

    let request = format!(
        "GET /index.html\r\nHost: {}\r\nAuthentication: {}\r\n\r\n",
        remote,
        bcrypt::hash(format!("{}{password}", conn.stable_id()), DEFAULT_COST)?
    );
    send.write_all(request.as_bytes()).await?;

    Ok((send, recv))
}

async fn close_request(
    mut send: SendStream,
    mut recv: RecvStream
) -> Result<(), Box<dyn Error>> {
    send.finish()?;
    recv.stop(0u32.into())?;
    Ok(())
}

async fn close_connection(
    endpoint: Endpoint,
    conn: Connection,
) -> Result<(), Box<dyn Error>> {
    conn.close(0u32.into(), b"good environment");
    endpoint.wait_idle().await;
    Ok(())
}
