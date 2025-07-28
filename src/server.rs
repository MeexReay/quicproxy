use std::{error::Error, net::SocketAddr, str, sync::Arc};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::PrivatePkcs8KeyDer;

pub async fn run_server(host: SocketAddr, password: &str) -> Result<(), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        host.ip().to_string().into(),
    ]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into();
    let certs = vec![cert.cert.into()];

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = vec![b"hq-29".into()];
    
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, host)?;

    while let Some(conn) = endpoint.accept().await {
        let fut = handle_connection(conn, password.to_string());

        tokio::spawn(async move {
            if let Err(e) = fut.await {
                eprintln!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Incoming, password: String) -> Result<(), Box<dyn Error>> {
    let connection = conn.await?;

    loop {
        let stream = connection.accept_bi().await;
        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                eprintln!("connection closed");
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(s) => s,
        };
        let fut = handle_request(
            stream.0,
            stream.1,
            password.clone()
         );
        
        tokio::spawn(
            async move {
                if let Err(e) = fut.await {
                    eprintln!("failed: {reason}", reason = e.to_string());
                }
            },
        );
    }
}

async fn handle_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    password: String
) -> Result<(), Box<dyn Error>> {
    todo!();

    Ok(())
}
