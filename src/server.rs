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
            connection.stable_id(),
            stream.0,
            stream.1,
            password.clone()
        );
        let connection = connection.clone();
        tokio::spawn(
            async move {
                if let Err(e) = fut.await {
                    eprintln!("failed: {reason}", reason = e.to_string());
                    connection.close(0u32.into(), "bad env!!! critical error!!!!1".as_bytes());
                }
            },
        );
    }
}

async fn handle_request(
    stable_id: usize,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    password: String
) -> Result<(), Box<dyn Error>> {
    let mut head_data = [0; 1024];
    let head_len = recv.read(&mut head_data).await?.unwrap_or_default();
    let head_data = &head_data[..head_len];

    let mut body_data = vec![];

    let mut stack = 0;
    let mut status = true;
    let mut is_key = true;
    let mut key = vec![];
    let mut value = vec![];
    
    let mut remote = String::new();
    
    for n in head_data {
        stack = match (stack, n) {
            (0, b'\r') => 1,
            (1, b'\n') => {
                if key == b"Host" {
                    remote = String::from_utf8(value.clone())?;
                } else if key == b"Authentication" {
                    let passhash = String::from_utf8(value.clone())?;
                    if !bcrypt::verify(password.clone(), &format!("{stable_id}{passhash}"))? {
                        return Err("bad passhash error!!! not nice env!!".into())
                    }
                }
                
                is_key = true;
                key.clear();
                value.clear();
                2
            },
            (2, b'\r') => 3,
            (2, _) => {
                status = false;
                0
            },
            (3, b'\n') => 4,
            (4, _) => {
                body_data.push(*n);
                4
            },
            _ => 0
        };

        if stack == 0 && status == false {
            if *n == b':' {
                is_key = false;
            } else if is_key {
                key.push(*n);
            } else if *n != b' ' {
                value.push(*n);
            }
        }
    }

    todo!();

    Ok(())
}
