use std::net::SocketAddr;

use clap::Parser;
use client::{run_tcp_socks_server, run_udp_socks_server};
use server::run_server;

mod client;
mod server;

/// Proxy that based on QUIC
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Connect to quicproxy server ()
    #[arg(short, long)]
    connect: Option<String>,

    /// Bind proxy (socks if connect arg is here or quicproxy otherwise)
    #[arg(short, long)]
    bind: Option<String>,
    
    /// Password for connections
    #[arg(short, long, default_value = "nope")]
    password: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(host) = args.connect {
        let local: SocketAddr = args.bind.unwrap_or("0.0.0.0:1080".to_string())
            .parse().expect("error parsing local host");

        tokio::spawn({
            let host = host.clone();
            let local = local.clone();
            let password = args.password.clone();

            async move {
                run_udp_socks_server(
                    local,
                    host.parse().expect("error parsing host"),
                    &password
                ).await.expect("error running local udp server");
            }
        });
        
        run_tcp_socks_server(
            local,
            host.parse().expect("error parsing host"),
            &args.password
        ).await.expect("error running local tcp server");
    } else if let Some(host) = args.bind {
        run_server(
            host.parse().expect("error parsing host"),
            &args.password
        ).await.expect("error running server");
    } else {
        println!("choose either --connect or --bind")
    }
}
