use clap::Parser;

mod client;
mod server;

/// Proxy that based on QUIC
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Connect to proxy
    #[arg(short, long)]
    connect: Option<String>,

    /// Bind proxy
    #[arg(short, long)]
    bind: Option<String>,
    
    /// Password
    #[arg(short, long, default_value = "nope")]
    password: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(host) = args.bind {
        todo!()
    } else if let Some(host) = args.connect {
        todo!()
    } else {
        println!("choose either --connect or --bind")
    }
}
