use clap::Parser;
use ncm_rs::run_server;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Start the server
    #[arg(short, long, default_value_t = true)]
    server: bool,

    /// Port to listen on
    #[arg(short, long, default_value_t = 3331)]
    port: u16,

    /// Proxy URL (e.g. http://127.0.0.1:7890 or socks5://127.0.0.1:7890)
    #[arg(long)]
    proxy: Option<String>,

    /// Default retry count for requests
    #[arg(long, default_value_t = 3)]
    retry: u32,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 30)]
    timeout: u64,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let args = Args::parse();

    if args.server {
        run_server(args.port, args.proxy, args.retry, args.timeout).await;
    }
}
