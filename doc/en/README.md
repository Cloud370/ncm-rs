# ncm-rs

English | [简体中文](../../README.md)

[![API Status](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cloud370/ncm-rs/status/api-status.json&style=flat-square&cacheSeconds=600)](https://github.com/cloud370/ncm-rs/blob/status/doc/en/API_STATUS.md)
[View API Daily Availability Report](https://github.com/cloud370/ncm-rs/blob/status/doc/en/API_STATUS.md)

A high-performance, cross-platform Netease Cloud Music API implementation written in Rust. 

It acts as a lightweight, efficient alternative to the Node.js version, capable of running as a standalone HTTP Proxy Server or being integrated as a Rust Library.

## Features

- **High Performance**: Lightweight and fast, built on Axum and Tokio.
- **Full Encryption**: Native implementation of `weapi`, `eapi`, and `linuxapi`.
- **Dual Mode**: Use as a standalone HTTP proxy or a Rust library.
- **Smart Proxying**: Automatic encryption detection and upstream proxy support.

## Usage as a Proxy Server

Start the server to expose a generic proxy endpoint. This endpoint accepts requests, handles the complex encryption internally, and forwards them to Netease servers.

### Installation & Run

```bash
# Clone the repository
git clone https://github.com/cloud370/ncm-rs.git
cd ncm-rs

# Run the server (default port: 3331)
cargo run

# Or specify a custom port
cargo run -- --port 8080

# Or specify a global proxy (HTTP/SOCKS5)
cargo run -- --proxy http://127.0.0.1:7890
```

### Direct URL Passthrough (Recommended)

This is the easiest way to use the proxy. You can request any Netease Cloud Music API path directly. The server automatically detects the necessary encryption based on the path.

**Example:**
```bash
# Automatically uses EAPI encryption for /eapi/ paths
curl "http://localhost:3331/eapi/cloudsearch/pc?s=Fade&type=1"

# Automatically uses WEAPI encryption for /weapi/ paths
curl "http://localhost:3331/weapi/search/get?s=Fade&type=1"
```

You can also configure request behavior using **HTTP Headers** or **Query Parameters**:

| Header | Query Param | Description |
|--------|-------------|-------------|
| `X-NCM-Crypto` | `crypto` | Force encryption type (`weapi`, `eapi`, `linuxapi`, `none`) |
| `X-NCM-Network-Proxy` | `proxy` | Use a specific upstream network proxy (HTTP/SOCKS5) |
| `X-NCM-Retry` | `retry` | Number of retries on failure |
| `X-NCM-Timeout` | `timeout` | Request timeout in seconds |

### Structured Proxy Endpoint

**POST** `http://localhost:3331/proxy`

If you prefer a structured JSON interface:

```bash
curl -X POST http://localhost:3331/proxy \
  -H "Content-Type: application/json" \
  -d '{
    "url": "/weapi/search/get",
    "params": {
        "s": "Fade",
        "type": 1,
        "limit": 3
    }
}'
```

## Usage as a Rust Library

You can integrate `ncm-rs` directly into your Rust application. For more advanced usage, check the [examples](../../examples) directory.

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ncm-rs = { git = "https://github.com/cloud370/ncm-rs.git" }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }
```

### Example

```rust
use ncm_rs::{NcmClient, types::CryptoType};
use reqwest::Method;
use serde_json::json;

#[tokio::main]
async fn main() {
    // Initialize client (optional proxy, timeout in seconds)
    let client = NcmClient::new(None, 30).unwrap();
    
    // Make a search request using Weapi
    let res = client.request(
        Method::POST,
        "/weapi/search/get",
        json!({
            "s": "Se Fue La Luz",
            "type": 1,
            "limit": 5
        }),
        CryptoType::Weapi
    ).await;

    match res {
        Ok(data) => println!("Response: {}", data),
        Err(e) => eprintln!("Error: {}", e),
    }
}
```

### More Examples

Detailed examples can be found in the [examples](../../examples) directory:
- [Cloud Search](../../examples/cloud_search.rs): Search for songs, artists, etc.
- [Playlist Details](../../examples/playlist_detail.rs): Get full details of a playlist.
- [Song URL](../../examples/song_url.rs): Get download/playback URLs for songs.

## Project Structure

- `src/client.rs`: Core HTTP Client with cookie and proxy management.
- `src/server.rs`: Axum-based HTTP server implementation.
- `src/utils/crypto.rs`: Encryption logic (AES, RSA, MD5).
- `src/lib.rs`: Library entry point.
- `src/main.rs`: CLI entry point.

## License

This project is licensed under the [MIT License](../../LICENSE).

## Disclaimer

This project is for **educational and research purposes only**. The API interface and data belong to NetEase Cloud Music. Please do not use this project for any illegal or commercial activities.
