use ncm_rs::{NcmClient, types::CryptoType};
use reqwest::Method;
use serde_json::json;

#[tokio::main]
async fn main() {
    // initialize client (optionally with proxy)
    let client = NcmClient::new(None, 30).expect("failed to create client");
    
    // Cloud Search API
    // Source: .temp\api-enhanced\module\cloudsearch.js
    // URL: /api/cloudsearch/pc
    // Method: POST
    // Crypto: Weapi (Standard for PC APIs)
    
    let keywords = "Se Fue La Luz"; // Example keyword
    
    let params = json!({
        "s": keywords,
        "type": 1,
        "limit": 30,
        "offset": 0,
        "total": true 
    });

    println!("Searching for: {}", keywords);

    let result = client.request(
        Method::POST,
        "/weapi/cloudsearch/pc",
        params,
        CryptoType::Auto
    ).await;

    match result {
        Ok(res) => {
            // Try to parse and show some songs to verify it worked
            if let Some(songs) = res.get("result").and_then(|r| r.get("songs")).and_then(|s| s.as_array()) {
                println!("Found {} songs:", songs.len());
                for song in songs.iter().take(5) {
                    let name = song.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                    let ar = song.get("ar").and_then(|v| v.as_array())
                        .map(|artists| artists.iter().map(|a| a.get("name").and_then(|n| n.as_str()).unwrap_or("?")).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default();
                    println!("- {} by {}", name, ar);
                }
            } else {
                println!("Response (Full): {}", serde_json::to_string_pretty(&res).unwrap());
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
