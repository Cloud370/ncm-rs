use ncm_rs::{NcmClient, types::CryptoType};
use reqwest::Method;
use serde_json::json;

#[tokio::main]
async fn main() {
    let client = NcmClient::new(None, 30).expect("failed to create client");

    // Song URL API
    // /eapi/song/enhance/player/url
    // /eapi/song/enhance/player/url/v1
    
    // Song ID for "海阔天空" (Beyond): 347230
    let song_ids = vec![347230];
    let level = "standard"; // standard, higher, exhigh, lossless, hires

    println!("Fetching URL for songs: {:?} (Level: {})", song_ids, level);

    let params = json!({
        "ids": format!("[{}]", song_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(",")),
        "level": level,
        "encodeType": "aac",
    });

    // Use /eapi/song/enhance/player/url/v1 which is commonly used in mobile app
    let result = client.request(
        Method::POST,
        "/eapi/song/enhance/player/url/v1",
        params,
        CryptoType::Eapi
    ).await;

    match result {
        Ok(res) => {
            if let Some(data) = res.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    let id = item.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                    let url = item.get("url").and_then(|u| u.as_str()).unwrap_or("No URL");
                    let br = item.get("br").and_then(|v| v.as_i64()).unwrap_or(0);
                    let size = item.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
                    
                    println!("Song ID: {}", id);
                    println!("URL: {}", url);
                    println!("Bitrate: {}", br);
                    println!("Size: {}", size);
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
