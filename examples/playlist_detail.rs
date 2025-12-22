use ncm_rs::{types::CryptoType, NcmClient};
use reqwest::Method;
use serde_json::json;

#[tokio::main]
async fn main() {
    let client = NcmClient::new(None, 30).expect("failed to create client");

    // Playlist Detail API
    // /weapi/v3/playlist/detail

    // Example Playlist ID: 138960283 (Some popular playlist)
    let playlist_id = "138960283";

    println!("Fetching details for playlist: {}", playlist_id);

    let params = json!({
        "id": playlist_id,
        "n": 1000,
        "s": 8 // recent subscribers count
    });

    // Usually /weapi/v3/playlist/detail uses Weapi or Linuxapi
    // Let's use Weapi
    let result = client
        .request(
            Method::POST,
            "/weapi/v3/playlist/detail",
            params,
            CryptoType::Weapi,
        )
        .await;

    match result {
        Ok(res) => {
            if let Some(playlist) = res.get("playlist") {
                let name = playlist
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("Unknown");
                let description = playlist
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                let track_count = playlist
                    .get("trackCount")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);

                println!("Playlist Name: {}", name);
                println!("Description: {}", description);
                println!("Track Count: {}", track_count);

                if let Some(tracks) = playlist.get("tracks").and_then(|t| t.as_array()) {
                    println!("First 5 tracks:");
                    for track in tracks.iter().take(5) {
                        let name = track.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                        let ar = track
                            .get("ar")
                            .and_then(|a| a.as_array())
                            .map(|artists| {
                                artists
                                    .iter()
                                    .map(|a| a.get("name").and_then(|n| n.as_str()).unwrap_or("?"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        println!("- {} by {}", name, ar);
                    }
                }
            } else {
                println!(
                    "Response (Full): {}",
                    serde_json::to_string_pretty(&res).unwrap()
                );
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
