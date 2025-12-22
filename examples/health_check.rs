use ncm_rs::{NcmClient, types::CryptoType};
use reqwest::Method;
use serde_json::json;
use std::{thread, time::Duration};

#[tokio::main]
async fn main() {
    let max_retries = 5;
    let mut success = false;

    for i in 0..max_retries {
        println!("Health Check Attempt {}/{}...", i + 1, max_retries);
        if check_api().await {
            success = true;
            break;
        }
        if i < max_retries - 1 {
            println!("Attempt {} failed. Retrying in 10 seconds...", i + 1);
            thread::sleep(Duration::from_secs(10));
        }
    }

    if success {
        println!("API is available.");
        std::process::exit(0);
    } else {
        eprintln!("API check failed after {} attempts.", max_retries);
        std::process::exit(1);
    }
}

async fn check_api() -> bool {
    // Timeout set to 15 seconds
    let client = match NcmClient::new(None, 15) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create client: {}", e);
            return false;
        }
    };

    // Simple search query
    let params = json!({
        "s": "Se Fue La Luz",
        "type": 1,
        "limit": 1,
        "offset": 0,
        "total": true 
    });

    // Use /weapi/cloudsearch/pc as it is a common endpoint
    let result = client.request(
        Method::POST,
        "/weapi/cloudsearch/pc",
        params,
        CryptoType::Auto
    ).await;

    match result {
        Ok(res) => {
            // Check for code 200
            if let Some(code) = res.get("code").and_then(|c| c.as_i64()) {
                if code == 200 {
                    // Also check if we got any result to be sure
                    if let Some(songs) = res.get("result").and_then(|r| r.get("songs")).and_then(|s| s.as_array()) {
                        if !songs.is_empty() {
                            println!("Successfully fetched search results.");
                            return true;
                        } else {
                            println!("Request 200 OK but no songs found (might be valid but suspicious for 'Fade').");
                             // Still count as success for connectivity? Yes, probably.
                             return true;
                        }
                    }
                     // If result structure is different but code is 200, it might still be OK.
                    return true;
                } else {
                    eprintln!("API returned status code: {}", code);
                }
            } else {
                eprintln!("API response missing 'code' field: {:?}", res);
            }
            false
        }
        Err(e) => {
            eprintln!("Request failed: {}", e);
            false
        }
    }
}
