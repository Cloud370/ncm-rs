use ncm_rs::{types::CryptoType, NcmClient};
use reqwest::{
    cookie::{CookieStore, Jar},
    Client, Url,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // 1. Create a persistent cookie store (Arc<Jar>)
    // This allows us to access/save cookies outside the client.
    // In a real app, you might use a file-backed store like `reqwest_cookie_store`.
    let cookie_store = Arc::new(Jar::default());

    // Simulate loading a saved login cookie
    let url = "https://music.163.com".parse::<Url>().unwrap();
    cookie_store.add_cookie_str(
        "MUSIC_U=testing_persistence_value; Domain=music.163.com; Path=/",
        &url,
    );

    println!("Initial Cookies in Store: {:?}", cookie_store.cookies(&url));

    // 2. Build custom reqwest Client with the provider
    let reqwest_client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(15))
        .cookie_provider(cookie_store.clone()) // Inject the store
        .build()
        .expect("Failed to build reqwest client");

    // 3. Initialize NcmClient
    let client = NcmClient::with_client(reqwest_client);

    println!("Sending request...");

    // 4. Make a request
    let result = client
        .request(
            reqwest::Method::POST,
            "/weapi/cloudsearch/pc",
            json!({
                "s": "Hello",
                "type": 1,
                "limit": 1
            }),
            CryptoType::Auto,
            None,
        )
        .await;

    match result {
        Ok(_) => {
            println!("Request successful!");
            // 5. Verify we can still access the cookies
            // Any Set-Cookie from server would be here now.
            let cookies = cookie_store.cookies(&url);
            println!("Cookies in Store after request: {:?}", cookies);

            // Check if our initial cookie is still there (it should be)
            if let Some(val) = cookies {
                if val
                    .to_str()
                    .unwrap_or("")
                    .contains("testing_persistence_value")
                {
                    println!("Verification Passed: Cookie persistence is working.");
                } else {
                    println!("Verification Failed: Initial cookie missing.");
                }
            }
        }
        Err(e) => eprintln!("Request failed: {}", e),
    }
}
