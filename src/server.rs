use crate::client::NcmClient;
use crate::types::CryptoType;
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, Uri},
    routing::{get, post},
    Json, Router,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub client: NcmClient,
    pub default_retry: u32,
    pub default_timeout: u64,
}

#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    pub url: String,
    pub method: Option<String>,
    pub params: Option<Value>,
    pub crypto: Option<String>,
    pub retry: Option<u32>,
    pub timeout: Option<u64>,
    pub cookie: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub fn create_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/proxy", post(handle_proxy))
        .route(
            "/",
            get(|| async { "Netease Cloud Music API Rust Proxy is running!" }),
        )
        .fallback(handle_wildcard)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn run_server(port: u16, proxy: Option<String>, retry: u32, timeout: u64) {
    // Disable cookie store for server mode to ensure statelessness
    let client = match NcmClient::new(proxy.as_deref(), timeout, false) {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to create client: {}", e);
            return;
        }
    };
    let state = Arc::new(AppState {
        client,
        default_retry: retry,
        default_timeout: timeout,
    });

    let app = create_app(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_wildcard(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(query_params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let start_time = Instant::now();

    // 1. Extract config and clean params
    let mut config = HashMap::new();
    let mut params_map = serde_json::Map::new();

    // Headers config
    if let Some(v) = headers.get("X-NCM-Crypto").and_then(|v| v.to_str().ok()) {
        config.insert("crypto".to_string(), v.to_string());
    }
    if let Some(v) = headers
        .get("X-NCM-Target-Url")
        .and_then(|v| v.to_str().ok())
    {
        config.insert("target_url".to_string(), v.to_string());
    }
    if let Some(v) = headers
        .get("X-NCM-Network-Proxy")
        .and_then(|v| v.to_str().ok())
    {
        config.insert("proxy".to_string(), v.to_string());
    }
    if let Some(v) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        config.insert("real_ip".to_string(), v.to_string());
    }
    if let Some(v) = headers.get("X-NCM-Retry").and_then(|v| v.to_str().ok()) {
        config.insert("retry".to_string(), v.to_string());
    }
    if let Some(v) = headers.get("X-NCM-Timeout").and_then(|v| v.to_str().ok()) {
        config.insert("timeout".to_string(), v.to_string());
    }
    if let Some(v) = headers.get("Cookie").and_then(|v| v.to_str().ok()) {
        config.insert("cookie".to_string(), v.to_string());
    }
    if let Some(v) = headers.get("X-NCM-Cookie").and_then(|v| v.to_str().ok()) {
        config.insert("cookie".to_string(), v.to_string());
    }

    // Query params processing
    for (k, v) in query_params {
        if k == "crypto"
            || k == "proxy"
            || k == "real_ip"
            || k == "retry"
            || k == "timeout"
            || k == "cookie"
        {
            config.insert(k, v);
        } else {
            params_map.insert(k, Value::String(v));
        }
    }

    // Body processing
    if !body.is_empty() {
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("application/json") {
            if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&body) {
                for (k, v) in map {
                    if k == "crypto"
                        || k == "proxy"
                        || k == "real_ip"
                        || k == "target_url"
                        || k == "retry"
                        || k == "timeout"
                        || k == "cookie"
                    {
                        if let Value::String(s) = v {
                            config.insert(k, s);
                        } else if let Value::Number(n) = v {
                            config.insert(k, n.to_string());
                        }
                    } else {
                        params_map.insert(k, v);
                    }
                }
            }
        } else if content_type.contains("application/x-www-form-urlencoded") {
            if let Ok(form_body) = serde_urlencoded::from_bytes::<HashMap<String, String>>(&body) {
                for (k, v) in form_body {
                    if k == "crypto"
                        || k == "proxy"
                        || k == "real_ip"
                        || k == "target_url"
                        || k == "retry"
                        || k == "timeout"
                        || k == "cookie"
                    {
                        config.insert(k, v);
                    } else {
                        params_map.insert(k, Value::String(v));
                    }
                }
            }
        }
    }

    // 2. Determine CryptoType
    let crypto_type = match config.get("crypto").map(|s| s.as_str()).unwrap_or("auto") {
        "weapi" => CryptoType::Weapi,
        "linuxapi" => CryptoType::Linuxapi,
        "eapi" => CryptoType::Eapi,
        "none" => CryptoType::None,
        "auto" => CryptoType::Auto,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid crypto type".to_string(),
                }),
            ))
        }
    };

    // 3. Prepare Client (handle proxy)
    let req_timeout = config
        .get("timeout")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(state.default_timeout);

    let client = if let Some(proxy_url) = config.get("proxy") {
        match NcmClient::new(Some(proxy_url), req_timeout, false) {
            Ok(c) => c,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Invalid proxy: {}", e),
                    }),
                ))
            }
        }
    } else if req_timeout != state.default_timeout {
        match NcmClient::new(None, req_timeout, false) {
            Ok(c) => c,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to create client with timeout: {}", e),
                    }),
                ))
            }
        }
    } else {
        state.client.clone()
    };

    // 4. Determine Request URL (handle target_url override)
    let request_path = if let Some(target) = config.get("target_url") {
        let path = uri.path();
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else {
            let target = target.trim_end_matches('/');
            let path = path.trim_start_matches('/');
            format!("{}/{}", target, path)
        }
    } else {
        uri.path().to_string()
    };

    // Retry configuration
    let retry_count = config
        .get("retry")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(state.default_retry);

    // 5. Forward Request with Retry
    let mut current_retry = 0;
    loop {
        match client
            .request(
                method.clone(),
                &request_path,
                Value::Object(params_map.clone()),
                crypto_type,
                config.get("cookie").map(|s| s.as_str()),
            )
            .await
        {
            Ok(res) => {
                let duration = start_time.elapsed();
                let params_summary = serde_json::to_string(&params_map).unwrap_or_default();
                let params_log = if params_summary.len() > 100 {
                    format!("{}...", &params_summary[..100])
                } else {
                    params_summary
                };

                info!(
                    "[{}] {} {}ms - Params: {}",
                    method,
                    uri,
                    duration.as_millis(),
                    params_log
                );
                return Ok(Json(res));
            }
            Err(e) => {
                if current_retry < retry_count {
                    current_retry += 1;
                    warn!(
                        "Request failed, retrying ({}/{}): {}",
                        current_retry, retry_count, e
                    );
                    continue;
                }

                let duration = start_time.elapsed();
                error!(
                    "[{}] {} Failed {}ms - Error: {}",
                    method,
                    uri,
                    duration.as_millis(),
                    e
                );

                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                ));
            }
        }
    }
}

async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ProxyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ErrorResponse>)> {
    let start_time = Instant::now();
    let method = match payload
        .method
        .as_deref()
        .unwrap_or("POST")
        .to_uppercase()
        .as_str()
    {
        "GET" => Method::GET,
        "POST" => Method::POST,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid method".to_string(),
                }),
            ))
        }
    };

    let params = payload.params.clone().unwrap_or(serde_json::json!({}));

    let crypto_type = match payload.crypto.as_deref().unwrap_or("auto") {
        "weapi" => CryptoType::Weapi,
        "linuxapi" => CryptoType::Linuxapi,
        "eapi" => CryptoType::Eapi,
        "none" => CryptoType::None,
        "auto" => CryptoType::Auto,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid crypto type. Options: weapi, linuxapi, eapi, none, auto"
                        .to_string(),
                }),
            ))
        }
    };

    let retry_count = payload.retry.unwrap_or(state.default_retry);
    let req_timeout = payload.timeout.unwrap_or(state.default_timeout);

    let client = if req_timeout != state.default_timeout {
        match NcmClient::new(None, req_timeout, false) {
            Ok(c) => c,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to create client with timeout: {}", e),
                    }),
                ))
            }
        }
    } else {
        state.client.clone()
    };

    let mut current_retry = 0;

    loop {
        match client
            .request(
                method.clone(),
                &payload.url,
                params.clone(),
                crypto_type,
                payload.cookie.as_deref(),
            )
            .await
        {
            Ok(res) => {
                let duration = start_time.elapsed();
                let params_summary = serde_json::to_string(&params).unwrap_or_default();
                let params_log = if params_summary.len() > 100 {
                    format!("{}...", &params_summary[..100])
                } else {
                    params_summary
                };
                info!(
                    "[PROXY] [{}] {} {}ms - Params: {}",
                    method,
                    payload.url,
                    duration.as_millis(),
                    params_log
                );
                return Ok(Json(res));
            }
            Err(e) => {
                if current_retry < retry_count {
                    current_retry += 1;
                    warn!(
                        "Request failed, retrying ({}/{}): {}",
                        current_retry, retry_count, e
                    );
                    continue;
                }
                let duration = start_time.elapsed();
                error!(
                    "[PROXY] [{}] {} Failed {}ms - Error: {}",
                    method,
                    payload.url,
                    duration.as_millis(),
                    e
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                ));
            }
        }
    }
}
