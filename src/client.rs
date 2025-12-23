use crate::error::NcmError;
use crate::types::CryptoType;
use crate::utils::crypto;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, COOKIE, REFERER, USER_AGENT};
use reqwest::{Client, Method, Proxy, Url};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::info;

const BASE_URL: &str = "https://music.163.com";
const API_URL: &str = "https://interface.music.163.com";
const USER_AGENT_PC: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const USER_AGENT_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36";

#[derive(Clone)]
pub struct NcmClient {
    client: Client,
    base_url: Url,
    api_url: Url,
}

impl NcmClient {
    pub fn new(proxy: Option<&str>, timeout: u64, cookie_store: bool) -> Result<Self, NcmError> {
        let mut builder = Client::builder()
            .cookie_store(cookie_store)
            .gzip(true)
            .timeout(Duration::from_secs(timeout));

        if let Some(proxy_url) = proxy {
            let proxy_obj = Proxy::all(proxy_url).map_err(NcmError::Http)?;
            builder = builder.proxy(proxy_obj);
        }

        let client = builder.build().map_err(NcmError::Http)?;

        Ok(Self {
            client,
            base_url: Url::parse(BASE_URL).unwrap(),
            api_url: Url::parse(API_URL).unwrap(),
        })
    }

    /// Construct a new NcmClient with a custom reqwest::Client.
    /// This allows advanced configuration like persistent cookie stores, custom proxies, etc.
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            base_url: Url::parse(BASE_URL).unwrap(),
            api_url: Url::parse(API_URL).unwrap(),
        }
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        params: Value,
        crypto_type: CryptoType,
        cookies: Option<&str>,
    ) -> Result<Value, NcmError> {
        let mut params_to_encrypt = params.clone();

        let real_crypto_type = match crypto_type {
            CryptoType::Auto => {
                // 1. Check if crypto is specified in params
                let mut detected_crypto = None;
                if let Value::Object(ref mut map) = params_to_encrypt {
                    if let Some(c) = map
                        .remove("crypto")
                        .and_then(|v| v.as_str().map(|s| s.to_string()))
                    {
                        detected_crypto = match c.to_lowercase().as_str() {
                            "weapi" => Some(CryptoType::Weapi),
                            "linuxapi" => Some(CryptoType::Linuxapi),
                            "eapi" => Some(CryptoType::Eapi),
                            "none" => Some(CryptoType::None),
                            _ => None,
                        };
                    }
                }

                if let Some(c) = detected_crypto {
                    c
                } else {
                    // 2. Fallback to path-based detection
                    if path.starts_with("http://") || path.starts_with("https://") {
                        if path.contains("/eapi/") {
                            CryptoType::Eapi
                        } else if path.contains("/weapi/") {
                            CryptoType::Weapi
                        } else if path.contains("/api/linux/") {
                            CryptoType::Linuxapi
                        } else {
                            CryptoType::None
                        }
                    } else if path.starts_with("/eapi/") {
                        CryptoType::Eapi
                    } else if path.starts_with("/weapi/") {
                        CryptoType::Weapi
                    } else if path.starts_with("/api/linux/") {
                        CryptoType::Linuxapi
                    } else {
                        // Default to Weapi for /api/ and others if not specified,
                        // similar to typical Node.js behavior which assumes PC/Weapi by default.
                        CryptoType::Weapi
                    }
                }
            }
            _ => crypto_type,
        };

        let (request_url, params_to_encrypt) = if real_crypto_type == CryptoType::Eapi {
            // Eapi logic: Use interface domain, but respect user path
            let url = if path.starts_with("http://") || path.starts_with("https://") {
                Url::parse(path).map_err(|e| NcmError::Unknown(e.to_string()))?
            } else {
                self.api_url
                    .join(path.trim_start_matches('/'))
                    .map_err(|e| NcmError::Unknown(e.to_string()))?
            };

            // Inject header
            let mut new_params = params_to_encrypt.clone();
            if let Value::Object(ref mut map) = new_params {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                let mut rng = rand::thread_rng();
                let random_num = rng.gen_range(0..1000);
                let request_id = format!("{}_{:04}", now, random_num);

                let header = json!({
                    "osver": "Microsoft-Windows-10-Professional-build-19045-64bit",
                    "deviceId": "unknown", // Should ideally be random or persistent
                    "appver": "3.1.17.204416",
                    "versioncode": "140",
                    "mobilename": "unknown",
                    "buildver": "unknown",
                    "resolution": "1920x1080",
                    "__csrf": "",
                    "os": "pc",
                    "channel": "netease",
                    "requestId": request_id
                });
                map.insert("header".to_string(), header);
            }
            (url, new_params)
        } else {
            let url = self
                .base_url
                .join(path)
                .map_err(|e| NcmError::Unknown(e.to_string()))?;
            (url, params_to_encrypt)
        };

        let mut headers = HeaderMap::new();
        let user_agent = match real_crypto_type {
            CryptoType::Linuxapi => USER_AGENT_LINUX,
            _ => USER_AGENT_PC,
        };
        headers.insert(USER_AGENT, HeaderValue::from_static(user_agent));

        if let Some(cookie_str) = cookies {
            if let Ok(val) = HeaderValue::from_str(cookie_str) {
                headers.insert(COOKIE, val);
            }
        }

        if matches!(method, Method::POST) {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
        }

        if path.contains("music.163.com") {
            headers.insert(REFERER, HeaderValue::from_static("https://music.163.com"));
        }

        let mut request_builder = self
            .client
            .request(method.clone(), request_url.clone())
            .headers(headers);

        // Handle Encryption
        let body_params = match real_crypto_type {
            CryptoType::Weapi => {
                let weapi_res = crypto::weapi(&params_to_encrypt)?;
                let mut map = HashMap::new();
                map.insert("params", weapi_res.params);
                map.insert("encSecKey", weapi_res.enc_sec_key);
                Some(map)
            }
            CryptoType::Linuxapi => {
                let linux_res = crypto::linuxapi(&params_to_encrypt)?;
                let mut map = HashMap::new();
                map.insert("eparams", linux_res.eparams);
                Some(map)
            }
            CryptoType::Eapi => {
                // Eapi uses the ORIGINAL path for hashing (e.g. /api/cloudsearch/pc)
                // However, if the user provided /eapi/ path, we might need to sign it as /api/
                // because Netease server often maps /eapi/ back to /api/ internally for signature verification.
                // This is a protocol quirk, not just "rewriting".
                let mut sign_path = path.replace("/eapi/", "/api/");
                if sign_path.starts_with("http://") || sign_path.starts_with("https://") {
                    if let Ok(u) = Url::parse(&sign_path) {
                        sign_path = u.path().to_string();
                    }
                }
                let eapi_res = crypto::eapi(&sign_path, &params_to_encrypt)?;
                let mut map = HashMap::new();
                map.insert("params", eapi_res.params);
                Some(map)
            }
            CryptoType::None => None,
            CryptoType::Auto => unreachable!(), // Handled at the beginning
        };

        if let Some(body) = body_params {
            request_builder = request_builder.form(&body);
        } else if matches!(method, Method::POST) {
            // If POST but no crypto, maybe just send JSON or form?
            // Usually Netease APIs are encrypted if POST.
            // For safety, if not encrypted, send as form if params exist
            if !params_to_encrypt.is_null() {
                request_builder = request_builder.form(&params_to_encrypt);
            }
        } else {
            // GET request params
            if !params_to_encrypt.is_null() {
                request_builder = request_builder.query(&params_to_encrypt);
            }
        }

        let params_str = params_to_encrypt.to_string();
        let params_log = if params_str.len() > 512 {
            format!("{}...", &params_str[..512])
        } else {
            params_str
        };
        info!(
            "[NCM] [{:?}] {} {} - Params: {}",
            real_crypto_type, method, request_url, params_log
        );

        let response = request_builder.send().await?;
        let status = response.status();

        // Return raw JSON value, don't check code field here to be "proxy-like"
        // But do check HTTP status
        if !status.is_success() {
            // Try to read body for error message
            let text = response.text().await.unwrap_or_default();
            return Err(NcmError::Api {
                code: status.as_u16() as i32,
                msg: format!("HTTP Error: {} - Body: {}", status, text),
            });
        }

        let text = response.text().await?;

        // Parse as Value
        if real_crypto_type == CryptoType::Eapi {
            // EAPI response might be encrypted, but sometimes it returns plain JSON on error or if not configured to encrypt response.
            // However, typically EAPI returns encrypted binary data which needs decryption.
            // But reqwest text() will try to decode it as utf-8.
            // Let's try to parse as JSON first. If it fails, maybe it's encrypted hex/base64 string?
            // Actually, real EAPI returns a byte stream that is encrypted.
            // For now, let's assume the user is getting a plain JSON error or unencrypted response if it works.
            // If the user gets "EOF while parsing a value", it means the response body is empty or invalid JSON.
            // Wait, if it is EAPI, the response body IS encrypted.
            // We need to decrypt it if it's not a standard JSON error.

            if let Ok(res) = serde_json::from_str::<Value>(&text) {
                return Ok(res);
            }

            // Try to decrypt
            // EAPI responses are often hex encoded strings in the body, OR raw bytes.
            // If text() succeeded, it might be hex.
            if let Ok(decrypted_val) = crypto::eapi_res_decrypt(&text) {
                return Ok(decrypted_val);
            }
        }

        let res: Value = serde_json::from_str(&text)?;
        Ok(res)
    }
}

impl Default for NcmClient {
    fn default() -> Self {
        // Default to enabling cookie store for library usage convenience
        Self::new(None, 30, true).expect("Failed to create default client")
    }
}
