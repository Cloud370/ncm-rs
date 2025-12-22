use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use block_padding::Pkcs7;
use cbc::Decryptor as CbcDecryptor;
use cbc::Encryptor as CbcEncryptor;
use ecb::Decryptor as EcbDecryptor;
use ecb::Encryptor as EcbEncryptor;
use num_bigint_dig::BigUint;
use rand::Rng;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::str;
use thiserror::Error;

// Constants
const IV: &[u8] = b"0102030405060708";
const PRESET_KEY: &[u8] = b"0CoJUm6Qyw8W8jud";
const LINUX_API_KEY: &[u8] = b"rFgB&h#%2?^eDg:Q";
const BASE62: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const PUBLIC_KEY_B64: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ37BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvaklV8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44oncaTWz7OBGLbCiK45wIDAQAB";
const EAPI_KEY: &[u8] = b"e82ckenh8dichen8";

type Aes128CbcEnc = CbcEncryptor<Aes128>;
type Aes128CbcDec = CbcDecryptor<Aes128>;
type Aes128EcbEnc = EcbEncryptor<Aes128>;
type Aes128EcbDec = EcbDecryptor<Aes128>;

/// Crypto errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("RSA error: {0}")]
    RsaError(String),
    #[error("Invalid data format: {0}")]
    InvalidData(String),
}

/// Helper for AES Encryption
/// Supports "cbc" and "ecb" modes.
pub fn aes_encrypt(text: &str, mode: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let plaintext = text.as_bytes();
    let len = plaintext.len();
    let mut buffer = vec![0u8; len + 16];
    buffer[..len].copy_from_slice(plaintext);

    if mode.eq_ignore_ascii_case("cbc") {
        let encryptor = Aes128CbcEnc::new(key.into(), iv.into());
        let ct_len = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, len)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?
            .len();
        Ok(buffer[..ct_len].to_vec())
    } else if mode.eq_ignore_ascii_case("ecb") {
        let encryptor = Aes128EcbEnc::new(key.into());
        let ct_len = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, len)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?
            .len();
        Ok(buffer[..ct_len].to_vec())
    } else {
        Err(CryptoError::EncryptionError("Unsupported mode".to_string()))
    }
}

/// Helper for AES Decryption
/// Supports "cbc" and "ecb" modes.
pub fn aes_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    mode: &str,
) -> Result<String, CryptoError> {
    let mut buffer = ciphertext.to_vec();

    if mode.eq_ignore_ascii_case("cbc") {
        let decryptor = Aes128CbcDec::new(key.into(), iv.into());
        let pt_len = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?
            .len();
        String::from_utf8(buffer[..pt_len].to_vec())
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
    } else {
        // ECB
        let decryptor = Aes128EcbDec::new(key.into());
        let pt_len = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?
            .len();
        String::from_utf8(buffer[..pt_len].to_vec())
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
    }
}

// RSA Encrypt (NoPadding / Raw)
fn rsa_encrypt(str: &str, pub_key_b64: &str) -> Result<String, CryptoError> {
    let der_bytes = BASE64.decode(pub_key_b64)?;
    let pub_key = RsaPublicKey::from_public_key_der(&der_bytes)
        .map_err(|e| CryptoError::RsaError(e.to_string()))?;

    let n = pub_key.n();
    let e = pub_key.e();

    let bytes = str.as_bytes();
    let m = BigUint::from_bytes_be(bytes);

    let c = m.modpow(e, n);

    let c_bytes = c.to_bytes_be();
    // Pad with leading zeros to 128 bytes (256 hex chars) if needed
    // Standard RSA 1024 output is 128 bytes.
    let mut hex_str = hex::encode(c_bytes);
    if hex_str.len() < 256 {
        hex_str = format!("{:0>256}", hex_str);
    }

    Ok(hex_str)
}

#[derive(Serialize, Debug)]
pub struct WeapiResult {
    pub params: String,
    #[serde(rename = "encSecKey")]
    pub enc_sec_key: String,
}

/// Web API Encryption (weapi)
pub fn weapi(object: &serde_json::Value) -> Result<WeapiResult, CryptoError> {
    let text = serde_json::to_string(object)?;

    let mut rng = rand::thread_rng();
    let mut secret_key = String::with_capacity(16);
    for _ in 0..16 {
        let idx = rng.gen_range(0..62);
        secret_key.push(BASE62[idx] as char);
    }

    let first_enc_bytes = aes_encrypt(&text, "cbc", PRESET_KEY, IV)?;
    let first_enc_b64 = BASE64.encode(&first_enc_bytes);

    let params_bytes = aes_encrypt(&first_enc_b64, "cbc", secret_key.as_bytes(), IV)?;
    let params = BASE64.encode(&params_bytes);

    let reversed_key: String = secret_key.chars().rev().collect();
    let enc_sec_key = rsa_encrypt(&reversed_key, PUBLIC_KEY_B64)?;

    Ok(WeapiResult {
        params,
        enc_sec_key,
    })
}

#[derive(Serialize, Debug)]
pub struct LinuxapiResult {
    pub eparams: String,
}

/// Linux API Encryption (linuxapi)
pub fn linuxapi(object: &serde_json::Value) -> Result<LinuxapiResult, CryptoError> {
    let text = serde_json::to_string(object)?;
    let enc_bytes = aes_encrypt(&text, "ecb", LINUX_API_KEY, &[])?;
    let eparams = hex::encode(enc_bytes).to_uppercase();
    Ok(LinuxapiResult { eparams })
}

#[derive(Serialize, Debug)]
pub struct EapiResult {
    pub params: String,
}

/// E-API Encryption (eapi)
pub fn eapi(url: &str, object: &serde_json::Value) -> Result<EapiResult, CryptoError> {
    let text = match object {
        serde_json::Value::String(s) => s.clone(),
        _ => serde_json::to_string(object)?,
    };

    let message = format!("nobody{}use{}md5forencrypt", url, text);
    let digest = format!("{:x}", md5::compute(message));

    let data = format!("{}-36cd479b6b5-{}-36cd479b6b5-{}", url, text, digest);

    let enc_bytes = aes_encrypt(&data, "ecb", EAPI_KEY, &[])?;
    let params = hex::encode(enc_bytes).to_uppercase();

    Ok(EapiResult { params })
}

/// Decrypt raw E-API ciphertext
pub fn decrypt(cipher: &str) -> Result<String, CryptoError> {
    let cipher_bytes = hex::decode(cipher)?;
    aes_decrypt(&cipher_bytes, EAPI_KEY, &[], "ecb")
}

/// Decrypt E-API response
pub fn eapi_res_decrypt(encrypted_params: &str) -> Result<serde_json::Value, CryptoError> {
    let cipher_bytes = hex::decode(encrypted_params)?;
    let decrypted = aes_decrypt(&cipher_bytes, EAPI_KEY, &[], "ecb")?;
    serde_json::from_str(&decrypted).map_err(CryptoError::JsonError)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EapiReqResult {
    pub url: String,
    pub data: serde_json::Value,
}

/// Decrypt E-API request
pub fn eapi_req_decrypt(encrypted_params: &str) -> Result<EapiReqResult, CryptoError> {
    let cipher_bytes = hex::decode(encrypted_params)?;
    let decrypted = aes_decrypt(&cipher_bytes, EAPI_KEY, &[], "ecb")?;

    // Split by -36cd479b6b5-
    // The structure is url-36cd479b6b5-data-36cd479b6b5-digest
    let parts: Vec<&str> = decrypted.split("-36cd479b6b5-").collect();
    if parts.len() >= 2 {
        let url = parts[0].to_string();
        let data_str = parts[1];
        let data: serde_json::Value =
            serde_json::from_str(data_str).unwrap_or(serde_json::Value::Null);
        Ok(EapiReqResult { url, data })
    } else {
        Err(CryptoError::InvalidData(
            "Invalid decrypted data format".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_weapi() {
        let object = json!({
            "username": "test",
            "password": "password"
        });
        let res = weapi(&object);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(!res.params.is_empty());
        assert!(!res.enc_sec_key.is_empty());
    }

    #[test]
    fn test_linuxapi() {
        let object = json!({
            "username": "test",
            "password": "password"
        });
        let res = linuxapi(&object);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(!res.eparams.is_empty());
    }

    #[test]
    fn test_eapi() {
        let object = json!({
            "username": "test",
            "password": "password"
        });
        let url = "/api/test";
        let res = eapi(url, &object);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(!res.params.is_empty());
    }

    #[test]
    fn test_aes_ecb_roundtrip() {
        let text = "hello world";
        let key = b"e82ckenh8dichen8";
        let iv = &[]; // ECB

        // Encrypt
        let enc = aes_encrypt(text, "ecb", key, iv).unwrap();

        // Decrypt
        let dec = aes_decrypt(&enc, key, iv, "ecb").unwrap();
        assert_eq!(text, dec);
    }
}
