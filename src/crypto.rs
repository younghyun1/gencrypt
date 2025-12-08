use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use base64::Engine;
use base64::engine::general_purpose;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::io::Cursor;
use zstd::stream::{decode_all, encode_all};

fn derive_keys(password: &str, salt: &[u8]) -> (u8, u8, u8, [u8; 32]) {
    let mut derived = [0u8; 35];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 600_000, &mut derived)
        .expect("HMAC should not fail");

    let key = derived[0];
    let mix_init = derived[1];
    let mix_multiplier = derived[2];
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&derived[3..35]);

    (key, mix_init, mix_multiplier, aes_key)
}

pub fn encode_custom(input: &str, password: &str) -> String {
    encode_custom_bytes(input.as_bytes(), password)
}

/// Binary-safe encoding for any byte content:
pub fn encode_custom_bytes(input: &[u8], password: &str) -> String {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    let (key, mix_init, mix_multiplier, aes_key) = derive_keys(password, &salt);

    let mut mix = mix_init;
    let masked: Vec<u8> = input
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let byte = b ^ key ^ mix.wrapping_add(i as u8);
            mix = mix.wrapping_mul(mix_multiplier).wrapping_add(byte);
            byte
        })
        .collect();

    // Compress with zstd level 3
    let compressed = encode_all(Cursor::new(&masked), 3).expect("zstd compress failed");

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, compressed.as_slice())
        .expect("aes-gcm encryption failed");

    // Prepend salt + nonce to ciphertext
    let mut output = salt.to_vec();
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    general_purpose::URL_SAFE_NO_PAD.encode(&output)
}

pub fn decode_custom(input: &str, password: &str) -> Result<String, String> {
    decode_custom_bytes(input, password).and_then(|v| {
        String::from_utf8(v).map_err(|e| format!("Failed to decode UTF-8 output: {e}"))
    })
}

/// Binary-safe decoding for any byte content:
pub fn decode_custom_bytes(input: &str, password: &str) -> Result<Vec<u8>, String> {
    let sanitized = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(&sanitized)
        .map_err(|e| format!("Base64 decode error: {e}"))?;

    if decoded.len() < 28 {
        // 16 salt + 12 nonce
        return Err("Ciphertext too short (needs salt + nonce)".to_string());
    }
    let (salt, rest) = decoded.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let (key, mix_init, mix_multiplier, aes_key) = derive_keys(password, salt);

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let decompressed = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decrypt error: {e}"))?;

    // Decompress with zstd
    let decompressed = decode_all(Cursor::new(&decompressed))
        .map_err(|e| format!("Zstd decompress error: {e}"))?;

    let mut mix = mix_init;
    let decrypted: Vec<u8> = decompressed
        .iter()
        .enumerate()
        .map(|(i, &enc)| {
            let orig = enc ^ key ^ mix.wrapping_add(i as u8);
            mix = mix.wrapping_mul(mix_multiplier).wrapping_add(enc);
            orig
        })
        .collect();

    Ok(decrypted)
}
