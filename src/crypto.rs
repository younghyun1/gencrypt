use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, SecretKey as KemSecretKey, SharedSecret as KemSharedSecret,
};
use rand::RngCore;
use std::io::Cursor;
use zstd::stream::{decode_all, encode_all};

fn derive_keys(password: &str, salt: &[u8]) -> (u8, u8, u8, [u8; 32]) {
    let mut derived = [0u8; 35];

    // Use default Argon2id parameters (m=19MiB, t=2, p=1)
    let argon2 = Argon2::default();

    // Derive keys directly into the buffer
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived)
        .expect("Argon2 key derivation failed");

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

    // ML-KEM-768 adds a post-quantum secret that we fold into masking and encryption.
    let (pk, sk) = mlkem1024::keypair();
    let (ss, kem_ct) = mlkem1024::encapsulate(&pk);
    let ss_bytes = ss.as_bytes();

    let pq_mask = ss_bytes[0];
    let pq_mix_init = ss_bytes[1];
    let pq_mix_multiplier = ss_bytes[2] | 1;

    let mut mix = mix_init ^ pq_mix_init;
    let mix_multiplier = mix_multiplier ^ pq_mix_multiplier;
    let masked: Vec<u8> = input
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let byte = b ^ key ^ pq_mask ^ mix.wrapping_add(i as u8);
            mix = mix.wrapping_mul(mix_multiplier).wrapping_add(byte);
            byte
        })
        .collect();

    // Compress with zstd level 3
    let compressed = encode_all(Cursor::new(&masked), 3).expect("zstd compress failed");

    // Encrypt with AES-256-GCM using a key blended with the PQ shared secret.
    let mut data_key = aes_key;
    for (i, b) in data_key.iter_mut().enumerate() {
        *b ^= ss_bytes[i % ss_bytes.len()];
    }
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&data_key));
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, compressed.as_slice())
        .expect("aes-gcm encryption failed");

    // Wrap the ML-KEM secret key with the password-derived key.
    let wrap_cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let mut wrap_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut wrap_nonce);
    let sk_wrapped = wrap_cipher
        .encrypt(GenericArray::from_slice(&wrap_nonce), sk.as_bytes())
        .expect("aes-gcm wrap failed");

    // Prepend metadata: salt + data nonce + kem ciphertext + wrap nonce + wrapped sk
    let mut output = salt.to_vec();
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(kem_ct.as_bytes());
    output.extend_from_slice(&wrap_nonce);
    output.extend_from_slice(&sk_wrapped);
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

    let kem_ct_len = mlkem1024::ciphertext_bytes();
    let sk_len = mlkem1024::secret_key_bytes();
    let min_len = 16 + 12 + kem_ct_len + 12 + sk_len + 16;
    if decoded.len() < min_len {
        return Err("Ciphertext too short (needs salt, PQ, and nonces)".to_string());
    }
    let (salt, rest) = decoded.split_at(16);
    let (nonce_bytes, rest) = rest.split_at(12);
    let (kem_ct_bytes, rest) = rest.split_at(kem_ct_len);
    let (wrap_nonce, rest) = rest.split_at(12);
    let (sk_wrapped, ciphertext) = rest.split_at(sk_len + 16);

    let (key, mix_init, mix_multiplier, aes_key) = derive_keys(password, salt);

    let kem_ct = mlkem1024::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| "Invalid ML-KEM ciphertext".to_string())?;

    let wrap_cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
    let sk_bytes = wrap_cipher
        .decrypt(GenericArray::from_slice(wrap_nonce), sk_wrapped)
        .map_err(|e| format!("AES-GCM unwrap error: {e}"))?;
    let sk = mlkem1024::SecretKey::from_bytes(&sk_bytes)
        .map_err(|_| "Invalid ML-KEM secret key".to_string())?;
    let ss = mlkem1024::decapsulate(&kem_ct, &sk);
    let ss_bytes = ss.as_bytes();

    let pq_mask = ss_bytes[0];
    let pq_mix_init = ss_bytes[1];
    let pq_mix_multiplier = ss_bytes[2] | 1;

    // Decrypt with AES-256-GCM
    let mut data_key = aes_key;
    for (i, b) in data_key.iter_mut().enumerate() {
        *b ^= ss_bytes[i % ss_bytes.len()];
    }
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&data_key));
    let nonce = GenericArray::from_slice(nonce_bytes);
    let decompressed = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES-GCM decrypt error: {e}"))?;

    // Decompress with zstd
    let decompressed = decode_all(Cursor::new(&decompressed))
        .map_err(|e| format!("Zstd decompress error: {e}"))?;

    let mut mix = mix_init ^ pq_mix_init;
    let mix_multiplier = mix_multiplier ^ pq_mix_multiplier;
    let decrypted: Vec<u8> = decompressed
        .iter()
        .enumerate()
        .map(|(i, &enc)| {
            let orig = enc ^ key ^ pq_mask ^ mix.wrapping_add(i as u8);
            mix = mix.wrapping_mul(mix_multiplier).wrapping_add(enc);
            orig
        })
        .collect();

    Ok(decrypted)
}
