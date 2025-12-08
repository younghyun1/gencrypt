# gencrypt

`gencrypt` is a tool for the paranoid used in encrypting, obfuscating, and compressing as well as decrypting arbitrary text or files using a password.

It combines:

- Key derivation with **PBKDF2-HMAC-SHA256** (600,000 iterations)
- A custom byte-masking step
- Compression with **zstd**
- Authenticated encryption using **AES‑256‑GCM**
- URL-safe, no-padding Base64 for transport

You can use it as:

- A **CLI application** to encrypt/decrypt text and files
- A **Rust library** to call `encode_custom` / `decode_custom` from your own code


## Installation

### From crates.io (recommended)

If you have a working Rust toolchain with Cargo installed:

```bash
cargo install gencrypt
```

This will download, build, and place the `gencrypt` binary in `~/.cargo/bin`.  
Make sure that directory is on your `PATH`.

Confirm installation:

```bash
gencrypt --help
```


### From source

1. Clone the repository:

   ```bash
   git clone https://github.com/<your-username>/gencrypt.git
   cd gencrypt
   ```

2. Build in release mode:

   ```bash
   cargo build --release
   ```

3. The compiled binary will be at:

   ```text
   target/release/gencrypt
   ```

   You can run it directly or copy/symlink it somewhere on your `PATH`.

## Using as a library

Add `gencrypt` as a dependency in `Cargo.toml`:

```toml
[dependencies]
gencrypt = "0.1"
```

Then, in your Rust code:

```rust
use gencrypt::crypto::{encode_custom, decode_custom};

fn main() -> Result<(), String> {
    let password = "correct horse battery staple";
    let plaintext = "Hello, world!";

    // Encrypt
    let ciphertext = encode_custom(plaintext, password);
    println!("Ciphertext: {ciphertext}");

    // Decrypt
    let recovered = decode_custom(&ciphertext, password)?;
    println!("Recovered: {recovered}");

    Ok(())
}
```

For binary-safe usage (arbitrary bytes instead of UTF‑8 strings), use the `*_bytes` APIs:

```rust
use gencrypt::crypto::{encode_custom_bytes, decode_custom_bytes};

fn roundtrip_bytes() -> Result<(), String> {
    let password = "secret";
    let data = b"\x00\xffbinary data\x01";

    let encoded = encode_custom_bytes(data, password);
    let decoded = decode_custom_bytes(&encoded, password)?;

    assert_eq!(decoded, data);
    Ok(())
}
```


## How it works (high level)

The main logic lives in [`crypto.rs`](./src/crypto.rs) and is used by the UI code in [`main.rs`](./src/main.rs).

Given an `input` and a `password`:

1. A random **salt** and **nonce** are generated.
2. `derive_keys(password, salt)` uses PBKDF2‑HMAC‑SHA256 to produce:
   - A small set of bytes for the custom masking step
   - A 32‑byte AES‑256 key
3. The input bytes are **masked** with a rolling `mix` value for an extra obfuscation layer.
4. The masked bytes are **compressed** with zstd (level 3).
5. The compressed data is encrypted using **AES‑256‑GCM** with the derived key and random nonce.
6. The result is: `salt || nonce || ciphertext`, encoded with URL-safe Base64 (no padding).

Decoding reverses these steps, verifying the AES‑GCM tag to ensure integrity and authenticity before attempting decompression or unmasking.


## Building / Running Tests

To build (debug):

```bash
cargo build
```

To run tests:

```bash
cargo test
```


## Security notes

- The password is stretched with **PBKDF2-HMAC-SHA256** using 600,000 iterations, which is intentionally slow to hinder brute-force attacks.
- Encryption uses **AES‑256‑GCM**, providing confidentiality and integrity.
- Nevertheless, do not treat this as a substitute for a fully reviewed, widely used cryptographic standard or protocol.
- Always keep your **passwords secret** and avoid reusing them across different systems.

Use at your own risk and verify that it meets your security requirements before using it for sensitive data.
