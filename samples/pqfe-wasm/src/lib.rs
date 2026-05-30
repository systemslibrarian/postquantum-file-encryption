//! A browser-targeted (WebAssembly) re-implementation of the PostQuantum.FileEncryption
//! `.pqfe` **v2** container format, so the demo can run fully client-side on static hosting
//! (e.g. GitHub Pages) with files never leaving the browser.
//!
//! This is a *second implementation* of the format specified in `docs/FILE-FORMAT.md`. It is
//! kept byte-compatible with the .NET library by decrypting the same known-answer vectors the
//! .NET test suite uses (see `tests/vectors.rs`). Only the **passphrase** key source is
//! supported here; ML-KEM recipient mode is not available in the browser.
//!
//! No novel cryptography: AES-256-GCM, PBKDF2-HMAC-SHA256, and Argon2id from the RustCrypto
//! crates, composed exactly as the format prescribes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::Sha256;

// ----------------------------------------------------------------- format constants

const MAGIC: &[u8; 4] = b"PQFE";
const FORMAT_VERSION: u8 = 2;
const AEAD_AES256GCM: u8 = 1;
const KEYSOURCE_PASSPHRASE: u8 = 1;
const KEYSOURCE_MLKEM: u8 = 2;
const KDF_PBKDF2: u8 = 1;
const KDF_ARGON2ID: u8 = 2;

const NONCE_PREFIX_LEN: usize = 4;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const FIXED_HEADER_LEN: usize = 18;

const FRAME_DATA: u8 = 0;
const FRAME_FINAL: u8 = 1;

// Bounds mirror the .NET library so a hostile container fails closed instead of exhausting work.
const MIN_PBKDF2_ITERS: u32 = 100_000;
const MAX_PBKDF2_ITERS: u32 = 100_000_000;
const MIN_ARGON2_MEM_KIB: u32 = 8 * 1024;
const MAX_ARGON2_MEM_KIB: u32 = 2 * 1024 * 1024;
const MIN_ARGON2_ITERS: u32 = 1;
const MAX_ARGON2_ITERS: u32 = 10_000;
const MIN_SALT_LEN: usize = 8;
const MIN_CHUNK: u32 = 1024;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;

// Encryption defaults — identical to the .NET library defaults.
const DEFAULT_CHUNK: u32 = 64 * 1024;
const DEFAULT_PBKDF2_ITERS: u32 = 600_000;
const DEFAULT_SALT_LEN: usize = 16;

/// Errors surfaced to callers. Decryption is fail-closed: every authentication failure maps to
/// the same generic [`PqError::Decryption`], so there is no oracle.
#[derive(Debug, PartialEq, Eq)]
pub enum PqError {
    /// Not a recognizable `.pqfe` container (bad magic, version, or structure).
    Format(&'static str),
    /// Wrong passphrase, or altered/corrupted/truncated container.
    Decryption,
    /// A capability not available in this browser core (e.g. recipient mode).
    Unsupported(&'static str),
}

impl core::fmt::Display for PqError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PqError::Format(m) => write!(f, "Not a PostQuantum.FileEncryption (.pqfe) container: {m}"),
            PqError::Decryption => write!(
                f,
                "Decryption failed: the passphrase is wrong, or the data has been altered or corrupted."
            ),
            PqError::Unsupported(m) => write!(f, "Unsupported: {m}"),
        }
    }
}

// ----------------------------------------------------------------- helpers

fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("a secure RNG is required");
}

fn build_nonce(prefix: &[u8], counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn build_aad(header: &[u8], counter: u64, frame_type: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 8 + 1);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.push(frame_type);
    aad
}

fn derive_pbkdf2(passphrase: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut key);
    key
}

fn derive_argon2id(
    passphrase: &[u8],
    salt: &[u8],
    mem_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; KEY_LEN], PqError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(mem_kib, iterations, parallelism, Some(KEY_LEN))
        .map_err(|_| PqError::Format("invalid Argon2id parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| PqError::Decryption)?;
    Ok(key)
}

// ----------------------------------------------------------------- encryption

/// Encrypts `data` into a `.pqfe` container using passphrase-based PBKDF2 + AES-256-GCM,
/// matching the .NET library defaults (64 KiB chunks, 600,000 iterations, 16-byte salt).
pub fn encrypt_bytes(data: &[u8], passphrase: &[u8]) -> Vec<u8> {
    let mut salt = vec![0u8; DEFAULT_SALT_LEN];
    random_bytes(&mut salt);
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    random_bytes(&mut nonce_prefix);

    let key = derive_pbkdf2(passphrase, &salt, DEFAULT_PBKDF2_ITERS);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    // KeyParams (passphrase / PBKDF2): KdfId | SaltLen | Salt | Iterations(u32 BE)
    let mut key_params = Vec::with_capacity(2 + salt.len() + 4);
    key_params.push(KDF_PBKDF2);
    key_params.push(salt.len() as u8);
    key_params.extend_from_slice(&salt);
    key_params.extend_from_slice(&DEFAULT_PBKDF2_ITERS.to_be_bytes());

    let header = build_header(KEYSOURCE_PASSPHRASE, DEFAULT_CHUNK, &nonce_prefix, &key_params);

    let mut out = Vec::with_capacity(header.len() + data.len() + 64);
    out.extend_from_slice(&header);

    let chunk = DEFAULT_CHUNK as usize;
    let mut counter: u64 = 0;
    let mut offset = 0usize;
    loop {
        let remaining = data.len() - offset;
        let take = remaining.min(chunk);
        let is_final = remaining <= chunk; // this chunk consumes the rest
        let frame_type = if is_final { FRAME_FINAL } else { FRAME_DATA };

        let nonce = build_nonce(&nonce_prefix, counter);
        let aad = build_aad(&header, counter, frame_type);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &data[offset..offset + take], aad: &aad },
            )
            .expect("AES-GCM encryption cannot fail for valid inputs");
        // `sealed` is ciphertext(take) || tag(16) — exactly the on-disk frame body order.
        debug_assert_eq!(sealed.len(), take + TAG_LEN);

        out.push(frame_type);
        out.extend_from_slice(&(take as u32).to_be_bytes());
        out.extend_from_slice(&sealed);

        counter += 1;
        offset += take;
        if is_final {
            break;
        }
    }

    out
}

fn build_header(key_source: u8, chunk_size: u32, nonce_prefix: &[u8], key_params: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(FIXED_HEADER_LEN + key_params.len());
    h.extend_from_slice(MAGIC);
    h.push(FORMAT_VERSION);
    h.push(AEAD_AES256GCM);
    h.push(key_source);
    h.push(0); // flags
    h.extend_from_slice(&chunk_size.to_be_bytes());
    h.extend_from_slice(nonce_prefix);
    h.extend_from_slice(&(key_params.len() as u16).to_be_bytes());
    h.extend_from_slice(key_params);
    h
}

// ----------------------------------------------------------------- decryption

struct Header {
    chunk_size: u32,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    key_params: Vec<u8>,
    bytes: Vec<u8>, // full serialized header, used as AAD prefix
    total_len: usize,
}

fn read_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn parse_header(data: &[u8]) -> Result<Header, PqError> {
    if data.len() < FIXED_HEADER_LEN {
        return Err(PqError::Format("too short"));
    }
    if &data[0..4] != MAGIC {
        return Err(PqError::Format("bad magic bytes"));
    }
    if data[4] != FORMAT_VERSION {
        return Err(PqError::Format("unsupported format version"));
    }
    if data[5] != AEAD_AES256GCM {
        return Err(PqError::Format("unsupported AEAD"));
    }
    match data[6] {
        KEYSOURCE_PASSPHRASE => {}
        KEYSOURCE_MLKEM => {
            return Err(PqError::Unsupported(
                "this container is encrypted to a recipient key; the browser demo only supports passphrases",
            ))
        }
        _ => return Err(PqError::Format("unknown key source")),
    }

    let chunk_size = read_u32(&data[8..12]);
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) {
        return Err(PqError::Format("chunk size out of range"));
    }

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&data[12..16]);

    let key_params_len = read_u16(&data[16..18]) as usize;
    let total_len = FIXED_HEADER_LEN + key_params_len;
    if data.len() < total_len {
        return Err(PqError::Format("header truncated"));
    }

    let key_params = data[FIXED_HEADER_LEN..total_len].to_vec();
    let bytes = data[..total_len].to_vec();
    Ok(Header { chunk_size, nonce_prefix, key_params, bytes, total_len })
}

fn derive_key_from_params(passphrase: &[u8], key_params: &[u8]) -> Result<[u8; KEY_LEN], PqError> {
    if key_params.len() < 2 {
        return Err(PqError::Format("passphrase parameters too short"));
    }
    let kdf_id = key_params[0];
    let salt_len = key_params[1] as usize;
    if salt_len < MIN_SALT_LEN || key_params.len() < 2 + salt_len {
        return Err(PqError::Format("invalid salt"));
    }
    let salt = &key_params[2..2 + salt_len];
    let rest = &key_params[2 + salt_len..];

    match kdf_id {
        KDF_PBKDF2 => {
            if rest.len() < 4 {
                return Err(PqError::Format("PBKDF2 parameters truncated"));
            }
            let iters = read_u32(&rest[0..4]);
            if !(MIN_PBKDF2_ITERS..=MAX_PBKDF2_ITERS).contains(&iters) {
                return Err(PqError::Format("PBKDF2 iterations out of range"));
            }
            Ok(derive_pbkdf2(passphrase, salt, iters))
        }
        KDF_ARGON2ID => {
            if rest.len() < 9 {
                return Err(PqError::Format("Argon2id parameters truncated"));
            }
            let mem = read_u32(&rest[0..4]);
            let iters = read_u32(&rest[4..8]);
            let parallelism = rest[8] as u32;
            if !(MIN_ARGON2_MEM_KIB..=MAX_ARGON2_MEM_KIB).contains(&mem)
                || !(MIN_ARGON2_ITERS..=MAX_ARGON2_ITERS).contains(&iters)
                || parallelism < 1
            {
                return Err(PqError::Format("Argon2id parameters out of range"));
            }
            derive_argon2id(passphrase, salt, mem, iters, parallelism)
        }
        _ => Err(PqError::Format("unsupported KDF")),
    }
}

/// Decrypts a `.pqfe` container produced with the passphrase key source. Fail-closed: any
/// tampering, truncation, or wrong passphrase yields [`PqError::Decryption`].
pub fn decrypt_bytes(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, PqError> {
    let header = parse_header(data)?;
    let key = derive_key_from_params(passphrase, &header.key_params)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let mut pos = header.total_len;
    let mut counter: u64 = 0;
    let mut out = Vec::new();
    let mut saw_final = false;

    while pos < data.len() {
        if pos + 5 > data.len() {
            return Err(PqError::Decryption); // truncated frame header
        }
        let frame_type = data[pos];
        if frame_type != FRAME_DATA && frame_type != FRAME_FINAL {
            return Err(PqError::Decryption);
        }
        let length = read_u32(&data[pos + 1..pos + 5]) as usize;
        if length as u32 > header.chunk_size {
            return Err(PqError::Decryption);
        }
        pos += 5;
        if pos + length + TAG_LEN > data.len() {
            return Err(PqError::Decryption); // truncated frame body
        }

        let body = &data[pos..pos + length + TAG_LEN]; // ciphertext || tag
        pos += length + TAG_LEN;

        let nonce = build_nonce(&header.nonce_prefix, counter);
        let aad = build_aad(&header.bytes, counter, frame_type);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: body, aad: &aad })
            .map_err(|_| PqError::Decryption)?;
        out.extend_from_slice(&plaintext);

        counter += 1;
        if frame_type == FRAME_FINAL {
            saw_final = true;
            break;
        }
    }

    if !saw_final {
        return Err(PqError::Decryption); // no authenticated final frame ⇒ truncated
    }
    Ok(out)
}

// ----------------------------------------------------------------- WebAssembly bindings

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Encrypts `data` with `passphrase` (UTF-8) and returns the `.pqfe` container bytes.
    #[wasm_bindgen]
    pub fn encrypt(data: &[u8], passphrase: &str) -> Vec<u8> {
        super::encrypt_bytes(data, passphrase.as_bytes())
    }

    /// Decrypts a `.pqfe` container with `passphrase` (UTF-8). Rejects tampered/wrong input.
    #[wasm_bindgen]
    pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>, JsError> {
        super::decrypt_bytes(data, passphrase.as_bytes()).map_err(|e| JsError::new(&e.to_string()))
    }
}
