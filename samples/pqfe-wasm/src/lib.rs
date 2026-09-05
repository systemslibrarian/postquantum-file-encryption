//! A browser-targeted (WebAssembly) re-implementation of the PostQuantum.FileEncryption
//! `.pqfe` **v2** container format, so the demo can run fully client-side on static hosting
//! (e.g. GitHub Pages) with files never leaving the browser.
//!
//! This is a *second implementation* of the format specified in `docs/FILE-FORMAT.md`. It is
//! kept byte-compatible with the .NET library by decrypting the same known-answer vectors the
//! .NET test suite uses (see `tests/vectors.rs`) and by a live both-directions interop CI job.
//! It implements the **passphrase** key source and the X25519 + ML-KEM-768 **hybrid recipient**
//! mode (KeySource 3/4). The browser bindings below expose passphrase mode only — recipient
//! private keys are not handled in-browser — but the hybrid core is exercised natively.
//!
//! No novel cryptography: AES-256-GCM, PBKDF2-HMAC-SHA256, and Argon2id from the RustCrypto
//! crates, plus ML-KEM-768 (`ml-kem`), X25519 (`x25519-dalek`), and HKDF-SHA256 (`hkdf`) for
//! the hybrid combiner — composed exactly as the format prescribes.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::Sha256;

// ----------------------------------------------------------------- format constants

const MAGIC: &[u8; 4] = b"PQFE";
const FORMAT_VERSION: u8 = 2;
const AEAD_AES256GCM: u8 = 1;
const KEYSOURCE_PASSPHRASE: u8 = 1;
const KEYSOURCE_MLKEM: u8 = 2;
const KEYSOURCE_HYBRID: u8 = 3;
const KEYSOURCE_MULTI: u8 = 4;
const KEYSOURCE_PROVIDER: u8 = 5;
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

// ---- hybrid recipient mode (KeySource 3/4) constants; see docs/FILE-FORMAT.md + HYBRID-COMBINER.md
const KEM_ML_KEM_768: u8 = 1; // KemId
const KEM_CT_LEN: usize = 1088; // ML-KEM-768 ciphertext
const X25519_LEN: usize = 32; // X25519 public/private key
const MLKEM_DK_LEN: usize = 2400; // ML-KEM-768 decapsulation (private) key, FIPS 203 encoding
const MLKEM_EK_LEN: usize = 1184; // ML-KEM-768 encapsulation (public) key, FIPS 203 encoding
/// A recipient private key is `X25519(32) ‖ ML-KEM-dk(2400)` (see `PqHybridPrivateKey.Export`).
pub const HYBRID_PRIVATE_KEY_LEN: usize = X25519_LEN + MLKEM_DK_LEN; // 2432
/// A recipient public key is `X25519(32) ‖ ML-KEM-ek(1184)` (see `PqHybridPublicKey.Export`).
pub const HYBRID_PUBLIC_KEY_LEN: usize = X25519_LEN + MLKEM_EK_LEN; // 1216
/// One serialized KeySource-3 block: `KemId(1) ‖ C(2) ‖ KemCt(1088) ‖ Eph(32) ‖ Nonce(12) ‖ Tag(16) ‖ Wrapped(32)`.
const HYBRID_BLOCK_LEN: usize = 3 + KEM_CT_LEN + X25519_LEN + NONCE_LEN + TAG_LEN + KEY_LEN; // 1183
const MODE_HYBRID: u8 = 3; // KeySource-4 per-entry mode byte

// Fixed HKDF `info` and AES-GCM wrap AAD labels. The `v3` here is the KeySource discriminant,
// not the container version (which stays `.pqfe` v2) — see HYBRID-COMBINER.md.
const KEK_INFO: &[u8] = b"PostQuantum.FileEncryption/v3 hybrid kek";
const WRAP_AAD: &[u8] = b"PostQuantum.FileEncryption/v3 cek-wrap";

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
    encrypt_bytes_with(
        data,
        passphrase,
        &salt,
        &nonce_prefix,
        DEFAULT_PBKDF2_ITERS,
        DEFAULT_CHUNK,
    )
}

/// Deterministic encryption with caller-supplied salt, nonce prefix, iteration count, and chunk
/// size. Intended for **conformance testing** (byte-for-byte cross-checks against the .NET
/// library); production code should use [`encrypt_bytes`], which generates random salt/nonce.
pub fn encrypt_bytes_with(
    data: &[u8],
    passphrase: &[u8],
    salt: &[u8],
    nonce_prefix: &[u8],
    iterations: u32,
    chunk_size: u32,
) -> Vec<u8> {
    // This test-facing writer must enforce the same parameter ranges as the .NET writer's
    // PqEncryptionOptions.Validate: without these, chunk_size = 0 loops forever appending
    // empty frames, a nonce prefix that is not 4 bytes panics mid-write, and a salt longer
    // than 255 bytes silently truncates its length byte — producing a container no
    // conforming reader can ever decrypt (silent data loss for a caller who kept only the
    // ciphertext).
    assert!(
        (MIN_SALT_LEN..=255).contains(&salt.len()),
        "salt must be 8..=255 bytes"
    );
    assert!(
        nonce_prefix.len() == NONCE_PREFIX_LEN,
        "nonce prefix must be exactly 4 bytes"
    );
    assert!(
        (MIN_PBKDF2_ITERS..=MAX_PBKDF2_ITERS).contains(&iterations),
        "iterations out of the format range"
    );
    assert!(
        (MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size),
        "chunk size out of the format range"
    );
    let key = derive_pbkdf2(passphrase, salt, iterations);

    // KeyParams (passphrase / PBKDF2): KdfId | SaltLen | Salt | Iterations(u32 BE)
    let mut key_params = Vec::with_capacity(2 + salt.len() + 4);
    key_params.push(KDF_PBKDF2);
    key_params.push(salt.len() as u8);
    key_params.extend_from_slice(salt);
    key_params.extend_from_slice(&iterations.to_be_bytes());

    let header = build_header(KEYSOURCE_PASSPHRASE, chunk_size, nonce_prefix, &key_params);
    encrypt_frames(&header, nonce_prefix, &key, chunk_size, data)
}

/// Writes the header followed by the chunked AES-256-GCM data plane with an established content
/// key. Identical for every key source (FILE-FORMAT.md, "Frames"), so passphrase and hybrid
/// recipient encryption share it. Returns the full container bytes.
fn encrypt_frames(
    header: &[u8],
    nonce_prefix: &[u8],
    cek: &[u8; KEY_LEN],
    chunk_size: u32,
    data: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek));

    let mut out = Vec::with_capacity(header.len() + data.len() + 64);
    out.extend_from_slice(header);

    let chunk = chunk_size as usize;
    let mut counter: u64 = 0;
    let mut offset = 0usize;
    loop {
        let remaining = data.len() - offset;
        let take = remaining.min(chunk);
        let is_final = remaining <= chunk; // this chunk consumes the rest
        let frame_type = if is_final { FRAME_FINAL } else { FRAME_DATA };

        let nonce = build_nonce(nonce_prefix, counter);
        let aad = build_aad(header, counter, frame_type);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &data[offset..offset + take],
                    aad: &aad,
                },
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

fn build_header(
    key_source: u8,
    chunk_size: u32,
    nonce_prefix: &[u8],
    key_params: &[u8],
) -> Vec<u8> {
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
    key_source: u8,
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
    let key_source = data[6];
    // Reject unknown key sources fail-closed (FILE-FORMAT.md rule 1); whether a *known* source
    // is supported by a given entry point is decided by that entry point, not here.
    if !matches!(
        key_source,
        KEYSOURCE_PASSPHRASE
            | KEYSOURCE_MLKEM
            | KEYSOURCE_HYBRID
            | KEYSOURCE_MULTI
            | KEYSOURCE_PROVIDER
    ) {
        return Err(PqError::Format("unknown key source"));
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
    Ok(Header {
        key_source,
        chunk_size,
        nonce_prefix,
        key_params,
        bytes,
        total_len,
    })
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
///
/// Recipient (hybrid) containers need a private key, not a passphrase; this returns
/// [`PqError::Unsupported`] for them — call [`decrypt_bytes_hybrid`] instead.
pub fn decrypt_bytes(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, PqError> {
    let header = parse_header(data)?;
    match header.key_source {
        KEYSOURCE_PASSPHRASE => {
            let key = derive_key_from_params(passphrase, &header.key_params)?;
            decrypt_frames(data, &header, &key)
        }
        KEYSOURCE_HYBRID | KEYSOURCE_MULTI => Err(PqError::Unsupported(
            "this container is encrypted to a recipient key; call decrypt_bytes_hybrid with a private key",
        )),
        KEYSOURCE_MLKEM => Err(PqError::Unsupported(
            "inline ML-KEM-only recipient mode (deprecated PQFE002) is not implemented in this core",
        )),
        _ => Err(PqError::Unsupported(
            "this container uses an external key provider, which this core does not implement",
        )),
    }
}

/// Runs the chunked AES-256-GCM data plane with an established 32-byte content key. This part of
/// the format is identical for every key source (FILE-FORMAT.md, "Frames"), so passphrase and
/// hybrid recipient decryption share it once the CEK is recovered.
fn decrypt_frames(data: &[u8], header: &Header, cek: &[u8; KEY_LEN]) -> Result<Vec<u8>, PqError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek));

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
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
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

// ----------------------------------------------------------------- hybrid recipient mode
//
// KeySource 3 (single) / 4 (multi) wrap the content key to X25519 + ML-KEM-768 recipients.
// Recovering the CEK is the only work unique to this path; the data plane above is shared.
// No novel cryptography: ML-KEM-768 (FIPS 203) from `ml-kem`, X25519 from `x25519-dalek`,
// HKDF-SHA256 from `hkdf`, AES-256-GCM from `aes-gcm` — composed exactly as HYBRID-COMBINER.md
// and FILE-FORMAT.md prescribe.

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::ml_kem_768::{
    Ciphertext as MlKem768Ct, DecapsulationKey as MlKem768Dk, EncapsulationKey as MlKem768Ek,
};
use ml_kem::{ExpandedKeyEncoding, Kem, Key as MlKemKey, KeyExport, MlKem768, TryKeyInit};

/// ML-KEM-768 decapsulation: `ss_pq = Decapsulate(dk, ct)`. Deterministic per FIPS 203, so this
/// yields the exact 32-byte shared secret the .NET (BouncyCastle) encryptor derived.
fn mlkem_decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32], PqError> {
    // ml-kem 0.3's `as_bytes`/`KeySize` is the 64-byte *seed*; the wire format here carries the
    // 2400-byte *expanded* key that BouncyCastle produces, so the expanded encoding is required.
    let encoded: &Array<u8, <MlKem768Dk as ExpandedKeyEncoding>::EncodedSize> =
        dk_bytes
            .try_into()
            .map_err(|_| PqError::Format("ML-KEM decapsulation key has the wrong length"))?;
    let dk = MlKem768Dk::from_expanded_bytes(encoded)
        .map_err(|_| PqError::Format("ML-KEM decapsulation key is invalid"))?;
    let ct = MlKem768Ct::try_from(ct_bytes)
        .map_err(|_| PqError::Format("ML-KEM ciphertext has the wrong length"))?;
    // FIPS 203 decapsulation never fails (implicit rejection yields a pseudorandom secret); a
    // ciphertext meant for another key simply produces a different secret, so the wrap tag below
    // mismatches. There is no error oracle here.
    // ml-kem 0.3's Decapsulate is infallible — FIPS 203 implicit rejection yields a pseudorandom
    // secret rather than an error, so a ciphertext for another key just fails the wrap tag below.
    let ss = dk.decapsulate(&ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(&ss);
    Ok(out)
}

/// X25519 agreement against the sender's ephemeral public key. Returns `None` for a small-order
/// ephemeral point (all-zero shared secret) so the caller fails closed, mirroring the .NET side.
fn x25519_agree(priv_bytes: &[u8], eph_pub: &[u8]) -> Option<[u8; 32]> {
    use x25519_dalek::{PublicKey, StaticSecret};
    let sk: [u8; 32] = priv_bytes.try_into().ok()?;
    let pk: [u8; 32] = eph_pub.try_into().ok()?;
    let shared = StaticSecret::from(sk).diffie_hellman(&PublicKey::from(pk));
    if !shared.was_contributory() {
        return None; // degenerate (small-order) point — treat exactly like a wrap-tag mismatch
    }
    Some(*shared.as_bytes())
}

/// The combiner: `KEK = HKDF-SHA256(ss_pq ‖ ss_classical, salt = absent, info = KEK_INFO, L = 32)`.
fn derive_kek(ss_pq: &[u8; 32], ss_classical: &[u8; 32]) -> [u8; KEY_LEN] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_pq);
    ikm[32..].copy_from_slice(ss_classical);
    let hk = Hkdf::<sha2::Sha256>::new(None, &ikm);
    let mut kek = [0u8; KEY_LEN];
    hk.expand(KEK_INFO, &mut kek)
        .expect("32-byte OKM is within HKDF-SHA256's output limit");
    kek
}

/// Tries to unwrap one KeySource-3 block with `private_key` (`X25519(32) ‖ ML-KEM-dk(2400)`).
///
/// - `Err(Format)` — the block is structurally malformed (bad `KemId` or length). Mirrors the
///   .NET reader, where a malformed hybrid block is a format error, not a skip (KNOWN-GAPS.md).
/// - `Ok(None)` — well-formed but not ours, or tampered: the wrap tag did not authenticate.
/// - `Ok(Some(cek))` — the recovered 32-byte content key.
fn try_unwrap_block(block: &[u8], private_key: &[u8]) -> Result<Option<[u8; KEY_LEN]>, PqError> {
    // Layout: KemId(1) | C(2) | KemCt(C) | Eph(32) | WrapNonce(12) | WrapTag(16) | Wrapped(32)
    if block.len() < 3 || block[0] != KEM_ML_KEM_768 {
        return Err(PqError::Format(
            "unsupported or malformed hybrid key parameters",
        ));
    }
    let c = read_u16(&block[1..3]) as usize;
    // With ML-KEM-768's fixed 1088-byte ciphertext, a well-formed block is exactly HYBRID_BLOCK_LEN.
    if c != KEM_CT_LEN || block.len() != HYBRID_BLOCK_LEN {
        return Err(PqError::Format(
            "hybrid key parameters have an invalid length",
        ));
    }

    let mut off = 3;
    let kem_ct = &block[off..off + c];
    off += c;
    let eph_pub = &block[off..off + X25519_LEN];
    off += X25519_LEN;
    let wrap_nonce = &block[off..off + NONCE_LEN];
    off += NONCE_LEN;
    let wrap_tag = &block[off..off + TAG_LEN];
    off += TAG_LEN;
    let wrapped = &block[off..off + KEY_LEN];

    let ss_pq = mlkem_decapsulate(&private_key[X25519_LEN..], kem_ct)?;
    let ss_classical = match x25519_agree(&private_key[..X25519_LEN], eph_pub) {
        Some(s) => s,
        None => return Ok(None),
    };
    let kek = derive_kek(&ss_pq, &ss_classical);

    // The wrap is AES-256-GCM(KEK, WrapNonce, CEK, aad = WRAP_AAD); on disk the tag is stored
    // separately, so reassemble ciphertext‖tag for the `aes-gcm` API.
    let mut ct_and_tag = Vec::with_capacity(KEY_LEN + TAG_LEN);
    ct_and_tag.extend_from_slice(wrapped);
    ct_and_tag.extend_from_slice(wrap_tag);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    match cipher.decrypt(
        Nonce::from_slice(wrap_nonce),
        Payload {
            msg: &ct_and_tag,
            aad: WRAP_AAD,
        },
    ) {
        Ok(cek) if cek.len() == KEY_LEN => {
            let mut out = [0u8; KEY_LEN];
            out.copy_from_slice(&cek);
            Ok(Some(out))
        }
        _ => Ok(None), // wrong recipient key or tampered — indistinguishable, no oracle
    }
}

/// Recovers the CEK from a KeySource-4 (multi-recipient) body: `Count(1)` then `Count` entries of
/// `Mode(1) ‖ BlockLength(2) ‖ block`. Tries each hybrid block; the first that authenticates wins.
fn unwrap_multi(body: &[u8], private_key: &[u8]) -> Result<[u8; KEY_LEN], PqError> {
    if body.is_empty() {
        return Err(PqError::Format("multi-recipient key parameters are empty"));
    }
    let count = body[0] as usize;
    if count < 1 {
        return Err(PqError::Format(
            "multi-recipient container declares zero recipients",
        ));
    }

    let mut off = 1;
    for _ in 0..count {
        if off + 3 > body.len() {
            return Err(PqError::Format(
                "multi-recipient key parameters are truncated",
            ));
        }
        let mode = body[off];
        let block_len = read_u16(&body[off + 1..off + 3]) as usize;
        off += 3;
        if off + block_len > body.len() {
            return Err(PqError::Format("multi-recipient block is truncated"));
        }
        let block = &body[off..off + block_len];
        off += block_len;

        if mode == MODE_HYBRID {
            if let Some(cek) = try_unwrap_block(block, private_key)? {
                return Ok(cek);
            }
        }
        // Unknown mode: keep trying the rest (matches the .NET reader).
    }

    Err(PqError::Decryption)
}

/// Decrypts a hybrid recipient container (KeySource 3 or 4) with a recipient private key
/// (`X25519(32) ‖ ML-KEM-dk(2400)`, i.e. `PqHybridPrivateKey.Export()` bytes, 2432 bytes).
///
/// Fail-closed: a wrong key, a container this key is not a recipient of, tampering, or truncation
/// all yield [`PqError::Decryption`] — one indistinguishable outcome, no oracle.
pub fn decrypt_bytes_hybrid(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, PqError> {
    if private_key.len() != HYBRID_PRIVATE_KEY_LEN {
        return Err(PqError::Format("a hybrid private key must be 2432 bytes"));
    }
    let header = parse_header(data)?;
    let cek = match header.key_source {
        KEYSOURCE_HYBRID => {
            try_unwrap_block(&header.key_params, private_key)?.ok_or(PqError::Decryption)?
        }
        KEYSOURCE_MULTI => unwrap_multi(&header.key_params, private_key)?,
        _ => {
            return Err(PqError::Unsupported(
                "this container is not a hybrid recipient container; use decrypt_bytes",
            ))
        }
    };
    decrypt_frames(data, &header, &cek)
}

// ---- hybrid recipient encryption (the wrap side) ----

/// A `CryptoRng` over the platform RNG, for the two randomized steps of a hybrid wrap: ML-KEM
/// encapsulation and the fresh ephemeral X25519 key. Failure of the OS RNG is unrecoverable, so
/// `fill_bytes` panics rather than returning a broken key — the same posture as `random_bytes`.
struct GetrandomRng;

// rand_core 0.10 restructured its traits: `TryRng` is the base, and `Rng`/`CryptoRng` are
// blanket-implemented for any `TryRng`/`TryCryptoRng` whose Error is `Infallible`. `RngCore` is
// now a deprecated stub. Implementing the fallible pair therefore yields the infallible ones,
// and `rand_core::Error` no longer exists.
impl rand_core::TryRng for GetrandomRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        random_bytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        random_bytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        random_bytes(dst);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for GetrandomRng {}

/// ML-KEM-768 encapsulation against a recipient encapsulation key: returns `(ct, ss_pq)`.
fn mlkem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32]), PqError> {
    let key: &MlKemKey<MlKem768Ek> = ek_bytes
        .try_into()
        .map_err(|_| PqError::Format("recipient ML-KEM encapsulation key has the wrong length"))?;
    let ek = MlKem768Ek::new(key)
        .map_err(|_| PqError::Format("recipient ML-KEM encapsulation key is invalid"))?;
    // ml-kem 0.3's encapsulate_with_rng is infallible; key validity is checked at construction.
    let (ct, ss) = ek.encapsulate_with_rng(&mut GetrandomRng);
    let mut ss_pq = [0u8; 32];
    ss_pq.copy_from_slice(&ss);
    Ok((ct[..].to_vec(), ss_pq))
}

/// Wraps `cek` to one recipient public key (`X25519(32) ‖ ML-KEM-ek(1184)`), returning a
/// KeySource-3 block. The inverse of [`try_unwrap_block`].
fn wrap_to_recipient(public_key: &[u8], cek: &[u8; KEY_LEN]) -> Result<Vec<u8>, PqError> {
    use x25519_dalek::{PublicKey, StaticSecret};
    if public_key.len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(PqError::Format("a hybrid public key must be 1216 bytes"));
    }
    let (kem_ct, ss_pq) = mlkem_encapsulate(&public_key[X25519_LEN..])?;

    let mut eph_sk = [0u8; 32];
    random_bytes(&mut eph_sk);
    let eph_secret = StaticSecret::from(eph_sk);
    let eph_public = PublicKey::from(&eph_secret);
    let recip_x25519: [u8; 32] = public_key[..X25519_LEN]
        .try_into()
        .expect("slice is exactly 32 bytes");
    let shared = eph_secret.diffie_hellman(&PublicKey::from(recip_x25519));
    if !shared.was_contributory() {
        return Err(PqError::Format(
            "recipient X25519 key is a degenerate (small-order) point",
        ));
    }
    let ss_classical = *shared.as_bytes();
    let kek = derive_kek(&ss_pq, &ss_classical);

    let mut wrap_nonce = [0u8; NONCE_LEN];
    random_bytes(&mut wrap_nonce);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&kek));
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: cek,
                aad: WRAP_AAD,
            },
        )
        .expect("AES-GCM encryption cannot fail for valid inputs");
    let (wrapped, wrap_tag) = sealed.split_at(KEY_LEN); // ciphertext(32) || tag(16)

    // KemId(1) | C(2) | KemCt | Eph(32) | WrapNonce(12) | WrapTag(16) | Wrapped(32)
    let mut block = Vec::with_capacity(HYBRID_BLOCK_LEN);
    block.push(KEM_ML_KEM_768);
    block.extend_from_slice(&(KEM_CT_LEN as u16).to_be_bytes());
    block.extend_from_slice(&kem_ct);
    block.extend_from_slice(eph_public.as_bytes());
    block.extend_from_slice(&wrap_nonce);
    block.extend_from_slice(wrap_tag);
    block.extend_from_slice(wrapped);
    debug_assert_eq!(block.len(), HYBRID_BLOCK_LEN);
    Ok(block)
}

/// Encrypts `data` to one or more hybrid recipients. One recipient → KeySource 3; more → KeySource
/// 4 (the same content key wrapped to each). Matches the .NET `PqHybridEncryptor` on-disk output
/// (encryption is randomized, so the bytes differ run to run but decrypt identically either way).
fn encrypt_hybrid_inner(data: &[u8], recipients: &[&[u8]]) -> Result<Vec<u8>, PqError> {
    if recipients.is_empty() {
        return Err(PqError::Format("at least one recipient is required"));
    }
    if recipients.len() > u8::MAX as usize {
        return Err(PqError::Format("too many recipients"));
    }

    let mut cek = [0u8; KEY_LEN];
    random_bytes(&mut cek);
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    random_bytes(&mut nonce_prefix);

    let (key_source, key_params) = if recipients.len() == 1 {
        (KEYSOURCE_HYBRID, wrap_to_recipient(recipients[0], &cek)?)
    } else {
        // KeySource 4 body: Count(1) then Count × (Mode(1) | BlockLength(2 BE) | block).
        let mut body = Vec::with_capacity(1 + recipients.len() * (3 + HYBRID_BLOCK_LEN));
        body.push(recipients.len() as u8);
        for recipient in recipients {
            let block = wrap_to_recipient(recipient, &cek)?;
            body.push(MODE_HYBRID);
            body.extend_from_slice(&(block.len() as u16).to_be_bytes());
            body.extend_from_slice(&block);
        }
        (KEYSOURCE_MULTI, body)
    };

    // The whole KeyParams block must fit the header's uint16 length field (FILE-FORMAT.md).
    if key_params.len() > u16::MAX as usize {
        return Err(PqError::Format(
            "too many recipients for the container header",
        ));
    }

    let header = build_header(key_source, DEFAULT_CHUNK, &nonce_prefix, &key_params);
    Ok(encrypt_frames(
        &header,
        &nonce_prefix,
        &cek,
        DEFAULT_CHUNK,
        data,
    ))
}

/// Generates a fresh hybrid recipient key pair, returning `(public_key, private_key)` in the
/// same encodings the .NET library uses: public = `X25519(32) ‖ ML-KEM-ek(1184)` (1216 bytes),
/// private = `X25519(32) ‖ ML-KEM-dk(2400)` (2432 bytes). The two implementations interoperate
/// on generated keys: FIPS 203 and RFC 7748 encodings are standard, so a key made on either side
/// is usable by the other (exercised by the interop CI job).
pub fn generate_hybrid_keypair() -> (Vec<u8>, Vec<u8>) {
    use x25519_dalek::{PublicKey, StaticSecret};

    let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut GetrandomRng);
    let mut x25519_sk = [0u8; 32];
    random_bytes(&mut x25519_sk);
    let secret = StaticSecret::from(x25519_sk);
    let public = PublicKey::from(&secret);

    let mut public_key = Vec::with_capacity(HYBRID_PUBLIC_KEY_LEN);
    public_key.extend_from_slice(public.as_bytes());
    public_key.extend_from_slice(&ek.to_bytes());

    let mut private_key = Vec::with_capacity(HYBRID_PRIVATE_KEY_LEN);
    private_key.extend_from_slice(&secret.to_bytes());
    // expanded (2400-byte) encoding, not the 64-byte seed — see mlkem_decapsulate
    private_key.extend_from_slice(&dk.to_expanded_bytes());

    debug_assert_eq!(public_key.len(), HYBRID_PUBLIC_KEY_LEN);
    debug_assert_eq!(private_key.len(), HYBRID_PRIVATE_KEY_LEN);
    (public_key, private_key)
}

/// Encrypts `data` to a single hybrid recipient (`X25519(32) ‖ ML-KEM-ek(1184)` public key,
/// 1216 bytes — `PqHybridPublicKey.Export()` bytes), producing a KeySource-3 `.pqfe` container.
pub fn encrypt_bytes_hybrid(data: &[u8], recipient_public_key: &[u8]) -> Result<Vec<u8>, PqError> {
    encrypt_hybrid_inner(data, &[recipient_public_key])
}

/// Encrypts `data` to several hybrid recipients (any one of whose private keys opens it),
/// producing a KeySource-4 `.pqfe` container.
pub fn encrypt_bytes_hybrid_multi(
    data: &[u8],
    recipient_public_keys: &[&[u8]],
) -> Result<Vec<u8>, PqError> {
    encrypt_hybrid_inner(data, recipient_public_keys)
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
