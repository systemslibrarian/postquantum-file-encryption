//! Conformance tests: the Rust core must decrypt the exact same known-answer vectors used by
//! the .NET test suite (`tests/.../KnownAnswerVectorTests.cs`). This is what keeps the two
//! independent implementations byte-compatible with the `.pqfe` v2 format.

use base64::Engine;
use pqfe_wasm::{decrypt_bytes, encrypt_bytes, PqError};

const PASSPHRASE: &[u8] = b"test-vector-passphrase";
const EXPECTED: &[u8] = b"PostQuantum.FileEncryption known-answer vector v2.";

// KeySource = passphrase, KDF = PBKDF2-HMAC-SHA256 (100,000 iters), 16-byte salt, 1 KiB chunks.
const PBKDF2_VECTOR: &str =
    "UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj";

// KeySource = passphrase, KDF = Argon2id (8 MiB, 1 pass, 1 lane), 16-byte salt, 1 KiB chunks.
const ARGON2_VECTOR: &str =
    "UFFGRQIBAQAAAAQAS7aXNQAbAhCZBPTffR0AgJ7we1bozxQOAAAgAAAAAAEBAQAAADJOzagbj5vUN9WHVWy1t7KN/pG9O5ab04z0IO4xyV5vRMxDN2TsXQGStrNyW5eC77skRpx0WhB0BC6SxsnfnwherIM=";

fn decode(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

#[test]
fn decrypts_dotnet_pbkdf2_vector() {
    let container = decode(PBKDF2_VECTOR);
    let plaintext = decrypt_bytes(&container, PASSPHRASE).expect("PBKDF2 vector must decrypt");
    assert_eq!(plaintext, EXPECTED);
}

#[test]
fn decrypts_dotnet_argon2id_vector() {
    let container = decode(ARGON2_VECTOR);
    let plaintext = decrypt_bytes(&container, PASSPHRASE).expect("Argon2id vector must decrypt");
    assert_eq!(plaintext, EXPECTED);
}

#[test]
fn wrong_passphrase_fails_closed() {
    let container = decode(PBKDF2_VECTOR);
    assert_eq!(decrypt_bytes(&container, b"wrong"), Err(PqError::Decryption));
}

#[test]
fn round_trip_small_and_multichunk() {
    for size in [0usize, 1, 100, 64 * 1024, 64 * 1024 + 5, 200_000] {
        let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
        let container = encrypt_bytes(&data, b"a-good-passphrase");
        let restored = decrypt_bytes(&container, b"a-good-passphrase").expect("round-trip");
        assert_eq!(restored, data, "round-trip failed for size {size}");
    }
}

#[test]
fn tampering_is_detected() {
    let data = b"some confidential bytes";
    let mut container = encrypt_bytes(data, b"a-good-passphrase");
    let last = container.len() - 1;
    container[last] ^= 0xFF; // flip a bit in the final tag
    assert_eq!(decrypt_bytes(&container, b"a-good-passphrase"), Err(PqError::Decryption));
}

#[test]
fn truncation_is_detected() {
    let data = vec![42u8; 5000];
    let container = encrypt_bytes(&data, b"a-good-passphrase");
    let truncated = &container[..container.len() - 20];
    assert_eq!(decrypt_bytes(truncated, b"a-good-passphrase"), Err(PqError::Decryption));
}

#[test]
fn non_container_is_format_error() {
    let garbage = vec![0u8; 64];
    assert!(matches!(decrypt_bytes(&garbage, PASSPHRASE), Err(PqError::Format(_))));
}
