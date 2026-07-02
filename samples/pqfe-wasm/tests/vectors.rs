//! Conformance tests: the Rust core must decrypt the exact same known-answer vectors used by
//! the .NET test suite (`tests/.../KnownAnswerVectorTests.cs`). This is what keeps the two
//! independent implementations byte-compatible with the `.pqfe` v2 format.

use base64::Engine;
use pqfe_wasm::{decrypt_bytes, encrypt_bytes, encrypt_bytes_with, PqError};

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

// Multi-chunk vector (TEST-VECTORS.md): 3,000 bytes at 1 KiB chunks — two data frames plus a
// final frame, so the per-chunk nonce counter and AAD chaining are pinned cross-implementation
// (the single-chunk vectors never exercise them). Plaintext byte i is (i * 31 + 7) & 0xFF.
const MULTICHUNK_VECTOR: &str =
    "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";

#[test]
fn decrypts_dotnet_multichunk_vector() {
    let container = decode(MULTICHUNK_VECTOR);
    let plaintext =
        decrypt_bytes(&container, PASSPHRASE).expect("multi-chunk vector must decrypt");
    let expected: Vec<u8> = (0..3000usize).map(|i| (i * 31 + 7) as u8).collect();
    assert_eq!(plaintext, expected);
}

// The PQKF v1 encrypted key file (docs/KEY-FILE-FORMAT.md, TEST-VECTORS.md Vector 5): a
// 5-byte framing (`PQKF` + version) around a standard v2 passphrase container whose plaintext
// is KeyType(1) ‖ private-key bytes. The Rust core has no key-file API — this test proves the
// embedded container is a plain conforming v2 container, which is the format's whole claim.
const PQKF_VECTOR: &str =
    "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";

const PQKF_EXPECTED_PRIVATE_KEY: &str =
    "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";

#[test]
fn decrypts_dotnet_pqkf_key_file_body() {
    let key_file = decode(PQKF_VECTOR);
    assert_eq!(&key_file[..4], b"PQKF", "PQKF magic");
    assert_eq!(key_file[4], 1, "PQKF version");

    let plaintext = decrypt_bytes(&key_file[5..], b"key-file-vector-passphrase")
        .expect("PQKF embedded container must decrypt as a plain v2 container");

    let expected_key = decode(PQKF_EXPECTED_PRIVATE_KEY);
    assert_eq!(plaintext[0], 1, "KeyType: hybrid recipient private key");
    assert_eq!(&plaintext[1..], &expected_key[..]);
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

/// Byte-exact cross-check: with a fixed salt and nonce prefix, the Rust core must produce the
/// identical container the .NET library does (see DeterministicVectorTests.cs).
#[test]
fn deterministic_output_matches_dotnet() {
    let salt: Vec<u8> = (0u8..16).collect();
    let nonce_prefix = [0xA1u8, 0xB2, 0xC3, 0xD4];
    let container = encrypt_bytes_with(
        b"Deterministic conformance vector - byte for byte.",
        b"deterministic-conformance",
        &salt,
        &nonce_prefix,
        120_000,
        1024,
    );
    let expected = "UFFGRQIBAQAAAAQAobLD1AAWARAAAQIDBAUGBwgJCgsMDQ4PAAHUwAEAAAAx8LbT/vUWhAJzxG27tIWQK9TfelTH70vWt+4CuWNvi58E0J1kT46rSZnQgLQx7ndsXtTEuK5a8PFd/Geog1+9mN4=";
    assert_eq!(base64::engine::general_purpose::STANDARD.encode(&container), expected);
}
