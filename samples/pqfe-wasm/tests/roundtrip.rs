//! Round-trip (encode ↔ decode) property coverage for the Rust core.
//!
//! The pinned known-answer vectors ([`vectors.rs`]) prove the format is read *correctly*, and
//! the CI interop harness proves .NET and Rust agree on a handful of fixed sizes. Neither
//! sweeps the framing surface: the per-chunk nonce counter, the AAD chaining, and the
//! final-frame marker are all functions of `(chunk_size, data_len)`, and the bug they hide —
//! producing a container the *same* implementation cannot read back — is invisible to a fixed
//! vector. This test drives every interesting boundary of that surface: for each chunk size,
//! data lengths straddling one, two, and three chunks, plus the empty and single-byte cases.
//!
//! Every case must satisfy `decrypt(encrypt(x)) == x`; a mismatch or error means the encode and
//! decode halves disagree — exactly the asymmetry a round-trip check exists to catch.

use pqfe_wasm::{
    decrypt_bytes, decrypt_bytes_hybrid, encrypt_bytes_hybrid, encrypt_bytes_hybrid_multi,
    encrypt_bytes_with, generate_hybrid_keypair, PqError,
};

const PASSPHRASE: &[u8] = b"round-trip-property-passphrase";
// The format's PBKDF2 floor; kept at the minimum so the framing matrix stays cheap.
const ITERS: u32 = 100_000;
// A fixed salt and nonce prefix keep the test deterministic — this exercises framing, not
// key derivation (the KATs pin the derivation).
const SALT: &[u8] = b"0123456789abcdef";
const NONCE_PREFIX: &[u8] = b"\x00\x01\x02\x03";

/// A deterministic, non-trivial byte pattern of the given length (position-dependent so a
/// chunk-ordering bug corrupts the comparison rather than happening to match).
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) & 0xFF) as u8).collect()
}

fn assert_round_trips(data: &[u8], chunk_size: u32) {
    let container = encrypt_bytes_with(data, PASSPHRASE, SALT, NONCE_PREFIX, ITERS, chunk_size);
    let recovered = decrypt_bytes(&container, PASSPHRASE).unwrap_or_else(|e| {
        panic!(
            "chunk {chunk_size}, len {}: decrypt failed: {e:?}",
            data.len()
        )
    });
    assert_eq!(
        recovered,
        data,
        "chunk {chunk_size}, len {}: recovered plaintext differs from input",
        data.len()
    );
}

#[test]
fn round_trips_across_the_framing_matrix() {
    // MIN_CHUNK, a small non-power-of-two, and the default 64 KiB.
    for &chunk in &[1024u32, 1500, 64 * 1024] {
        let c = chunk as usize;
        // Lengths straddling the empty case, the first chunk boundary, and multi-chunk.
        let lengths = [
            0,
            1,
            c - 1,
            c,
            c + 1,
            2 * c - 1,
            2 * c,
            2 * c + 1,
            3 * c + 7,
        ];
        for &len in &lengths {
            assert_round_trips(&pattern(len), chunk);
        }
    }
}

#[test]
fn tampering_with_any_frame_byte_fails_closed() {
    // A round-trip that authenticates is only half the contract; the other half is that a
    // single flipped byte anywhere never decrypts. Walk the whole container at a coarse stride
    // (fine enough to hit the header, every frame's ciphertext, and every tag).
    let data = pattern(3 * 1024 + 7); // multi-chunk at MIN_CHUNK
    let mut container = encrypt_bytes_with(&data, PASSPHRASE, SALT, NONCE_PREFIX, ITERS, 1024);
    let original = container.clone();

    for i in (0..container.len()).step_by(17) {
        container[i] ^= 0x01;
        assert!(
            decrypt_bytes(&container, PASSPHRASE).is_err(),
            "flipping byte {i} still decrypted — fail-closed violation"
        );
        container[i] = original[i];
    }
}

#[test]
fn hybrid_single_recipient_round_trips() {
    let (public_key, private_key) = generate_hybrid_keypair();
    // Straddle the empty case and the 64 KiB default chunk boundary.
    for &len in &[0usize, 1, 100, 64 * 1024, 64 * 1024 + 5, 200_000] {
        let data = pattern(len);
        let container = encrypt_bytes_hybrid(&data, &public_key).expect("hybrid encrypt");
        let restored = decrypt_bytes_hybrid(&container, &private_key)
            .unwrap_or_else(|e| panic!("len {len}: hybrid round-trip failed: {e:?}"));
        assert_eq!(restored, data, "len {len}: hybrid round-trip mismatch");
    }
}

#[test]
fn hybrid_multi_recipient_round_trips_for_each_recipient() {
    let keys: Vec<_> = (0..3).map(|_| generate_hybrid_keypair()).collect();
    let publics: Vec<&[u8]> = keys.iter().map(|(pk, _)| pk.as_slice()).collect();
    let data = pattern(70_000); // multi-chunk

    let container = encrypt_bytes_hybrid_multi(&data, &publics).expect("multi encrypt");

    // Every listed recipient — first, middle, and last — must recover the same plaintext.
    for (i, (_, private_key)) in keys.iter().enumerate() {
        let restored = decrypt_bytes_hybrid(&container, private_key)
            .unwrap_or_else(|e| panic!("recipient {i}: multi round-trip failed: {e:?}"));
        assert_eq!(restored, data, "recipient {i}: multi round-trip mismatch");
    }
}

#[test]
fn hybrid_round_trip_rejects_a_stranger_key() {
    let (public_key, _) = generate_hybrid_keypair();
    let (_, stranger_private) = generate_hybrid_keypair();
    let container = encrypt_bytes_hybrid(b"secret", &public_key).expect("hybrid encrypt");
    assert_eq!(
        decrypt_bytes_hybrid(&container, &stranger_private),
        Err(PqError::Decryption),
        "a key that is not a recipient must fail closed"
    );
}

#[test]
fn truncation_at_every_length_fails_closed() {
    // Every proper prefix of a valid container must be rejected — the anti-truncation guarantee.
    let data = pattern(2 * 1024 + 100);
    let container = encrypt_bytes_with(&data, PASSPHRASE, SALT, NONCE_PREFIX, ITERS, 1024);

    for cut in (1..container.len()).step_by(29) {
        assert!(
            decrypt_bytes(&container[..cut], PASSPHRASE).is_err(),
            "a {cut}-byte prefix of a {}-byte container decrypted — truncation not detected",
            container.len()
        );
    }
}
