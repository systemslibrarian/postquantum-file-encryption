//! Cross-implementation conformance: the Rust core runs the *same committed vector corpus* as the
//! .NET `ConformanceManifestTests` (`test-vectors/manifest.json`). Positive and lenient vectors must
//! decrypt to the stated plaintext; every negative vector must be rejected. This proves the two
//! independent implementations agree on exactly what a conforming `.pqfe` v2 reader accepts and
//! rejects — including the frozen v2 reader leniencies (nonzero reserved `Flags`, trailing bytes in
//! passphrase `KeyParams`, trailing bytes after the final frame, and trailing blocks past a
//! multi-recipient count), which both readers must continue to accept for the whole `1.x` line.
//!
//! The expectations mirror the manifest inline (the corpus is frozen, so the values do not drift);
//! `test-vectors/README.md` documents the manifest as the machine-readable index.

use pqfe_wasm::{decrypt_bytes, decrypt_bytes_hybrid};
use std::path::PathBuf;

const PASSPHRASE: &[u8] = b"test-vector-passphrase";
const KAT_PLAINTEXT: &[u8] = b"PostQuantum.FileEncryption known-answer vector v2.";

fn read(rel: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn accept(rel: &str, passphrase: &[u8], expected: &[u8]) {
    let plaintext =
        decrypt_bytes(&read(rel), passphrase).unwrap_or_else(|e| panic!("{rel} must decrypt: {e:?}"));
    assert_eq!(plaintext, expected, "{rel} plaintext");
}

// A conforming reader must reject these. We assert `Err` rather than a specific `PqError` variant:
// the format-vs-decryption split is an error-*type* nicety (oracle avoidance), while the hard,
// cross-implementation contract is simply that the file fails closed.
fn reject(rel: &str, passphrase: &[u8]) {
    assert!(
        decrypt_bytes(&read(rel), passphrase).is_err(),
        "{rel} must be rejected"
    );
}

#[test]
fn positive_vectors_decrypt() {
    accept("passphrase-pbkdf2.pqfe", PASSPHRASE, KAT_PLAINTEXT);
    accept("passphrase-argon2id.pqfe", PASSPHRASE, KAT_PLAINTEXT);
    accept(
        "passphrase-pbkdf2-rustcore.pqfe",
        b"cross-impl-passphrase",
        b"Encrypted by the Rust/WASM core, decrypted by .NET.",
    );
}

#[test]
fn lenient_corners_are_accepted() {
    // Frozen v2 reader leniencies (docs/CONFORMANCE.md 2.2) — the Rust core mirrors each.
    accept(
        "lenient/nonzero-flags.pqfe",
        PASSPHRASE,
        b"PostQuantum.FileEncryption conformance: reserved Flags byte set to 0x01.",
    );
    accept(
        "lenient/trailing-keyparams.pqfe",
        PASSPHRASE,
        b"PostQuantum.FileEncryption conformance: trailing bytes in passphrase KeyParams.",
    );
    accept("lenient/trailing-after-final.pqfe", PASSPHRASE, KAT_PLAINTEXT);

    // KeySource-4 body with a block past the declared count: consumed-and-ignored.
    let container = read("lenient/multi-recipient-trailing.pqfe");
    let key = read("lenient/multi-recipient-trailing.key");
    let plaintext =
        decrypt_bytes_hybrid(&container, &key).expect("multi-recipient trailing vector must decrypt");
    assert_eq!(
        plaintext,
        b"PostQuantum.FileEncryption conformance: trailing block past the multi-recipient count."
    );
}

#[test]
fn negative_vectors_are_rejected() {
    for rel in [
        "negative/bad-magic.pqfe",
        "negative/bad-version.pqfe",
        "negative/unknown-aead.pqfe",
        "negative/unknown-keysource.pqfe",
        "negative/chunksize-zero.pqfe",
        "negative/pbkdf2-iterations-out-of-range.pqfe",
        "negative/header-tamper.pqfe",
        "negative/ciphertext-tamper.pqfe",
        "negative/tag-truncated.pqfe",
        "negative/prefix-truncated.pqfe",
        "negative/not-a-container.bin",
    ] {
        reject(rel, PASSPHRASE);
    }

    // The frozen positive vector, opened with the wrong passphrase, must also fail closed.
    reject("passphrase-pbkdf2.pqfe", b"wrong-passphrase");
}
