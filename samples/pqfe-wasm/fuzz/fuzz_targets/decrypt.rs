#![no_main]
//! Coverage-guided fuzzing of the `.pqfe` container parser. The contract: `decrypt_bytes` must
//! **never panic** on arbitrary input — it either returns the plaintext or a `PqError`. The
//! fuzzer drives libFuzzer to find any input that violates that (a crash, overflow, or hang).
//!
//! Run (needs nightly + cargo-fuzz: `cargo install cargo-fuzz`):
//!   cd samples/pqfe-wasm && cargo +nightly fuzz run decrypt

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The result is intentionally ignored; we only care that this returns rather than panics.
    let _ = pqfe_wasm::decrypt_bytes(data, b"fuzz-passphrase");
});
