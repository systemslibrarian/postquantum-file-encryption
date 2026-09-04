#![no_main]
// Fuzzes the hybrid (KeySource 3/4) decrypt path. The passphrase target cannot reach it:
// decrypt_bytes returns Unsupported for these key sources right after the header parse, so
// try_unwrap_block / unwrap_multi — manual offset arithmetic over hostile bytes — had zero
// coverage-guided fuzzing. Using the pinned multi-recipient conformance key (its container is
// in the seed corpus) lets the fuzzer reach the unwrap-SUCCESS branch and the post-unwrap
// frame loop, not just the parse-and-reject paths.
use libfuzzer_sys::fuzz_target;

const PRIVATE_KEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../test-vectors/lenient/multi-recipient-trailing.key"
));

fuzz_target!(|data: &[u8]| {
    let _ = pqfe_wasm::decrypt_bytes_hybrid(data, PRIVATE_KEY);
});
