#!/bin/bash -eu
# OSS-Fuzz build script: builds the Rust fuzz target and stages it in $OUT.

cd "$SRC/postquantum-file-encryption/samples/pqfe-wasm"

# OSS-Fuzz provides the sanitizer/engine flags; cargo-fuzz honors them.
cargo fuzz build -O

FUZZ_TARGET_BIN="fuzz/target/x86_64-unknown-linux-gnu/release/decrypt"
cp "$FUZZ_TARGET_BIN" "$OUT/decrypt"
