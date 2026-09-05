#!/bin/bash -eu
# OSS-Fuzz build script: builds the Rust fuzz target and stages it in $OUT.

cd "$SRC/postquantum-file-encryption/samples/pqfe-wasm"

# OSS-Fuzz provides the sanitizer/engine flags; cargo-fuzz honors them.
cargo fuzz build -O

TARGET_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
cp "$TARGET_DIR/decrypt" "$OUT/decrypt"
cp "$TARGET_DIR/decrypt_hybrid" "$OUT/decrypt_hybrid"

# Seed corpora: the committed known-answer vectors give both targets valid containers to
# mutate from the first iteration (the hybrid target's seed matches its compiled-in key).
zip -j "$OUT/decrypt_seed_corpus.zip" fuzz/seed-corpus/*.pqfe
zip -j "$OUT/decrypt_hybrid_seed_corpus.zip" fuzz/seed-corpus/*.pqfe
