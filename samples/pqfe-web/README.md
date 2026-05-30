# PostQuantum.FileEncryption — Browser Demo (Rust → WebAssembly)

A **fully client-side** encrypt/decrypt demo. Your file never leaves the browser: a small
Rust core compiled to WebAssembly performs passphrase-based **AES-256-GCM** locally.

It is an independent re-implementation of the [`.pqfe` v2 format](../../docs/FILE-FORMAT.md)
in [`samples/pqfe-wasm`](../pqfe-wasm), kept **byte-compatible** with the .NET library:

- the Rust crate's tests decrypt the same known-answer vectors the .NET test suite uses, and
- the .NET test suite decrypts a container produced by this Rust core
  (`CrossImplementationTests`).

So a file encrypted here opens with the .NET library, and vice versa. Only the **passphrase**
key source is implemented in the browser; ML-KEM recipient mode is .NET-only.

## Run it locally

You need the [Rust toolchain](https://rustup.rs) and
[`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).

```bash
# from this folder
rustup target add wasm32-unknown-unknown
wasm-pack build ../pqfe-wasm --target web --release --out-dir ../pqfe-web/pkg

# serve the static files (any static server works)
python3 -m http.server 8080
# open http://localhost:8080
```

That's it — there is no server-side component. The same static files are what the
[GitHub Pages workflow](../../.github/workflows/pages.yml) publishes.

## Verify the core

```bash
cd ../pqfe-wasm && cargo test          # decrypts the .NET vectors + round-trip + fail-closed
```

---

*To God be the glory — 1 Corinthians 10:31.*
