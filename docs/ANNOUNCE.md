# Announcing PostQuantum.FileEncryption 1.0

> A draft announcement post — publish-anywhere format. Trim to taste before posting to
> dev.to, Hashnode, Microsoft Learn, a personal blog, or LinkedIn. The companion
> [docs/DISCOVERABILITY.md](DISCOVERABILITY.md) lists the awesome-* lists and feeds worth
> filing alongside it.

---

## Encrypting a file in .NET should be three lines and never bite you

Most file encryption code in the wild looks confident and is quietly wrong.

It mixes up nonces. It writes the IV into the file *next to* the ciphertext as if that
made it tamper-resistant. It uses CBC and bolts on an HMAC after a coffee. It calls
`PBKDF2` with 1,000 iterations because the docs example did, in 2008. It catches
`CryptographicException` and rethrows as `string.Empty`. It tells you exactly which kind
of authentication failed, because a helpful error message is the right thing to do — except
when it isn't, because now you have a padding oracle.

I wanted a library where calling the obvious method gave you the right answer. Not because
the caller carefully read the spec, but because the API didn't offer a wrong path. That's
the small bet behind **PostQuantum.FileEncryption** — a high-level, fail-closed file and
stream encryptor for .NET 10.

```csharp
using PostQuantum.FileEncryption;

await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", "correct horse battery staple");
await new PqFileDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.restored.pdf", "correct horse battery staple");
```

That's the entire happy path. Chunked authenticated streaming, atomic file output, a unique
content key per file, AAD that binds the header and the chunk ordinal, and a
`PqDecryptionException` that says exactly nothing about *why* it failed — because attackers
are the loudest consumers of helpful error messages.

## What's actually in the box

- **AES-256-GCM** end-to-end, chunked. AES-256 keeps your data confidential against a
  harvest-now-decrypt-later quantum adversary (≈128-bit security under Grover) — so the
  *data plane* is post-quantum aware today.
- **PBKDF2-HMAC-SHA256** (default, OWASP 600k iterations) or **Argon2id** (memory-hard).
  Pick one with `PqEncryptionOptions.Argon2id`; decryption picks itself up from the header.
- **Hybrid public-key encryption** via the companion `PostQuantum.FileEncryption.Hybrid`
  package — X25519 *and* ML-KEM-768 combined, multi-recipient, so the content key stays
  safe if either primitive is later broken.
- **Envelope encryption seam** (`IContentKeyProvider`) so your KMS or HSM can hold the
  master key. The library ships with a built-in `LocalKekContentKeyProvider`; AWS KMS,
  Azure Key Vault, and HashiCorp Vault adapters belong in separate packages.
- **Frozen format.** `.pqfe` v2 is pinned for the entire `1.x` line by published
  conformance vectors, cross-checked against a Rust → WebAssembly reference
  implementation. A file you encrypt today opens with every `1.x` build, anywhere.

## What's *not* in the box, on purpose

This is the part most crypto libraries skip. The
[Known Gaps](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/KNOWN-GAPS.md)
ledger is honest:

- The library is **not independently audited**. Funded engagements are welcome.
- **Metadata is not hidden** — approximate plaintext size, file names, and timestamps are
  not protected. Encrypted file names and length-hiding padding are candidates for `2.0`.
- **String passphrases** linger in managed memory; the `ReadOnlyMemory<byte>` and
  `ReadOnlySpan<char>` overloads exist so you can choose the secret's lifetime.
- The legacy inline ML-KEM-only recipient mode is **deprecated** (`PQFE002`) — use the
  Hybrid package.

If a security claim is on the README, there's a test for it; if there isn't a test,
[the ledger](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/KNOWN-GAPS.md)
says so out loud.

## The trust spine

A cryptographic library earns trust slowly. The `1.0` release tries to make that easier:

- **CycloneDX SBOMs** and **SLSA-style build-provenance attestations** on every release.
- **Reproducible builds** — a recipe and a CI job that rebuilds the tagged source on a
  clean machine and proves it matches the `.nupkg` on nuget.org, modulo signatures.
- **Locked public API** via `Microsoft.CodeAnalysis.PublicApiAnalyzers` baselines and
  `<EnablePackageValidation>` against the previous published version. Accidental breakage
  fails the build.
- **Continuous fuzzing** on both the .NET and Rust → WASM parsers (cargo-fuzz + SharpFuzz),
  nightly, with cached corpora. OSS-Fuzz integration files are ready upstream.
- **A published [threat model](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/THREAT-MODEL.md)** that says what an audit should focus on.

## Try it

```bash
dotnet add package PostQuantum.FileEncryption --version 1.0.0
# Add this only if you need public-key (recipient) encryption:
dotnet add package PostQuantum.FileEncryption.Hybrid --version 1.0.0
```

A tiny CLI sample at
[`samples/Pqfe.Cli`](https://github.com/systemslibrarian/postquantum-file-encryption/tree/main/samples/Pqfe.Cli)
is also the AOT canary. A fully client-side browser demo backed by a Rust → WebAssembly
re-implementation of the format lives at
[`samples/pqfe-web`](https://github.com/systemslibrarian/postquantum-file-encryption/tree/main/samples/pqfe-web)
— files never leave the page.

The repository is MIT-licensed and lives at
**[github.com/systemslibrarian/postquantum-file-encryption](https://github.com/systemslibrarian/postquantum-file-encryption)**.
Issues, security advisories, and funded audit engagements all welcome.

---

*To God be the glory — 1 Corinthians 10:31.*
