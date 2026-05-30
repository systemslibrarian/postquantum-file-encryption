# Contributing

Thanks for your interest in PostQuantum.FileEncryption. This is security-sensitive software, so
contributions are held to a high bar — but that bar is mostly about discipline, not cleverness.

## Before you start

- **Security issues are different.** Do **not** open a public issue or PR for a vulnerability.
  Follow [SECURITY.md](SECURITY.md) for private disclosure.
- For features, please open an issue first so we can agree on the design — especially anything
  touching the container format or cryptography.

## Ground rules (non-negotiable)

These mirror [CLAUDE.md](CLAUDE.md), the project's working conventions:

1. **No homegrown cryptography.** Use platform primitives (`System.Security.Cryptography`) or a
   vetted library. Never invent a construction.
2. **Authenticated encryption only**, and **fail closed** — on any doubt about authenticity,
   throw and emit no plaintext. No error oracles.
3. **Transparency over reassurance.** New limitations go in [KNOWN-GAPS.md](KNOWN-GAPS.md). Any
   on-disk change updates [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) **and** bumps
   `FormatVersion` in the same change.
4. **Tests are part of the change.** Add or extend fail-closed tests (tamper, truncate, wrong
   key, bad format) alongside happy-path tests. If you change the format, add a known-answer
   vector and keep the .NET ↔ Rust cross-check green.

## Building and testing

```bash
dotnet build -c Release       # warnings are errors
dotnet test  -c Release       # 70+ tests
cd samples/pqfe-wasm && cargo test   # Rust conformance (decrypts the .NET vectors, byte-exact)
```

CI runs both suites on Ubuntu and Windows, plus CodeQL and a dependency audit. PRs must pass.

## Style

- Match the surrounding code: nullable enabled, full XML docs on public API, `ConfigureAwait(false)`
  on library awaits, key material zeroed in `finally`.
- Keep the public surface minimal; new knobs usually belong on `PqEncryptionOptions`.

## Submitting

- Branch, commit with clear messages, and open a PR against `main` using the template.
- For anything security-relevant, call it out explicitly so it gets the review it needs.

*To God be the glory — 1 Corinthians 10:31.*
