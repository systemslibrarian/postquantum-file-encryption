# PostQuantum.FileEncryption.Analyzers

Roslyn analyzers that catch dangerous misuse of the
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption) family
**at compile time** — in the IDE, before the mistake ships.

Real-world encryption failures overwhelmingly come from *misuse*, not broken primitives. The
library's API is fail-closed by design; these rules extend that discipline to the calling code.

```bash
dotnet add package PostQuantum.FileEncryption.Analyzers --version 1.7.0
```

A development-only dependency: nothing is added to your runtime output or your users'
dependency graph.

## The rules

| Rule | Severity | What it catches |
| --- | --- | --- |
| `PQFE101` | Warning | A **compile-time-constant passphrase** (literal or `const`) passed to any encrypt/decrypt/export API. A passphrase in source ships with every binary and lives in source control forever — the encryption then protects nothing against anyone who has either. |
| `PQFE102` | Warning | **Raw private-key bytes written to disk** — `File.WriteAllBytes(path, key.Export())`. `ExportEncrypted` exists for exactly this job: an authenticated, Argon2id-hardened key file that fails closed on a wrong passphrase or tampering. Public keys are exempt (they're public). |
| `PQFE103` | Warning | A **discarded encrypt/decrypt/sign/verify task**. Unlike the compiler's CS4014, this fires in synchronous methods too. A discarded task means the operation — and its *authentication* — may never complete, and its failure is never observed. An explicit `_ =` discard is treated as deliberate and not flagged. |
| `PQFE104` | Warning | A **silently swallowed fail-closed exception** — an empty `catch (PqDecryptionException)` / `PqSignatureException` / `PqEncryptionException` block. These exceptions are the library's signal that data is inauthentic or forged; an empty catch turns that hard stop into silent success. Probing with `catch (PqFormatException)` ("is this even a container?") is legitimate and exempt. |

Every rule links to the long-form reasoning in
[docs/ANTI-PATTERNS.md](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ANTI-PATTERNS.md).

## Design principles

- **High confidence over high coverage.** Each rule fires only on shapes that are almost
  certainly wrong; a quiet analyzer that is trusted beats a chatty one that gets disabled.
- **Escape hatches are explicit.** `#pragma warning disable PQFE10x` (or an `_ =` discard for
  PQFE103) records the decision in the code, where a reviewer can see it.
- **No runtime opinions.** The analyzers never change behavior; the library's fail-closed
  contract is enforced by the library itself. These rules just move the feedback earlier.

The rule IDs live in the `PQFE1xx` range; `PQFE0xx` is reserved for the library's own
`[Obsolete]` diagnostics.

*To God be the glory — 1 Corinthians 10:31.*
