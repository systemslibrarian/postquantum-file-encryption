# Quickstart: folder backup encryption

The smallest complete backup-encryption program that still does everything right: runtime
passphrase, Argon2id key derivation, atomic outputs, cooperative Ctrl+C, fail-closed error
handling, scriptable exit codes.

```bash
export PQFE_PASS='a passphrase with real entropy'   # Windows: set PQFE_PASS=...
dotnet run -- encrypt ~/documents ~/backup-staging
dotnet run -- decrypt ~/backup-staging ~/restored
```

Start here, then graduate to [docs/COOKBOOK.md](../../../docs/COOKBOOK.md) (recipes 1, 2,
and 9 explain every choice this program makes) and
[docs/ANTI-PATTERNS.md](../../../docs/ANTI-PATTERNS.md) (the shapes it deliberately avoids).

In your own project, reference the packages instead of the project:

```bash
dotnet add package PostQuantum.FileEncryption
dotnet add package PostQuantum.FileEncryption.Analyzers   # compile-time misuse checks
```

*To God be the glory — 1 Corinthians 10:31.*
