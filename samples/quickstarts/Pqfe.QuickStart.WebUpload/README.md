# Quickstart: encrypted uploads in ASP.NET Core

A minimal upload endpoint that encrypts each file *as it streams in*, to a recipient public
key. The property worth copying: the web server holds no decryption capability at all — a
fully compromised server can add files but cannot read any of them.

```bash
dotnet run
curl -F "file=@report.pdf" http://localhost:5000/upload
```

The first run generates a demo key pair so the sample works out of the box; in production
the key pair is generated offline (`pqfe keygen --encrypt`) and only the public half is
deployed. See [docs/COOKBOOK.md](../../../docs/COOKBOOK.md) recipes 3 and 6 for the full
pattern, including decrypt-side resource limits for user-supplied containers.

In your own project, reference the packages instead of the projects:

```bash
dotnet add package PostQuantum.FileEncryption.Hybrid
dotnet add package PostQuantum.FileEncryption.Analyzers   # compile-time misuse checks
```

*To God be the glory — 1 Corinthians 10:31.*
