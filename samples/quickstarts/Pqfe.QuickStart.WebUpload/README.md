# Quickstart: encrypted uploads in ASP.NET Core

A minimal upload endpoint that encrypts each file *as it streams in*, to a recipient public
key. The property worth copying: **the web server holds no decryption capability at all** — a
fully compromised server can add files but cannot read any of them. This sample is built to
*keep* that property at runtime, not just claim it:

- **Plaintext never touches the server's disk.** The upload is parsed with `MultipartReader`
  and streamed straight into the encryptor — not through a buffered `IFormFile`, whose
  spool-to-temp-file behavior for larger uploads would land plaintext on disk.
- **The server never holds a private key.** It is generated offline and only the public half
  is deployed here. The app refuses to start without it — it never falls back to making one.
- **Output is atomic.** Ciphertext is staged to a `.partial` file and only moved into place
  once complete; any failure deletes the staged file, so an interrupted upload never leaves a
  half-written container.

## 1. Generate a recipient identity — offline

Do this on a trusted machine, **not** the web server. The private key stays with whoever will
decrypt uploads; only `me.pub` is deployed with the app.

```bash
# PQFE_PASS protects the encrypted private-key file; omit it to be prompted.
PQFE_PASS='choose-a-strong-passphrase' \
  dotnet run --project ../Pqfe.QuickStart.WebUpload.Keygen -- ./me.pub ./me.key
```

`me.key` is a passphrase-encrypted `PQKF` file (see
[docs/KEY-FILE-FORMAT.md](../../../docs/KEY-FILE-FORMAT.md)); `me.pub` is the raw hybrid public
key the server encrypts to.

## 2. Run the upload service

```bash
# me.pub must be present. Point at it explicitly, or drop it in the content root.
Pqfe__RecipientPublicKeyPath=./me.pub dotnet run
curl -F "file=@report.pdf" http://localhost:5000/upload
```

The encrypted container lands under `encrypted-uploads/` (override with
`Pqfe__StorageRoot`). To read it back, decrypt on the machine that holds `me.key` — see
[docs/COOKBOOK.md](../../../docs/COOKBOOK.md) recipes 3 and 6, including decrypt-side resource
limits for user-supplied containers.

## What proves it

The integration test (`tests/Pqfe.QuickStart.WebUpload.Tests`) uploads a payload above the
64 KiB form-buffer threshold, confirms the stored bytes are a real `.pqfe` container that
**only the private key** opens, that a stranger key fails closed, and that a file-less request
is rejected with nothing written.

In your own project, reference the packages instead of the projects:

```bash
dotnet add package PostQuantum.FileEncryption.Hybrid
dotnet add package PostQuantum.FileEncryption.Analyzers   # compile-time misuse checks
```

*To God be the glory — 1 Corinthians 10:31.*
