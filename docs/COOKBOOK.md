# Cookbook

Complete, copy-paste-runnable recipes for the jobs people actually hire this library for.
Every recipe includes the failure handling done *right* — the safe pattern should be the easy
pattern. The inverse document, [ANTI-PATTERNS.md](ANTI-PATTERNS.md), shows the shapes to
avoid; the [analyzers package](https://www.nuget.org/packages/PostQuantum.FileEncryption.Analyzers)
catches several of them at compile time.

Packages used below:

```bash
dotnet add package PostQuantum.FileEncryption                # passphrase encryption (core)
dotnet add package PostQuantum.FileEncryption.Hybrid         # public-key (recipient) encryption
dotnet add package PostQuantum.FileEncryption.Signing        # detached signatures
dotnet add package PostQuantum.FileEncryption.Analyzers      # compile-time misuse checks
```

---

## 1. Encrypt and decrypt a file with a passphrase — done right

Progress, cancellation, and every failure case handled. The file APIs are atomic: on any
failure, nothing partial is left at the destination.

```csharp
using PostQuantum.FileEncryption;

static async Task<int> EncryptFileAsync(string inputPath, string outputPath, string passphrase,
    CancellationToken cancellationToken)
{
    var encryptor = new PqFileEncryptor(PqEncryptionOptions.Argon2id); // memory-hard KDF
    var progress = new Progress<PqProgress>(p =>
        Console.Error.Write($"\r{p.Fraction * 100:F0}%"));

    try
    {
        await encryptor.EncryptFileAsync(inputPath, outputPath, passphrase, progress, cancellationToken);
        return 0;
    }
    catch (FileNotFoundException)
    {
        Console.Error.WriteLine($"input not found: {inputPath}");
        return 66;
    }
    catch (OperationCanceledException)
    {
        // Nothing partial exists at outputPath — the temp file was cleaned up.
        return 130;
    }
}

static async Task<int> DecryptFileAsync(string inputPath, string outputPath, string passphrase,
    CancellationToken cancellationToken)
{
    try
    {
        await new PqFileDecryptor().DecryptFileAsync(inputPath, outputPath, passphrase, null, cancellationToken);
        return 0;
    }
    catch (PqFormatException)
    {
        Console.Error.WriteLine("not a .pqfe container");
        return 65;
    }
    catch (PqDecryptionException)
    {
        // Deliberately one message for wrong passphrase AND tampered/truncated bytes —
        // do not try to tell them apart, and never emit partial output.
        Console.Error.WriteLine("decryption failed: wrong passphrase, or the file was altered");
        return 65;
    }
}
```

Where does the passphrase come from? Never a string literal (`PQFE101` will flag it) — a
secret store, an environment variable scoped to the process, or an interactive prompt.

## 2. Decrypting files you didn't create — resource limits

A hostile container header can legally demand 2 GiB of Argon2id memory or a 16 MiB chunk
buffer *before anything authenticates*. If the input crosses a trust boundary (uploads,
email attachments, shared storage), cap what a header may demand:

```csharp
var decryptor = new PqFileDecryptor(PqDecryptionLimits.Untrusted);   // sane ceilings
// or tune your own:
var custom = new PqFileDecryptor(new PqDecryptionLimits
{
    MaxArgon2MemoryKiB = 64 * 1024,   // 64 MiB
    MaxPbkdf2Iterations = 1_000_000,
    MaxChunkSizeBytes = 1 * 1024 * 1024,
});
```

A header above a limit is rejected with `PqFormatException` before any allocation or KDF
work. The same parameter exists on `PqHybridDecryptor` and on
`ImportEncrypted` for key files. Files you encrypted yourself with default options always
open under `PqDecryptionLimits.Untrusted`.

## 3. Public-key (recipient) encryption with the Hybrid package

The sender needs only the recipient's *public* key; the recipient's private key never
travels. X25519 + ML-KEM-768 — an attacker must break both.

```csharp
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Hybrid;

// Recipient, once: generate a key pair; publish the public half, protect the private half.
using var keyPair = PqHybridKeyPair.Generate();
await File.WriteAllBytesAsync("me.pub", keyPair.PublicKey.Export());          // share freely
byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(passphrase);              // passphrase-protected
await File.WriteAllBytesAsync("me.key", keyFile);                             // PQKF format — safe at rest

// Sender: encrypt to the public key.
var recipient = PqHybridPublicKey.Import(await File.ReadAllBytesAsync("me.pub"));
await new PqHybridEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", recipient);

// Recipient: load the private key and decrypt.
using var privateKey = PqHybridPrivateKey.ImportEncrypted(
    await File.ReadAllBytesAsync("me.key"), passphrase);
await new PqHybridDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.pdf", privateKey);
```

Note what is *not* here: no raw `Export()` of the private key to disk (`PQFE102` flags it).
`ImportEncrypted` fails closed on a wrong passphrase or a tampered key file.

## 4. Encrypting for several recipients at once

One container, any listed recipient can open it with their own key:

```csharp
var recipients = new[] { alice, bob, carol };   // PqHybridPublicKey[]
await new PqHybridEncryptor().EncryptFileToAsync("minutes.docx", "minutes.docx.pqfe", recipients);
```

Removing someone's future access means re-encrypting for the new set — a container already
in their possession can't be un-shared (cryptography can't revoke what someone already has).

## 5. Sign, then verify — proving who produced a file

Detached Ed25519 + ML-DSA-65 signatures; both must verify.

```csharp
using PostQuantum.FileEncryption.Signing;

// Signer, once:
using var signingKeys = PqSigningKeyPair.Generate();
await File.WriteAllBytesAsync("release.pub", signingKeys.PublicKey.Export());
await File.WriteAllBytesAsync("release.key", signingKeys.PrivateKey.ExportEncrypted(passphrase));

// Sign (typically over a finished .pqfe container — encrypt-then-sign):
await new PqSigner().SignFileAsync("backup.pqfe", "backup.pqfe.sig", signingKeys.PrivateKey);

// Verifier — the public key must arrive over a channel you trust:
var publicKey = PqSigningPublicKey.Import(await File.ReadAllBytesAsync("release.pub"));
try
{
    await new PqVerifier().VerifyFileAsync("backup.pqfe", "backup.pqfe.sig", publicKey);
    // Only past this line are the bytes proven to come from the key holder.
}
catch (PqSignatureException)
{
    // Forged, altered, or signed by a different key — treat the file as untrusted.
    // (PQFE104 flags an empty catch here.)
    throw;
}
```

Order the pipeline **verify → then decrypt → then use**. Trust is anchored in *whose public
key you verify with* — a signature by itself proves nothing (see
[ANTI-PATTERNS.md](ANTI-PATTERNS.md) on strip-and-resign).

## 6. ASP.NET Core: encrypt uploads as they stream in

Encrypt the upload stream directly to storage — the plaintext never lands on disk. Constant
memory regardless of file size.

```csharp
app.MapPost("/upload", async (HttpRequest request, CancellationToken cancellationToken) =>
{
    IFormFile? file = (await request.ReadFormAsync(cancellationToken)).Files.FirstOrDefault();
    if (file is null)
    {
        return Results.BadRequest();
    }

    string storagePath = Path.Combine(storageRoot, $"{Guid.NewGuid():N}.pqfe");
    await using (Stream upload = file.OpenReadStream())
    await using (var output = File.Create(storagePath))
    {
        // recipientKey: PqHybridPublicKey loaded once at startup — the web server holds
        // no decryption capability at all. Decryption happens elsewhere, with the private key.
        await new PqHybridEncryptor().EncryptToAsync(
            upload, output, new[] { recipientKey }, file.Length, null, cancellationToken);
    }
    return Results.Ok();
});
```

The public-key design matters operationally: a compromised web server can *add* files but
cannot read any of them. For decryption endpoints serving user-supplied containers, use
`new PqHybridDecryptor(PqDecryptionLimits.Untrusted)` (recipe 2).

## 7. Envelope encryption with a KMS (AWS / Azure)

The master key lives in the KMS/HSM and never enters your process; each file gets a fresh
content key that the KMS wraps. Rotation re-wraps 32 bytes instead of re-encrypting terabytes.

```csharp
// dotnet add package PostQuantum.FileEncryption.Aws
using var provider = new AwsKmsContentKeyProvider(kmsClient, keyId);

await new PqFileEncryptor().EncryptFileAsync("data.bin", "data.pqfe", provider);
await new PqFileDecryptor().DecryptFileAsync("data.pqfe", "data.bin", provider);
```

Operational errors (missing key, access denied, throttling) surface as the SDK's own
exceptions so they are never mistaken for tampering; only authenticity failures map to
`PqDecryptionException`. See [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md) for rotation and
key-policy guidance.

## 8. Dependency injection

```csharp
// dotnet add package PostQuantum.FileEncryption.Extensions.DependencyInjection
builder.Services.AddPqFileEncryption(PqEncryptionOptions.Argon2id);  // core encrypt/decrypt
builder.Services.AddPqHybridFileEncryption();                        // recipient encryption
builder.Services.AddPqSigning();                                     // detached signatures
```

Encryptors/decryptors are thread-safe and cheap; resolving them per-request or as singletons
are both fine.

## 9. Production failure handling — what each exception means

| Exception | Meaning | What to do |
| --- | --- | --- |
| `PqFormatException` | Structurally not a (supported) container, or a header exceeds your configured limits. Detectable without any key. | Reject the input; safe to tell the user "not an encrypted file". |
| `PqDecryptionException` | Authentication failed: wrong passphrase/key **or** altered/truncated bytes — deliberately indistinguishable. | Fail the operation. Log the *event*, never the passphrase. Don't retry with the same inputs. |
| `PqSignatureException` | The signature does not verify — forged, altered, or a different key. | Treat the file as untrusted; alert, don't use. |
| `OperationCanceledException` | Cooperative cancellation. Nothing partial at the destination for file APIs. | Normal control flow. |
| `ArgumentException` and friends | Caller error (empty passphrase on encrypt, wrong key length). | A bug in your code, not hostile data — fix at the call site. |

Two logging rules: never log passphrases or key bytes (obvious, still worth stating), and
log authentication failures *as security events* — on a decryption service, a spike of
`PqDecryptionException` is either corruption or someone probing.

---

*To God be the glory — 1 Corinthians 10:31.*
