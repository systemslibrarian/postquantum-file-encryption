# PostQuantum.FileEncryption.Extensions.DependencyInjection

`Microsoft.Extensions.DependencyInjection` integration for
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption) and
[PostQuantum.FileEncryption.Hybrid](https://www.nuget.org/packages/PostQuantum.FileEncryption.Hybrid).
One call registers the encryptor and decryptor services in any host that uses the standard
.NET service container — ASP.NET Core, Worker Services, console hosts with
`Microsoft.Extensions.Hosting`.

```bash
dotnet add package PostQuantum.FileEncryption.Extensions.DependencyInjection
```

## Usage

Passphrase encryption only (registers `PqFileEncryptor` + `PqFileDecryptor`):

```csharp
builder.Services.AddPqFileEncryption();
```

Passphrase **and** X25519 + ML-KEM-768 hybrid recipient encryption (additionally registers
`PqHybridEncryptor` + `PqHybridDecryptor`):

```csharp
builder.Services.AddPqHybridFileEncryption();
```

Detached Ed25519 + ML-DSA-65 signing and verification (registers `PqSigner` + `PqVerifier`;
key material stays in your own key storage and is passed per call):

```csharp
builder.Services.AddPqSigning();
```

Then inject and use:

```csharp
public sealed class ArchiveService(PqFileEncryptor encryptor, PqFileDecryptor decryptor)
{
    public Task ProtectAsync(string path, string passphrase, CancellationToken ct) =>
        encryptor.EncryptFileAsync(path, path + ".pqfe", passphrase, cancellationToken: ct);
}
```

### Options

Pass a `PqEncryptionOptions` to tune encryption (KDF choice, work factors, chunk size).
Omitting it gives you the library's secure defaults:

```csharp
builder.Services.AddPqFileEncryption(PqEncryptionOptions.Argon2id);
```

Options never affect decryption — the decryptor reads every parameter from the
authenticated container header, so a service registered with one set of options decrypts
files produced with any other.

## Behavior

- **Singletons.** The encryptor/decryptor types are thread-safe and hold no per-operation
  state; one instance serves the whole host.
- **`TryAdd` semantics.** If your application already registered its own instance of any of
  these types, your registration wins.
- **Lockstep versioning.** This package always pins `PostQuantum.FileEncryption`,
  `PostQuantum.FileEncryption.Hybrid`, and `PostQuantum.FileEncryption.Signing` at its own
  version.

## Links

- [Repository & full documentation](https://github.com/systemslibrarian/postquantum-file-encryption)
- [File format specification (FROZEN .pqfe v2)](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/FILE-FORMAT.md)
- [Known gaps — the honest ledger](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/KNOWN-GAPS.md)

---

*To God be the glory — 1 Corinthians 10:31.*
