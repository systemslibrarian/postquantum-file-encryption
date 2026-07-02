# Anti-patterns — how to hold it wrong

The library is fail-closed by design, but no API can stop calling code from defeating
itself. This page collects the shapes that do — each with the wrong code, why it is
dangerous, and the correct form. The first four are enforced at compile time by the
[analyzers package](https://www.nuget.org/packages/PostQuantum.FileEncryption.Analyzers)
(`PQFE101`–`PQFE104`); the rest can't be caught by static analysis, only by reading this
page. The positive counterpart is the [COOKBOOK](COOKBOOK.md).

## PQFE101

### Hard-coding the passphrase

```csharp
// WRONG — ships with every binary, lives in source control forever
await encryptor.EncryptFileAsync("db-backup.bak", "db-backup.pqfe", "CompanyBackup2026!");
```

Anyone who can read the source, the repository history, or the compiled assembly can
decrypt every file this code ever produced. The KDF hardening is irrelevant — there is
nothing to guess.

```csharp
// RIGHT — the passphrase enters at runtime, from somewhere with access control
string passphrase = await secretClient.GetSecretAsync("backup-passphrase");
await encryptor.EncryptFileAsync("db-backup.bak", "db-backup.pqfe", passphrase);
```

Environment variables are acceptable for scripts and CI with a caveat: they are visible to
child processes and can surface in crash dumps and process inspection — scope them to the
single invocation.

## PQFE102

### Writing raw private-key bytes to disk

```csharp
// WRONG — the unprotected secret key, readable by anything that can read the file
File.WriteAllBytes("me.key", keyPair.PrivateKey.Export());
```

`Export()` exists for callers who are about to put the bytes somewhere already protected (an
HSM, a secret store, a hardware token). A plain file is not that place.

```csharp
// RIGHT — an authenticated, Argon2id-hardened key file (the PQKF format)
File.WriteAllBytes("me.key", keyPair.PrivateKey.ExportEncrypted(passphrase));
using var key = PqHybridPrivateKey.ImportEncrypted(File.ReadAllBytes("me.key"), passphrase);
```

A PQKF file at rest is useless without the passphrase and fails closed on any tampering.
Public keys are public — raw `Export()` is exactly right for them.

## PQFE103

### Discarding the task

```csharp
// WRONG — in a synchronous method, this compiles without even a compiler warning
void Backup() =>
    new PqFileEncryptor().EncryptFileAsync(src, dst, passphrase);   // fire and forget
```

The method returns immediately; the encryption may still be running, may have failed, or may
have been half-cancelled at process exit — and no one will ever know, because the exception
died with the task. On the decrypt side it is worse: continuing past an unawaited
`DecryptFileAsync` means acting before authentication has happened.

```csharp
// RIGHT
await new PqFileEncryptor().EncryptFileAsync(src, dst, passphrase);
```

If you genuinely mean to hand the task off, assign it (`Task pending = ...`) and observe it
later — the analyzer treats an explicit `_ =` discard as you taking responsibility.

## PQFE104

### Swallowing the fail-closed exception

```csharp
// WRONG — the "it's forged" signal becomes silent success for whatever runs next
try { await verifier.VerifyFileAsync(path, sigPath, publicKey); }
catch (PqSignatureException) { }
InstallUpdate(path);   // runs whether or not the signature verified
```

`PqDecryptionException` and `PqSignatureException` are not noise to suppress — they are the
*entire point*: the data is inauthentic, forged, or corrupt. An empty catch converts a hard
stop into a shrug.

```csharp
// RIGHT — the failure changes what happens next
try { await verifier.VerifyFileAsync(path, sigPath, publicKey); }
catch (PqSignatureException)
{
    logger.LogWarning("Rejected unverifiable update package {Path}", path);
    return;   // do NOT install
}
InstallUpdate(path);
```

Probing with `catch (PqFormatException)` to ask "is this even a container?" is legitimate —
that check is structural, needs no key, and is deliberately not flagged.

## Beyond the analyzers

### Decrypting untrusted input with no limits

A container header may legally demand 2 GiB of Argon2id memory and 16 MiB chunk buffers
*before anything authenticates* — which makes a 200-byte hostile file a denial-of-service
tool against a naïve decryption service. If input crosses a trust boundary, construct the
decryptor with `PqDecryptionLimits.Untrusted` (or your own ceilings); the same applies to
`PqHybridDecryptor` and `ImportEncrypted`. See [COOKBOOK](COOKBOOK.md) recipe 2.

### Treating a valid signature as "this file is safe"

A detached signature proves the bytes are exactly what *some* key holder signed. It does not
prove the file is benign, current, or meant for this purpose — and it cannot stop
**strip-and-resign**: anyone who can read the bytes can discard your `.sig` and sign the
same bytes with *their* key. Trust lives entirely in *whose public key you verify with* and
how it reached you. Distribute verification keys over a channel the attacker doesn't
control, and pin them.

### Expecting metadata privacy

Encryption here protects *content*. The container reveals that it is a `.pqfe` file, its
approximate plaintext size, the KDF and cost parameters, and (for recipient mode) how many
recipients there are. File names, timestamps, and access patterns are outside the envelope
entirely. If sizes or names are themselves sensitive, pad or rename before encrypting —
metadata protection is a candidate for the 2.0 format, not a property of v2.

### Rolling your own retry loop on `PqDecryptionException`

Wrong passphrase and corrupted file are deliberately indistinguishable, so "retry three
times" either hammers the KDF for nothing (corruption never heals) or turns your service
into a convenient online guessing oracle with the KDF cost as the only brake. Fail once,
report once. If users mistype passphrases, that is a UX problem (confirmation prompts),
not a retry problem.

### Deleting the plaintext before the encrypt completes

The file APIs are atomic on the *output* side — nothing partial appears at the destination.
They cannot protect an input you delete early. Delete originals only after the encrypt call
returns successfully (and, for backups, ideally after a test decrypt).

### Backing up everything except the key

An encrypted backup whose only key lived on the machine that died is a very secure way to
have no backup. Key files (`ExportEncrypted`) are small — store them separately from the
data they open, and treat the passphrase's recovery story with the same seriousness as the
data's.

---

*To God be the glory — 1 Corinthians 10:31.*
