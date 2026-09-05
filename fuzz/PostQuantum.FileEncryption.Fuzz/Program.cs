// Coverage-guided fuzzing of the .NET .pqfe and PQKF parsers via SharpFuzz + libFuzzer. The
// contract: parsing/decryption must never throw anything other than a PqEncryptionException on
// arbitrary input (no crash, no unexpected exception). See fuzz/README.md for how to
// instrument and run.
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Internal;
using SharpFuzz;

const string passphrase = "fuzz-passphrase";

// Everything that touches the instrumented library must run INSIDE the callback: SharpFuzz only
// sets up its shared-memory coverage map once Run() starts, so calling an instrumented method
// (even a constructor) beforehand would write to unmapped memory.
Fuzzer.LibFuzzer.Run(data =>
{
    // Target 1: the .pqfe v2 container parser. Untrusted limits, for the same reason as the
    // PQKF target below — and because the permissive Default limits let the fuzzer mint
    // format-legal headers demanding 2 GiB Argon2id / 100M PBKDF2 iterations, which stalled
    // single iterations for ~20 minutes and failed scheduled runs on timeout. The format-maxima
    // range checks the Default path exercises are pinned by ParserBoundaryTests instead.
    try
    {
        // Synchronous wait is fine in a fuzz harness; the call is CPU-bound over a byte buffer.
        _ = new PqFileDecryptor(PqDecryptionLimits.Untrusted)
            .DecryptBytesAsync(data.ToArray(), passphrase).GetAwaiter().GetResult();
    }
    catch (PqEncryptionException)
    {
        // Expected, fail-closed: wrong passphrase / corrupt / truncated / not-a-container.
    }

    // Target 2: the PQKF v1 encrypted key-file parser (framing + embedded container + the
    // authenticated key-type check). Untrusted limits keep a fuzzer-crafted Argon2id header
    // from turning one iteration into a gigabyte KDF — which is also how real callers should
    // open key files from unknown sources.
    try
    {
        _ = PqKeyFileFormat.Decrypt(
            PqKeyFileFormat.KeyTypeHybridPrivate, "hybrid recipient private key", 2432,
            data, passphrase, PqDecryptionLimits.Untrusted);
    }
    catch (PqEncryptionException)
    {
        // Expected, fail-closed: bad magic / bad version / corrupt body / wrong key type.
    }
});
