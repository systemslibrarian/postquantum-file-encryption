// Coverage-guided fuzzing of the .NET .pqfe parser via SharpFuzz + libFuzzer. The contract:
// decryption must never throw anything other than a PqEncryptionException on arbitrary input
// (no crash, no unexpected exception). See fuzz/README.md for how to instrument and run.
using PostQuantum.FileEncryption;
using SharpFuzz;

const string passphrase = "fuzz-passphrase";

// Everything that touches the instrumented library must run INSIDE the callback: SharpFuzz only
// sets up its shared-memory coverage map once Run() starts, so calling an instrumented method
// (even a constructor) beforehand would write to unmapped memory.
Fuzzer.LibFuzzer.Run(data =>
{
    try
    {
        // Synchronous wait is fine in a fuzz harness; the call is CPU-bound over a byte buffer.
        _ = new PqFileDecryptor().DecryptBytesAsync(data.ToArray(), passphrase).GetAwaiter().GetResult();
    }
    catch (PqEncryptionException)
    {
        // Expected, fail-closed: wrong passphrase / corrupt / truncated / not-a-container.
    }
});
