using CsCheck;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Property-based tests: assert invariants over many generated inputs (and shrink to a minimal
/// counterexample on failure), rather than a handful of hand-picked cases.
/// </summary>
public sealed class PropertyTests
{
    [Fact]
    public async Task Round_trip_holds_for_arbitrary_input_and_chunk_size()
    {
        // Arbitrary plaintext length (0–20 KiB) × arbitrary valid chunk size.
        var gen = Gen.Select(
            Gen.Byte.Array[Gen.Int[0, 20_000]],
            Gen.Int[PqEncryptionOptions.MinChunkSizeBytes, 65_536]);

        await gen.SampleAsync(async pair =>
        {
            var (data, chunkSize) = pair;
            byte[] container = await new PqFileEncryptor(Fast(chunkSize)).EncryptBytesAsync(data, Passphrase);
            byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, Passphrase);
            Assert.Equal(data, restored);
        }, iter: 50);
    }

    [Fact]
    public async Task A_wrong_passphrase_never_decrypts()
    {
        var gen = Gen.Select(
            Gen.Byte.Array[Gen.Int[1, 8_000]],
            Gen.String[Gen.Char.AlphaNumeric, 1, 24]);

        await gen.SampleAsync(async pair =>
        {
            var (data, wrong) = pair;
            byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(data, Passphrase);
            if (wrong == Passphrase) return; // skip the (astronomically unlikely) match
            await Assert.ThrowsAsync<PqDecryptionException>(() =>
                new PqFileDecryptor().DecryptBytesAsync(container, wrong));
        }, iter: 30);
    }
}
