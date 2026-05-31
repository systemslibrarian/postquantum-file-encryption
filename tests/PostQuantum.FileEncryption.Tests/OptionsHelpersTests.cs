using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Exercises the discoverability/ergonomics helpers on <see cref="PqEncryptionOptions"/> —
/// the <c>Argon2id</c> preset and the <c>With...</c> fluent methods. These are pure surface
/// shortcuts over the existing init-only properties, so the tests focus on (a) the right
/// fields propagate, (b) untouched fields are carried through, and (c) the resulting
/// options actually produce valid containers when round-tripped through the engine.
/// </summary>
public sealed class OptionsHelpersTests
{
    [Fact]
    public void Argon2id_preset_selects_argon2id_kdf()
    {
        Assert.Equal(PqKdf.Argon2id, PqEncryptionOptions.Argon2id.Kdf);
    }

    [Fact]
    public void Default_preset_selects_pbkdf2_kdf()
    {
        Assert.Equal(PqKdf.Pbkdf2HmacSha256, PqEncryptionOptions.Default.Kdf);
    }

    [Fact]
    public void WithArgon2id_overrides_only_specified_parameters()
    {
        PqEncryptionOptions baseOpts = new() { Argon2MemoryKiB = 32_000, Argon2Iterations = 3 };
        PqEncryptionOptions tuned = baseOpts.WithArgon2id(memoryKiB: 65_536);

        Assert.Equal(PqKdf.Argon2id, tuned.Kdf);
        Assert.Equal(65_536, tuned.Argon2MemoryKiB);
        Assert.Equal(3, tuned.Argon2Iterations);          // carried through
        Assert.Equal(baseOpts.SaltSizeBytes, tuned.SaltSizeBytes);
        Assert.Equal(baseOpts.ChunkSizeBytes, tuned.ChunkSizeBytes);
    }

    [Fact]
    public void WithPbkdf2_overrides_iterations_and_carries_the_rest()
    {
        PqEncryptionOptions baseOpts = new() { Kdf = PqKdf.Argon2id, ChunkSizeBytes = 8192 };
        PqEncryptionOptions tuned = baseOpts.WithPbkdf2(iterations: 250_000);

        Assert.Equal(PqKdf.Pbkdf2HmacSha256, tuned.Kdf);
        Assert.Equal(250_000, tuned.Pbkdf2Iterations);
        Assert.Equal(8192, tuned.ChunkSizeBytes);         // carried through
    }

    [Fact]
    public void WithChunkSize_keeps_kdf_and_costs()
    {
        PqEncryptionOptions baseOpts = PqEncryptionOptions.Argon2id;
        PqEncryptionOptions tuned = baseOpts.WithChunkSize(16 * 1024);

        Assert.Equal(PqKdf.Argon2id, tuned.Kdf);
        Assert.Equal(16 * 1024, tuned.ChunkSizeBytes);
        Assert.Equal(baseOpts.Argon2MemoryKiB, tuned.Argon2MemoryKiB);
        Assert.Equal(baseOpts.Argon2Iterations, tuned.Argon2Iterations);
    }

    [Fact]
    public async Task Argon2id_preset_round_trips_a_real_payload()
    {
        // Use minimum cost so the test stays quick. The helpers must produce options that
        // pass the engine's own validation — anything else would be a silent regression.
        var opts = PqEncryptionOptions.Argon2id.WithArgon2id(
            memoryKiB: PqEncryptionOptions.MinArgon2MemoryKiB,
            iterations: PqEncryptionOptions.MinArgon2Iterations,
            parallelism: 1);

        byte[] original = RandomBytes(4_096);
        byte[] cipher = await new PqFileEncryptor(opts).EncryptBytesAsync(original, Passphrase);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(cipher, Passphrase);

        Assert.Equal(original, restored);
    }

    [Theory]
    [InlineData(0, 0)]            // never reported in practice, but the math should still be safe
    [InlineData(100, 0)]
    [InlineData(0, 100)]
    [InlineData(50, 100)]
    [InlineData(100, 100)]
    public void Fraction_is_clamped_or_null_for_known_edge_cases(int processed, int total)
    {
        var p = new PqProgress(BytesProcessed: processed, TotalBytes: total);

        if (total > 0)
        {
            Assert.NotNull(p.Fraction);
            Assert.InRange(p.Fraction!.Value, 0.0, 1.0);
        }
        else
        {
            Assert.Null(p.Fraction);
        }
    }

    [Fact]
    public void Fraction_is_null_when_total_unknown()
    {
        var p = new PqProgress(BytesProcessed: 100, TotalBytes: null);
        Assert.Null(p.Fraction);
    }

    [Fact]
    public void Fraction_clamps_when_bytes_processed_exceeds_total()
    {
        // Defensive: the engine should never report this, but the property must remain safe.
        var p = new PqProgress(BytesProcessed: 1_500, TotalBytes: 1_000);
        Assert.Equal(1.0, p.Fraction);
    }
}
