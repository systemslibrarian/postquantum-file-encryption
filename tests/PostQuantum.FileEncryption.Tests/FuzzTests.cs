using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// A small mutation-fuzzing harness over the container parser. The contract under test is
/// fail-closed robustness: for <em>any</em> corruption of a valid container, decryption must
/// either reject it with a <see cref="PqEncryptionException"/> or (only if the mutation was a
/// genuine no-op) return the exact original plaintext. It must never throw an unexpected
/// exception type and never emit different plaintext.
/// </summary>
public sealed class FuzzTests
{
    private const string Passphrase = "fuzzing-passphrase";

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static async Task<(byte[] container, byte[] plaintext)> BuildContainerAsync(int plaintextSize)
    {
        var options = new PqEncryptionOptions
        {
            Pbkdf2Iterations = PqEncryptionOptions.MinPbkdf2Iterations,
            ChunkSizeBytes = 1024,
        };
        byte[] plaintext = RandomBytes(plaintextSize);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(options).EncryptAsync(new MemoryStream(plaintext), cipher, Passphrase);
        return (cipher.ToArray(), plaintext);
    }

    [Fact]
    public async Task Bit_flips_never_crash_and_never_yield_wrong_plaintext()
    {
        (byte[] valid, byte[] plaintext) = await BuildContainerAsync(3000); // spans multiple chunks

        // Deterministic seed so failures reproduce. (Tests may use Random; workflow scripts may not.)
        var rng = new Random(20260530);

        for (int i = 0; i < 300; i++)
        {
            byte[] mutated = (byte[])valid.Clone();
            int mutations = 1 + rng.Next(3);
            for (int m = 0; m < mutations; m++)
            {
                int pos = rng.Next(mutated.Length);
                mutated[pos] ^= (byte)(1 + rng.Next(255)); // guaranteed to change the byte
            }

            using var output = new MemoryStream();
            try
            {
                await new PqFileDecryptor().DecryptAsync(new MemoryStream(mutated), output, Passphrase);
                // Authenticated everywhere: if decryption "succeeds", the bytes must be unchanged.
                Assert.Equal(plaintext, output.ToArray());
            }
            catch (PqEncryptionException)
            {
                // Expected: every meaningful corruption is rejected, fail-closed.
            }
        }
    }

    [Fact]
    public async Task Truncations_at_every_length_are_rejected()
    {
        // A small single-chunk container keeps the every-prefix scan fast.
        (byte[] valid, _) = await BuildContainerAsync(250);

        // Every proper prefix of a valid container is incomplete and must be rejected.
        for (int length = 0; length < valid.Length; length++)
        {
            byte[] truncated = valid[..length];
            using var output = new MemoryStream();
            await Assert.ThrowsAnyAsync<PqEncryptionException>(() =>
                new PqFileDecryptor().DecryptAsync(new MemoryStream(truncated), output, Passphrase));
        }
    }

    [Fact]
    public async Task Random_garbage_is_always_rejected_cleanly()
    {
        var rng = new Random(424242);
        for (int i = 0; i < 200; i++)
        {
            byte[] garbage = RandomBytes(1 + rng.Next(2048));
            using var output = new MemoryStream();
            await Assert.ThrowsAnyAsync<PqEncryptionException>(() =>
                new PqFileDecryptor().DecryptAsync(new MemoryStream(garbage), output, Passphrase));
        }
    }
}
