using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Both passphrase KDFs (PBKDF2 and Argon2id) must round-trip and validate their options.</summary>
public sealed class KdfTests
{
    private const string Passphrase = "a fairly long and reasonable passphrase";

    // Argon2id at the minimum cost keeps the suite fast while still exercising the real KDF.
    private static PqEncryptionOptions Argon2Options => new()
    {
        Kdf = PqKdf.Argon2id,
        Argon2MemoryKiB = PqEncryptionOptions.MinArgon2MemoryKiB,
        Argon2Iterations = 1,
        Argon2Parallelism = 1,
        ChunkSizeBytes = 1024,
    };

    private static PqEncryptionOptions Pbkdf2Options => new()
    {
        Kdf = PqKdf.Pbkdf2HmacSha256,
        Pbkdf2Iterations = PqEncryptionOptions.MinPbkdf2Iterations,
        ChunkSizeBytes = 1024,
    };

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    public static TheoryData<bool> KdfChoices => new() { true, false };

    [Theory]
    [MemberData(nameof(KdfChoices))]
    public async Task Round_trip_succeeds_for_each_kdf(bool useArgon2)
    {
        PqEncryptionOptions options = useArgon2 ? Argon2Options : Pbkdf2Options;
        byte[] original = RandomBytes(5000);

        using var cipher = new MemoryStream();
        await new PqFileEncryptor(options).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, Passphrase);

        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task Decryptor_does_not_need_to_know_which_kdf_was_used()
    {
        // A file encrypted with Argon2id decrypts with a default decryptor; the KDF is in the header.
        byte[] original = RandomBytes(1500);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Argon2Options).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        cipher.Position = 0;

        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, Passphrase);
        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task Wrong_passphrase_fails_closed_under_argon2()
    {
        byte[] original = RandomBytes(1500);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Argon2Options).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        cipher.Position = 0;

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(cipher, restored, "not the passphrase"));
    }

    [Theory]
    [InlineData(PqKdf.Pbkdf2HmacSha256, 50_000)]   // below PBKDF2 minimum
    [InlineData(PqKdf.Argon2id, 1)]                 // Argon2 memory far below minimum (reused field)
    public void Out_of_range_options_are_rejected(PqKdf kdf, int badValue)
    {
        var options = kdf == PqKdf.Pbkdf2HmacSha256
            ? new PqEncryptionOptions { Kdf = kdf, Pbkdf2Iterations = badValue }
            : new PqEncryptionOptions { Kdf = kdf, Argon2MemoryKiB = badValue };

        Assert.Throws<ArgumentOutOfRangeException>(() => new PqFileEncryptor(options));
    }
}
