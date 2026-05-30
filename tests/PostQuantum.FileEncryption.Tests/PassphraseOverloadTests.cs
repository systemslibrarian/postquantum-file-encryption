using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// The zeroable byte/<see cref="ReadOnlyMemory{T}"/> passphrase overloads must behave
/// identically to the convenience <see cref="string"/> overloads (which encode as UTF-8).
/// </summary>
public sealed class PassphraseOverloadTests
{
    private static readonly PqEncryptionOptions FastOptions = new()
    {
        Pbkdf2Iterations = PqEncryptionOptions.MinPbkdf2Iterations,
        ChunkSizeBytes = 1024,
    };

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    [Fact]
    public async Task Byte_passphrase_round_trips()
    {
        byte[] original = RandomBytes(3000);
        byte[] passphrase = Encoding.UTF8.GetBytes("zeroable-passphrase");

        using var cipher = new MemoryStream();
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), cipher, passphrase);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, passphrase);

        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task String_encrypted_then_decrypted_with_utf8_bytes()
    {
        // A string passphrase and its UTF-8 bytes are interchangeable across the two overloads.
        byte[] original = RandomBytes(2000);
        const string passphrase = "interchangeable ☂ unicode";

        using var cipher = new MemoryStream();
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), cipher, passphrase);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, Encoding.UTF8.GetBytes(passphrase));

        Assert.Equal(original, restored.ToArray());
    }
}
