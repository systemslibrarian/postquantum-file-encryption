using System.Text;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pinned known-answer vectors. These fixed containers were produced by an earlier build and
/// must keep decrypting to the same plaintext. If a change to the format or the cryptography
/// breaks them, that is a deliberate, breaking change — bump the format version and regenerate
/// the vectors on purpose.
/// </summary>
public sealed class KnownAnswerVectorTests
{
    private const string Passphrase = "test-vector-passphrase";
    private static readonly byte[] ExpectedPlaintext =
        Encoding.UTF8.GetBytes("PostQuantum.FileEncryption known-answer vector v2.");

    // KeySource = passphrase, KDF = PBKDF2-HMAC-SHA256 (100,000 iters), 16-byte salt, 1 KiB chunks.
    private const string Pbkdf2Vector =
        "UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj";

    // KeySource = passphrase, KDF = Argon2id (8 MiB, 1 pass, 1 lane), 16-byte salt, 1 KiB chunks.
    private const string Argon2Vector =
        "UFFGRQIBAQAAAAQAS7aXNQAbAhCZBPTffR0AgJ7we1bozxQOAAAgAAAAAAEBAQAAADJOzagbj5vUN9WHVWy1t7KN/pG9O5ab04z0IO4xyV5vRMxDN2TsXQGStrNyW5eC77skRpx0WhB0BC6SxsnfnwherIM=";

    [Theory]
    [InlineData(Pbkdf2Vector)]
    [InlineData(Argon2Vector)]
    public async Task Pinned_container_decrypts_to_known_plaintext(string base64Container)
    {
        byte[] container = Convert.FromBase64String(base64Container);

        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(new MemoryStream(container), restored, Passphrase);

        Assert.Equal(ExpectedPlaintext, restored.ToArray());
    }

    [Fact]
    public async Task Pinned_container_rejects_a_wrong_passphrase()
    {
        byte[] container = Convert.FromBase64String(Pbkdf2Vector);

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(container), restored, "wrong"));
    }
}
