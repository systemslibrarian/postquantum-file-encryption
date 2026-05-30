using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// <b>EXPERIMENTAL feature.</b> ML-KEM recipient (public-key) encryption is not part of the
/// stable symmetric surface — see <c>docs/ROADMAP-v3.md</c>. The full round-trip runs only where
/// the platform provides ML-KEM (<see cref="PqKeyPair.IsSupported"/>); the capability-gating
/// behavior is verified on every platform, including hosts without ML-KEM.
/// </summary>
[Trait("Category", "Experimental")]
public sealed class RecipientTests
{
    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    [Fact]
    public async Task Recipient_round_trip_when_supported()
    {
        if (!PqKeyPair.IsSupported)
        {
            // No ML-KEM on this host (e.g. Linux without OpenSSL 3.5). Covered by the gating tests.
            return;
        }

        using var keyPair = PqKeyPair.Generate();
        byte[] original = RandomBytes(5000);

        using var cipher = new MemoryStream();
        await new PqFileEncryptor().EncryptAsync(new MemoryStream(original), cipher, keyPair.PublicKey);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, keyPair.PrivateKey);

        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task Wrong_private_key_fails_closed_when_supported()
    {
        if (!PqKeyPair.IsSupported)
        {
            return;
        }

        using var alice = PqKeyPair.Generate();
        using var mallory = PqKeyPair.Generate();
        byte[] original = RandomBytes(1000);

        using var cipher = new MemoryStream();
        await new PqFileEncryptor().EncryptAsync(new MemoryStream(original), cipher, alice.PublicKey);
        cipher.Position = 0;

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(cipher, restored, mallory.PrivateKey));
    }

    [Fact]
    public void Generate_reflects_platform_support()
    {
        if (PqKeyPair.IsSupported)
        {
            using var keyPair = PqKeyPair.Generate();
            Assert.NotNull(keyPair.PublicKey);
            Assert.NotNull(keyPair.PrivateKey);
        }
        else
        {
            Assert.Throws<PlatformNotSupportedException>(() => PqKeyPair.Generate());
        }
    }

    [Fact]
    public async Task Encrypting_to_recipient_without_platform_support_fails_clearly()
    {
        if (PqKeyPair.IsSupported)
        {
            return; // This test asserts the unsupported-platform behavior only.
        }

        // A correctly-sized public key passes import validation; the platform gate trips at encrypt.
        var publicKey = PqRecipientPublicKey.Import(new byte[1184]);
        using var cipher = new MemoryStream();
        await Assert.ThrowsAsync<PlatformNotSupportedException>(() =>
            new PqFileEncryptor().EncryptAsync(new MemoryStream(new byte[64]), cipher, publicKey));
    }

    [Fact]
    public void Public_key_import_rejects_wrong_length()
    {
        Assert.Throws<ArgumentException>(() => PqRecipientPublicKey.Import(new byte[10]));
    }

    [Fact]
    public async Task Passphrase_container_cannot_be_opened_with_a_private_key()
    {
        if (!PqKeyPair.IsSupported)
        {
            return;
        }

        // Encrypt with a passphrase, then try to decrypt as if it were a recipient container.
        using var keyPair = PqKeyPair.Generate();
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(new PqEncryptionOptions { Pbkdf2Iterations = PqEncryptionOptions.MinPbkdf2Iterations })
            .EncryptAsync(new MemoryStream(new byte[100]), cipher, "pw");
        cipher.Position = 0;

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(cipher, restored, keyPair.PrivateKey));
    }
}
