using System.Text;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pins the deprecated inline ML-KEM-768 recipient path (KeySource 2) with a committed
/// decrypt-only vector (docs/TEST-VECTORS.md, Vector 9) — the third key-establishment path,
/// previously pinned by nothing: its randomized round-trip tests self-skip on hosts without
/// platform ML-KEM, so a self-consistent serialization or derivation regression would have
/// passed CI everywhere. Encryption is randomized (a fresh KEM encapsulation per container),
/// so the vector is decrypt-only. Generated once on a Linux host with OpenSSL 3.5 (platform
/// ML-KEM) and frozen; the key pair was generated solely for this vector and protects nothing.
/// The artifact bytes themselves are hash-pinned on every host by <see cref="VectorArtifactTests"/>.
/// </summary>
public sealed class RecipientKnownAnswerVectorTests
{
    private const string ExpectedPlaintext =
        "PostQuantum.FileEncryption inline ML-KEM-768 recipient known-answer vector.";

    [Fact]
    public async Task Pinned_inline_mlkem_recipient_container_decrypts()
    {
        if (!PqKeyPair.IsSupported)
        {
            return; // platform-gated; the artifacts stay hash-pinned everywhere regardless
        }

        (byte[] container, PqRecipientPrivateKey privateKey) = await LoadVectorAsync();
        using (privateKey)
        {
            using var output = new MemoryStream();
            await new PqFileDecryptor().DecryptAsync(
                new MemoryStream(container, writable: false), output, privateKey);

            Assert.Equal(ExpectedPlaintext, Encoding.UTF8.GetString(output.ToArray()));
        }
    }

    [Fact]
    public async Task Pinned_inline_mlkem_recipient_container_rejects_tampering()
    {
        if (!PqKeyPair.IsSupported)
        {
            return;
        }

        (byte[] container, PqRecipientPrivateKey privateKey) = await LoadVectorAsync();
        using (privateKey)
        {
            container[^1] ^= 0x01; // final tag byte

            using var output = new MemoryStream();
            await Assert.ThrowsAsync<PqDecryptionException>(() =>
                new PqFileDecryptor().DecryptAsync(
                    new MemoryStream(container, writable: false), output, privateKey));
        }
    }

    private static async Task<(byte[] container, PqRecipientPrivateKey privateKey)> LoadVectorAsync()
    {
        string dir = Path.Combine(FindRepositoryRoot(), "test-vectors");
        byte[] container = await File.ReadAllBytesAsync(Path.Combine(dir, "mlkem-recipient.pqfe"));
        byte[] keyBytes = await File.ReadAllBytesAsync(Path.Combine(dir, "mlkem-recipient.key"));
        return (container, PqRecipientPrivateKey.Import(keyBytes));
    }

    private static string FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "test-vectors")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName
            ?? throw new InvalidOperationException(
                $"No 'test-vectors' directory found above {AppContext.BaseDirectory}.");
    }
}
