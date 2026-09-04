using System.Reflection;
using PostQuantum.FileEncryption.Internal;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Regression pins for the key-zeroization contract (THREAT-MODEL.md "Key hygiene"): the
/// engine's <c>finally</c> blocks and the key types' <c>Dispose</c> implementations must leave
/// key buffers all-zero on the success, failure, and cancellation paths. This class of defense
/// has silently regressed before (docs/audits/2026-06-12, findings 1 and 4), and nothing else
/// in the suite would notice — a decryptor works just as well with an un-zeroed key.
/// </summary>
public sealed class ZeroizationTests
{
    private static (byte[] key, ContainerHeader header) FreshKeyAndHeader()
    {
        byte[] key = RandomBytes(ContainerFormat.KeyLength);
        var header = ContainerHeader.Create(
            ContainerFormat.KeySourcePassphrase, 1024, keyParams: [0x01, 0x02, 0x03]);
        return (key, header);
    }

    private static void AssertZeroed(byte[] buffer) =>
        Assert.All(buffer, b => Assert.Equal(0, b));

    [Fact]
    public async Task Engine_zeroes_the_content_key_on_encrypt_and_decrypt_success()
    {
        (byte[] key, ContainerHeader header) = FreshKeyAndHeader();
        byte[] decryptKey = (byte[])key.Clone();
        byte[] plaintext = RandomBytes(3000); // three frames at the 1024-byte chunk size

        using var container = new MemoryStream();
        await PqContainerEngine.EncryptCoreAsync(
            new MemoryStream(plaintext), container, key, header, plaintext.Length, null, default);
        AssertZeroed(key);

        container.Position = 0;
        ContainerHeader parsed = await PqContainerEngine.ReadHeaderAsync(container, default);
        using var output = new MemoryStream();
        await PqContainerEngine.DecryptCoreAsync(
            container, output, decryptKey, parsed, container.Length, null, default);

        AssertZeroed(decryptKey);
        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task Engine_zeroes_the_content_key_when_decryption_fails_authentication()
    {
        (byte[] key, ContainerHeader header) = FreshKeyAndHeader();
        byte[] decryptKey = (byte[])key.Clone();
        byte[] plaintext = RandomBytes(500);

        using var container = new MemoryStream();
        await PqContainerEngine.EncryptCoreAsync(
            new MemoryStream(plaintext), container, key, header, plaintext.Length, null, default);

        byte[] tampered = container.ToArray();
        tampered[^1] ^= 0x01; // flip a tag byte

        using var source = new MemoryStream(tampered);
        ContainerHeader parsed = await PqContainerEngine.ReadHeaderAsync(source, default);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            PqContainerEngine.DecryptCoreAsync(source, output, decryptKey, parsed, tampered.Length, null, default));

        AssertZeroed(decryptKey);
    }

    [Fact]
    public async Task Engine_zeroes_the_content_key_when_encryption_is_cancelled()
    {
        (byte[] key, ContainerHeader header) = FreshKeyAndHeader();

        using var destination = new MemoryStream();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PqContainerEngine.EncryptCoreAsync(
                new MemoryStream(RandomBytes(5000)), destination, key, header,
                5000, null, new CancellationToken(canceled: true)));

        AssertZeroed(key);
    }

    [Fact]
    public void Recipient_private_key_dispose_zeroes_the_decapsulation_key()
    {
        byte[] raw = RandomBytes(KemSizes.MlKem768DecapsulationKey);
        var key = PqRecipientPrivateKey.Import(raw);

        FieldInfo? field = typeof(PqRecipientPrivateKey)
            .GetField("_decapsulationKey", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field); // renamed field ⇒ update this pin, don't delete it
        byte[] held = Assert.IsType<byte[]>(field.GetValue(key));
        Assert.Equal(raw, held); // sanity: we are looking at the real key buffer

        key.Dispose();
        AssertZeroed(held);
    }

    [Fact]
    public void Local_kek_provider_dispose_zeroes_the_kek()
    {
        var provider = LocalKekContentKeyProvider.Generate();

        FieldInfo? field = typeof(LocalKekContentKeyProvider)
            .GetField("_kek", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field); // renamed field ⇒ update this pin, don't delete it
        byte[] held = Assert.IsType<byte[]>(field.GetValue(provider));
        Assert.Contains(held, b => b != 0); // sanity: a real random KEK

        provider.Dispose();
        AssertZeroed(held);
    }
}
