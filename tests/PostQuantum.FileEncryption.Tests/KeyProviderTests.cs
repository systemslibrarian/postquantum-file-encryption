using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Envelope encryption via <see cref="IContentKeyProvider"/> and the local-KEK provider.</summary>
public sealed class KeyProviderTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pqfe-kek-" + Guid.NewGuid().ToString("N"));

    public KeyProviderTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { /* best effort */ } }

    [Theory]
    [InlineData(0)]
    [InlineData(5000)]
    public async Task Bytes_round_trip(int size)
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        byte[] original = RandomBytes(size);

        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, provider);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, provider);

        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Stream_and_file_round_trip()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        byte[] original = RandomBytes(6000);

        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Fast()).EncryptAsync(new MemoryStream(original), cipher, provider);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, provider);
        Assert.Equal(original, restored.ToArray());

        string plain = Path.Combine(_dir, "p"), ct = Path.Combine(_dir, "c.pqfe"), outp = Path.Combine(_dir, "o");
        await File.WriteAllBytesAsync(plain, original);
        await new PqFileEncryptor(Fast()).EncryptFileAsync(plain, ct, provider);
        await new PqFileDecryptor().DecryptFileAsync(ct, outp, provider);
        Assert.Equal(original, await File.ReadAllBytesAsync(outp));
    }

    [Fact]
    public async Task Exported_kek_recreates_a_working_provider()
    {
        byte[] kek;
        byte[] container;
        byte[] original = RandomBytes(2000);
        using (var provider = LocalKekContentKeyProvider.Generate())
        {
            kek = provider.ExportKek();
            container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, provider);
        }

        // A new provider over the same KEK decrypts; the wrapped key travels in the container.
        using var restored = new LocalKekContentKeyProvider(kek);
        Assert.Equal(original, await new PqFileDecryptor().DecryptBytesAsync(container, restored));
    }

    [Fact]
    public async Task Wrong_kek_fails_closed()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        using var other = LocalKekContentKeyProvider.Generate();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(1000), provider);

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, other));
    }

    [Fact]
    public async Task Tampered_container_is_rejected()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(1000), provider);
        container[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, provider));
    }

    [Fact]
    public async Task A_different_provider_id_is_rejected()
    {
        using var local = LocalKekContentKeyProvider.Generate();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), local);

        // A provider with a different id must be rejected before any unwrap attempt.
        var other = new RenamedProvider(local, "aws-kms");
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, other));
    }

    [Fact]
    public async Task Passphrase_decryptor_rejects_a_key_provider_container()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), provider);
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, "a passphrase"));
    }

    [Fact]
    public void Local_provider_requires_a_256_bit_kek()
    {
        Assert.Throws<ArgumentException>(() => new LocalKekContentKeyProvider(new byte[16]));
    }

    [Fact]
    public async Task A_provider_returning_a_short_key_cannot_downgrade_encryption()
    {
        // A 16-byte content key would silently produce an AES-128-GCM container while the
        // format promises AES-256 — the engine must reject it before any ciphertext exists.
        using var local = LocalKekContentKeyProvider.Generate();
        var misbehaving = new TruncatingProvider(local, 16);

        var ex = await Assert.ThrowsAsync<PqEncryptionException>(() =>
            new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), misbehaving));
        Assert.Contains("16-byte", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_provider_returning_a_short_key_on_unwrap_fails_closed()
    {
        using var local = LocalKekContentKeyProvider.Generate();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), local);

        // The container is fine; the (custom) provider misbehaves on unwrap. That must be the
        // library's typed fail-closed signal, not a raw CryptographicException from AesGcm.
        var misbehaving = new TruncatingProvider(local, 15);
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, misbehaving));
    }

    /// <summary>A custom provider that delegates to another but reports a different id — proves the abstraction.</summary>
    private sealed class RenamedProvider(IContentKeyProvider inner, string id) : IContentKeyProvider
    {
        public string ProviderId => id;
        public Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken ct = default) => inner.WrapNewKeyAsync(ct);
        public Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken ct = default) => inner.UnwrapKeyAsync(wrapInfo, ct);
    }

    /// <summary>A misbehaving provider that truncates every content key it hands back.</summary>
    private sealed class TruncatingProvider(IContentKeyProvider inner, int keyLength) : IContentKeyProvider
    {
        public string ProviderId => inner.ProviderId;

        public async Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken ct = default)
        {
            (byte[] contentKey, byte[] wrapInfo) = await inner.WrapNewKeyAsync(ct);
            return (contentKey[..keyLength], wrapInfo);
        }

        public async Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken ct = default) =>
            (await inner.UnwrapKeyAsync(wrapInfo, ct))[..keyLength];
    }
}
